#!/usr/bin/env python3
"""
Audit sandbox pod network-policy reachability from inside the sandbox pod.

This script intentionally does not print environment variables. It records only
basic runtime metadata, DNS behavior, and TCP connect results.

Default expectations are based on:
  manifests/networkpolicies/manifests/platform/sandbox.yaml
  manifests/networkpolicies/manifests/platform/sandboxcontroller.yaml

The policy contains wildcard FQDNs, so this cannot enumerate every possible
host. Instead, it probes all explicit policy hosts plus representative wildcard
and negative-control hosts.
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import ipaddress
import json
import os
import platform
import random
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_ARTIFACT_DIR = Path("/workspace/.artifacts")
DEFAULT_MD_OUT = DEFAULT_ARTIFACT_DIR / "sandbox-pod-network-policy-audit.md"
DEFAULT_JSON_OUT = DEFAULT_ARTIFACT_DIR / "sandbox-pod-network-policy-audit.json"
SERVICEACCOUNT_NAMESPACE = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
RESOLV_CONF = Path("/etc/resolv.conf")

EXPECT_ALLOW = "allow"
EXPECT_DENY = "deny"
DNS_ALLOW = "allow"
DNS_DENY = "deny"
DNS_ANY = "any"


@dataclasses.dataclass(frozen=True)
class TestCase:
    name: str
    host: str
    port: int
    expect: str
    category: str
    dns_expect: str = DNS_ANY
    public_dns: bool = True
    notes: str = ""


def now_ms() -> int:
    return int(time.time() * 1000)


def elapsed_ms(start_ms: int) -> int:
    return max(0, now_ms() - start_ms)


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def detect_namespace() -> str:
    return read_text(SERVICEACCOUNT_NAMESPACE) or "arize-dev"


def parse_resolv_conf() -> Dict[str, List[str]]:
    nameservers: List[str] = []
    searches: List[str] = []
    options: List[str] = []
    content = read_text(RESOLV_CONF) or ""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "nameserver":
            nameservers.extend(parts[1:])
        elif parts[0] == "search":
            searches.extend(parts[1:])
        elif parts[0] == "options":
            options.extend(parts[1:])
    return {
        "nameservers": nameservers,
        "searches": searches,
        "options": options,
    }


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_local_probe_ip() -> Optional[str]:
    """Return the local source IP selected for internet egress without sending data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.0)
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def runtime_metadata(platform_namespace: str) -> Dict[str, object]:
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user": getpass.getuser(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "cwd": os.getcwd(),
        "hostname": socket.gethostname(),
        "local_probe_ip": get_local_probe_ip(),
        "platform_namespace": platform_namespace,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "resolv_conf": parse_resolv_conf(),
    }


def system_resolve(host: str, port: int, timeout: float) -> Dict[str, object]:
    if is_ip_literal(host):
        return {
            "ok": True,
            "addresses": [host],
            "error": None,
            "duration_ms": 0,
        }

    start = now_ms()
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = sorted({info[4][0] for info in infos})
        return {
            "ok": bool(addresses),
            "addresses": addresses,
            "error": None if addresses else "no addresses returned",
            "duration_ms": elapsed_ms(start),
        }
    except OSError as exc:
        return {
            "ok": False,
            "addresses": [],
            "error": f"{exc.__class__.__name__}: {exc}",
            "duration_ms": elapsed_ms(start),
        }
    finally:
        socket.setdefaulttimeout(old_timeout)


def encode_dns_name(name: str) -> bytes:
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        data = label.encode("ascii")
        if not data or len(data) > 63:
            raise ValueError(f"invalid DNS label in {name!r}")
        encoded.append(len(data))
        encoded.extend(data)
    encoded.append(0)
    return bytes(encoded)


def skip_dns_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def read_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original_offset = offset
    seen_offsets = set()

    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        if offset in seen_offsets:
            raise ValueError("DNS compression loop")
        seen_offsets.add(offset)

        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                original_offset = offset + 1
            break
        offset += 1
        label = packet[offset : offset + length]
        labels.append(label.decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), original_offset


def parse_dns_response(packet: bytes, expected_id: int) -> Dict[str, object]:
    if len(packet) < 12:
        raise ValueError("truncated DNS header")
    dns_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    if dns_id != expected_id:
        raise ValueError("mismatched DNS transaction id")
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)

    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(packet, offset)
        offset += 4

    addresses: List[str] = []
    cnames: List[str] = []
    for _ in range(ancount):
        _name, offset = read_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS answer")
        rr_type, rr_class, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        offset += rdlength
        rdata = packet[rdata_offset:offset]

        if rr_class != 1:
            continue
        if rr_type == 1 and rdlength == 4:
            addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rr_type == 5:
            cname, _ = read_dns_name(packet, rdata_offset)
            cnames.append(cname)
        # AAAA is intentionally not used for TCP probes by default. Most of the
        # relevant sandbox egress paths are IPv4, and IPv6 support varies by pod.

    return {
        "rcode": rcode,
        "truncated": truncated,
        "addresses": sorted(set(addresses)),
        "cnames": sorted(set(cnames)),
    }


def public_dns_query(host: str, resolver: str, timeout: float) -> Dict[str, object]:
    start = now_ms()
    dns_id = random.randint(0, 65535)
    query = (
        struct.pack("!HHHHHH", dns_id, 0x0100, 1, 0, 0, 0)
        + encode_dns_name(host)
        + struct.pack("!HH", 1, 1)
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (resolver, 53))
        packet, _ = sock.recvfrom(4096)
        parsed = parse_dns_response(packet, dns_id)
        addresses = parsed["addresses"]
        return {
            "ok": bool(addresses),
            "addresses": addresses,
            "cnames": parsed["cnames"],
            "rcode": parsed["rcode"],
            "truncated": parsed["truncated"],
            "error": None if addresses else f"rcode={parsed['rcode']} no A records",
            "duration_ms": elapsed_ms(start),
        }
    except OSError as exc:
        return {
            "ok": False,
            "addresses": [],
            "cnames": [],
            "rcode": None,
            "truncated": False,
            "error": f"{exc.__class__.__name__}: {exc}",
            "duration_ms": elapsed_ms(start),
        }
    except ValueError as exc:
        return {
            "ok": False,
            "addresses": [],
            "cnames": [],
            "rcode": None,
            "truncated": False,
            "error": f"DNS parse error: {exc}",
            "duration_ms": elapsed_ms(start),
        }
    finally:
        sock.close()


def public_resolve(host: str, resolvers: Sequence[str], timeout: float) -> Dict[str, object]:
    if is_ip_literal(host):
        return {
            "ok": True,
            "addresses": [host],
            "resolvers": {},
            "error": None,
        }

    by_resolver: Dict[str, object] = {}
    all_addresses: List[str] = []
    errors: List[str] = []
    for resolver in resolvers:
        result = public_dns_query(host, resolver, timeout)
        by_resolver[resolver] = result
        all_addresses.extend(result.get("addresses", []))
        if result.get("error"):
            errors.append(f"{resolver}: {result['error']}")

    addresses = sorted(set(all_addresses))
    return {
        "ok": bool(addresses),
        "addresses": addresses,
        "resolvers": by_resolver,
        "error": None if addresses else "; ".join(errors),
    }


def tcp_connect(target: str, port: int, timeout: float) -> Dict[str, object]:
    start = now_ms()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((target, port))
        return {
            "ok": True,
            "target": target,
            "port": port,
            "error": None,
            "duration_ms": elapsed_ms(start),
        }
    except OSError as exc:
        return {
            "ok": False,
            "target": target,
            "port": port,
            "error": f"{exc.__class__.__name__}: {exc}",
            "duration_ms": elapsed_ms(start),
        }
    finally:
        sock.close()


def build_default_cases(platform_namespace: str) -> List[TestCase]:
    sandboxcontroller = f"sandboxcontroller.{platform_namespace}.svc.cluster.local"
    postgres = f"postgres.{platform_namespace}.svc.cluster.local"
    postgres17 = f"postgres17.{platform_namespace}.svc.cluster.local"
    app_server = f"app-server.{platform_namespace}.svc.cluster.local"
    kubernetes_api = "kubernetes.default.svc.cluster.local"

    cases = [
        TestCase(
            "allowed_internal_sandboxcontroller_emit_turn",
            sandboxcontroller,
            8080,
            EXPECT_ALLOW,
            "internal-service",
            DNS_ALLOW,
            public_dns=False,
            notes="Only in-cluster sandbox egress path in sandbox.yaml.",
        ),
        TestCase(
            "denied_internal_sandboxcontroller_grpc",
            sandboxcontroller,
            50051,
            EXPECT_DENY,
            "internal-service",
            DNS_ALLOW,
            public_dns=False,
            notes="SandboxController gRPC is not allowed from sandbox pods.",
        ),
        TestCase(
            "denied_kubernetes_api",
            kubernetes_api,
            443,
            EXPECT_DENY,
            "internal-service-discovery",
            DNS_DENY,
            public_dns=False,
        ),
        TestCase(
            "denied_postgres",
            postgres,
            5432,
            EXPECT_DENY,
            "internal-service-discovery",
            DNS_DENY,
            public_dns=False,
        ),
        TestCase(
            "denied_postgres17",
            postgres17,
            5432,
            EXPECT_DENY,
            "internal-service-discovery",
            DNS_DENY,
            public_dns=False,
        ),
        TestCase(
            "denied_app_server_service",
            app_server,
            443,
            EXPECT_DENY,
            "internal-service-discovery",
            DNS_DENY,
            public_dns=False,
        ),
        TestCase(
            "denied_metadata_dns",
            "metadata.google.internal",
            80,
            EXPECT_DENY,
            "metadata",
            DNS_DENY,
            public_dns=False,
        ),
        TestCase(
            "denied_metadata_ip",
            "169.254.169.254",
            80,
            EXPECT_DENY,
            "metadata",
            DNS_ANY,
            public_dns=False,
        ),
        TestCase("denied_direct_dev_flight_private_ip", "10.0.32.10", 443, EXPECT_DENY, "private-ip", DNS_ANY, False),
        TestCase("denied_direct_prod_flight_private_ip", "10.0.48.10", 443, EXPECT_DENY, "private-ip", DNS_ANY, False),
        TestCase("denied_direct_eu_internal_app_ip", "192.168.48.4", 443, EXPECT_DENY, "private-ip", DNS_ANY, False),
        TestCase("denied_direct_eu_internal_api_ip", "192.168.48.6", 443, EXPECT_DENY, "private-ip", DNS_ANY, False),
        TestCase("denied_direct_eu_internal_otlp_ip", "192.168.48.7", 443, EXPECT_DENY, "private-ip", DNS_ANY, False),
    ]

    allowed_fqdns = [
        ("allowed_arize_root", "arize.com", 443, "arize-fqdn"),
        ("allowed_arize_app", "app.arize.com", 443, "arize-fqdn"),
        ("allowed_arize_api", "api.arize.com", 443, "arize-fqdn"),
        ("allowed_arize_otlp", "otlp.arize.com", 443, "arize-fqdn"),
        ("allowed_arize_flight", "flight.arize.com", 443, "arize-fqdn"),
        ("allowed_dev_app", "app.dev.arize.com", 443, "arize-fqdn"),
        ("allowed_dev_otlp", "devotlp.arize.com", 443, "arize-fqdn"),
        ("allowed_devx", "devx.arize.com", 443, "arize-fqdn"),
        ("allowed_devr", "devr.arize.com", 443, "arize-fqdn"),
        ("allowed_eu_app", "app.eu-west-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_eu_api", "api.eu-west-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_eu_otlp", "otlp.eu-west-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_eu_flight", "flight.eu-west-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_ca_app", "app.ca-central-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_ca_api", "api.ca-central-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_ca_otlp", "otlp.ca-central-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_ca_flight", "flight.ca-central-1a.arize.com", 443, "arize-fqdn"),
        ("allowed_gcs", "storage.googleapis.com", 443, "storage"),
        ("allowed_gcs_wildcard", "www.storage.googleapis.com", 443, "storage"),
        ("allowed_claude", "claude.ai", 443, "llm-provider"),
        ("allowed_anthropic_api", "api.anthropic.com", 443, "llm-provider"),
        ("allowed_github", "github.com", 443, "source-control"),
        ("allowed_github_api", "api.github.com", 443, "source-control"),
        ("allowed_github_raw", "raw.githubusercontent.com", 443, "source-control"),
        ("allowed_github_codeload", "codeload.github.com", 443, "source-control"),
        ("allowed_datadog", "api.datadoghq.com", 443, "observability"),
        ("allowed_pypi", "pypi.org", 443, "package-manager"),
        ("allowed_pythonhosted", "files.pythonhosted.org", 443, "package-manager"),
        ("allowed_bootstrap_pypa", "bootstrap.pypa.io", 443, "package-manager"),
        ("allowed_npm", "registry.npmjs.org", 443, "package-manager"),
        ("allowed_yarn", "registry.yarnpkg.com", 443, "package-manager"),
        ("allowed_nodejs", "nodejs.org", 443, "package-manager"),
        ("allowed_google_fonts_css", "fonts.googleapis.com", 443, "package-manager"),
        ("allowed_google_fonts_static", "fonts.gstatic.com", 443, "package-manager"),
        ("allowed_crates", "crates.io", 443, "package-manager"),
        ("allowed_cargo_index", "index.crates.io", 443, "package-manager"),
        ("allowed_cargo_static", "static.crates.io", 443, "package-manager"),
        ("allowed_rust_static", "static.rust-lang.org", 443, "package-manager"),
        ("allowed_rustup", "sh.rustup.rs", 443, "package-manager"),
        ("allowed_go_proxy", "proxy.golang.org", 443, "package-manager"),
        ("allowed_go_sum", "sum.golang.org", 443, "package-manager"),
        ("allowed_go_dev", "go.dev", 443, "package-manager"),
        ("allowed_pkg_go_dev", "pkg.go.dev", 443, "package-manager"),
        ("allowed_rubygems", "rubygems.org", 443, "package-manager"),
        ("allowed_maven", "repo.maven.apache.org", 443, "package-manager"),
        ("allowed_maven1", "repo1.maven.org", 443, "package-manager"),
        ("allowed_gradle_services", "services.gradle.org", 443, "package-manager"),
        ("allowed_gradle_plugins", "plugins.gradle.org", 443, "package-manager"),
        ("allowed_nuget_api", "api.nuget.org", 443, "package-manager"),
        ("allowed_composer", "getcomposer.org", 443, "package-manager"),
        ("allowed_packagist", "packagist.org", 443, "package-manager"),
        ("allowed_packagist_repo", "repo.packagist.org", 443, "package-manager"),
        ("allowed_debian_http", "deb.debian.org", 80, "package-manager"),
        ("allowed_debian_https", "deb.debian.org", 443, "package-manager"),
        ("allowed_ubuntu_archive_http", "archive.ubuntu.com", 80, "package-manager"),
        ("allowed_ubuntu_security_http", "security.ubuntu.com", 80, "package-manager"),
        ("allowed_ubuntu_ports_http", "ports.ubuntu.com", 80, "package-manager"),
        ("allowed_openai_api", "api.openai.com", 443, "llm-provider"),
        ("allowed_huggingface", "huggingface.co", 443, "llm-provider"),
        ("allowed_huggingface_cdn", "cdn-lfs.huggingface.co", 443, "llm-provider"),
        ("allowed_cohere_api", "api.cohere.ai", 443, "llm-provider"),
        ("allowed_mistral_api", "api.mistral.ai", 443, "llm-provider"),
        ("allowed_openai_blob", "openaipublic.blob.core.windows.net", 443, "llm-provider"),
        ("allowed_bedrock_us_east_1", "bedrock-runtime.us-east-1.amazonaws.com", 443, "llm-provider"),
        ("allowed_gemini", "generativelanguage.googleapis.com", 443, "llm-provider"),
        ("allowed_vertex", "aiplatform.googleapis.com", 443, "llm-provider"),
        ("allowed_vertex_regional", "us-central1-aiplatform.googleapis.com", 443, "llm-provider"),
    ]
    for name, host, port, category in allowed_fqdns:
        dns_expect = DNS_ALLOW if host in {"app.dev.arize.com", "devotlp.arize.com"} else DNS_ANY
        cases.append(TestCase(name, host, port, EXPECT_ALLOW, category, dns_expect, True))

    denied_controls = [
        TestCase(
            "denied_example_public_fqdn",
            "example.com",
            443,
            EXPECT_DENY,
            "negative-control",
            DNS_ANY,
            True,
            "Public DNS is allowed, but this FQDN is not in toFQDNs.",
        ),
        TestCase(
            "denied_google_root",
            "google.com",
            443,
            EXPECT_DENY,
            "negative-control",
            DNS_ANY,
            True,
            "googleapis.com is allowed in places; google.com is not.",
        ),
        TestCase(
            "denied_sts_googleapis",
            "sts.googleapis.com",
            443,
            EXPECT_DENY,
            "negative-control",
            DNS_ANY,
            True,
            "Commented as only-add-if-needed in sandbox.yaml.",
        ),
        TestCase(
            "denied_iamcredentials_googleapis",
            "iamcredentials.googleapis.com",
            443,
            EXPECT_DENY,
            "negative-control",
            DNS_ANY,
            True,
            "Commented as only-add-if-needed in sandbox.yaml.",
        ),
        TestCase(
            "denied_oauth2_googleapis",
            "oauth2.googleapis.com",
            443,
            EXPECT_DENY,
            "negative-control",
            DNS_ANY,
            True,
            "Commented as only-add-if-needed in sandbox.yaml.",
        ),
        TestCase(
            "denied_eu_internal_app_fqdn",
            "app.int.eu-west-1a.arize.com",
            443,
            EXPECT_DENY,
            "internal-fqdn",
            DNS_ANY,
            True,
            "*.eu-west-1a.arize.com should not match nested app.int.eu-west-1a.arize.com.",
        ),
        TestCase(
            "denied_eu_internal_api_fqdn",
            "api.int.eu-west-1a.arize.com",
            443,
            EXPECT_DENY,
            "internal-fqdn",
            DNS_ANY,
            True,
            "*.eu-west-1a.arize.com should not match nested api.int.eu-west-1a.arize.com.",
        ),
        TestCase(
            "denied_eu_internal_otlp_fqdn",
            "otlp.int.eu-west-1a.arize.com",
            443,
            EXPECT_DENY,
            "internal-fqdn",
            DNS_ANY,
            True,
            "*.eu-west-1a.arize.com should not match nested otlp.int.eu-west-1a.arize.com.",
        ),
    ]
    cases.extend(denied_controls)
    return cases


def parse_extra_case(value: str, expect: str) -> TestCase:
    parts = value.rsplit(":", 2)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("extra case must be HOST:PORT")
    host, port_raw = parts
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port in {value!r}") from exc
    return TestCase(
        name=f"extra_{expect}_{host.replace('.', '_').replace(':', '_')}_{port}",
        host=host,
        port=port,
        expect=expect,
        category="extra",
        dns_expect=DNS_ANY,
        public_dns=not is_ip_literal(host),
    )


def first_n(items: Iterable[str], limit: int) -> List[str]:
    out: List[str] = []
    for item in items:
        if item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def probe_case(case: TestCase, resolvers: Sequence[str], timeout: float, max_ips: int) -> Dict[str, object]:
    system_dns = system_resolve(case.host, case.port, timeout)
    if case.public_dns:
        public_dns = public_resolve(case.host, resolvers, timeout)
    else:
        public_dns = {
            "ok": False,
            "addresses": [],
            "resolvers": {},
            "error": "public DNS probe disabled for this case",
        }

    candidate_ips: List[str] = []
    candidate_ips.extend(system_dns.get("addresses", []))
    candidate_ips.extend(public_dns.get("addresses", []))
    candidate_ips = [ip for ip in first_n(candidate_ips, max_ips) if ":" not in ip]

    ip_tcp_results = [tcp_connect(ip, case.port, timeout) for ip in candidate_ips]
    tcp_ok = any(result.get("ok") for result in ip_tcp_results)

    warnings: List[str] = []
    failures: List[str] = []

    if case.dns_expect == DNS_ALLOW and not (system_dns.get("ok") or public_dns.get("ok")):
        failures.append("expected DNS resolution but no resolver returned an address")
    if case.dns_expect == DNS_DENY and (system_dns.get("ok") or public_dns.get("ok")):
        warnings.append("expected DNS denial, but the name resolved")

    if case.expect == EXPECT_ALLOW:
        if not tcp_ok:
            failures.append("expected TCP reachability but all connect attempts failed")
    elif case.expect == EXPECT_DENY:
        if tcp_ok:
            failures.append("expected TCP denial but a connect attempt succeeded")
    else:
        failures.append(f"unknown expectation {case.expect!r}")

    if failures:
        status = "FAIL"
    elif warnings:
        status = "WARN"
    else:
        status = "PASS"

    return {
        "name": case.name,
        "host": case.host,
        "port": case.port,
        "expect": case.expect,
        "dns_expect": case.dns_expect,
        "category": case.category,
        "notes": case.notes,
        "status": status,
        "warnings": warnings,
        "failures": failures,
        "system_dns": system_dns,
        "public_dns": public_dns,
        "tcp_ip": ip_tcp_results,
    }


def status_counts(results: Sequence[Dict[str, object]]) -> Dict[str, int]:
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for result in results:
        counts[str(result["status"])] = counts.get(str(result["status"]), 0) + 1
    return counts


def compact_addresses(result: Dict[str, object]) -> str:
    addresses: List[str] = []
    system_dns = result.get("system_dns", {})
    public_dns = result.get("public_dns", {})
    if isinstance(system_dns, dict):
        addresses.extend(system_dns.get("addresses", []))
    if isinstance(public_dns, dict):
        addresses.extend(public_dns.get("addresses", []))
    unique = first_n(addresses, 5)
    if not unique:
        return "-"
    suffix = "" if len(set(addresses)) <= len(unique) else "..."
    return ", ".join(unique) + suffix


def tcp_summary(result: Dict[str, object]) -> str:
    ip_results = result.get("tcp_ip", [])
    ip_ok = any(item.get("ok") for item in ip_results if isinstance(item, dict))
    if ip_ok:
        return "ip"
    return "blocked/failed"


def format_markdown(metadata: Dict[str, object], results: Sequence[Dict[str, object]]) -> str:
    counts = status_counts(results)
    lines = [
        "# Sandbox Pod Network Policy Audit",
        "",
        "## Runtime Metadata",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    for key in [
        "timestamp_utc",
        "mode",
        "user",
        "uid",
        "gid",
        "cwd",
        "hostname",
        "local_probe_ip",
        "platform_namespace",
        "python",
        "platform",
    ]:
        lines.append(f"| `{key}` | `{metadata.get(key)}` |")

    resolv = metadata.get("resolv_conf", {})
    if isinstance(resolv, dict):
        lines.append(f"| `resolv_conf.nameservers` | `{', '.join(resolv.get('nameservers', []))}` |")
        lines.append(f"| `resolv_conf.searches` | `{', '.join(resolv.get('searches', []))}` |")
        lines.append(f"| `resolv_conf.options` | `{', '.join(resolv.get('options', []))}` |")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- PASS: `{counts.get('PASS', 0)}`",
            f"- WARN: `{counts.get('WARN', 0)}`",
            f"- FAIL: `{counts.get('FAIL', 0)}`",
            "",
            "## Results",
            "",
            "| Status | Expected | DNS Expected | Category | Host | Port | TCP | Addresses | Notes |",
            "| --- | --- | --- | --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for result in results:
        notes = "; ".join(result.get("failures", []) + result.get("warnings", []))
        if not notes:
            notes = str(result.get("notes") or "")
        lines.append(
            "| {status} | {expect} | {dns_expect} | {category} | `{host}` | {port} | {tcp} | `{addresses}` | {notes} |".format(
                status=result["status"],
                expect=result["expect"],
                dns_expect=result["dns_expect"],
                category=result["category"],
                host=result["host"],
                port=result["port"],
                tcp=tcp_summary(result),
                addresses=compact_addresses(result),
                notes=notes.replace("|", "\\|"),
            )
        )

    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "",
            "- `allow` means the source policy appears to permit this destination and port.",
            "- `deny` means the source policy appears not to permit this destination and port.",
            "- `WARN` on DNS usually means service discovery is broader than expected even if TCP stayed blocked.",
            "- This script does not enumerate every wildcard hostname; it probes explicit hosts plus representative candidates.",
            "- No environment variables are collected or printed.",
            "",
        ]
    )
    return "\n".join(lines)


def print_console_summary(results: Sequence[Dict[str, object]]) -> None:
    counts = status_counts(results)
    print(f"Sandbox network policy audit: PASS={counts.get('PASS', 0)} WARN={counts.get('WARN', 0)} FAIL={counts.get('FAIL', 0)}")
    for result in results:
        if result["status"] == "PASS":
            continue
        hostport = f"{result['host']}:{result['port']}"
        reasons = result.get("failures", []) + result.get("warnings", [])
        print(f"[{result['status']}] {result['name']} {hostport} -> {'; '.join(reasons)}")


def write_outputs(
    metadata: Dict[str, object],
    results: Sequence[Dict[str, object]],
    json_out: Optional[Path],
    md_out: Optional[Path],
) -> None:
    payload = {
        "metadata": metadata,
        "summary": status_counts(results),
        "results": results,
    }
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Wrote JSON results: {json_out}")
    if md_out:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(format_markdown(metadata, results), encoding="utf-8")
        print(f"Wrote Markdown results: {md_out}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform-namespace",
        default=detect_namespace(),
        help="Platform namespace used in sandboxcontroller.<namespace>.svc.cluster.local.",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Per DNS/TCP probe timeout in seconds.")
    parser.add_argument("--max-ips-per-host", type=int, default=3, help="Maximum resolved IPs to TCP probe per host.")
    parser.add_argument(
        "--public-resolver",
        action="append",
        default=["1.1.1.1", "8.8.8.8"],
        help="Public DNS resolver to probe directly. Can be repeated.",
    )
    parser.add_argument(
        "--full-auto",
        action="store_true",
        help=(
            "Run the complete built-in audit matrix and write artifacts. "
            "This overrides --case-filter and --no-artifacts."
        ),
    )
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT, help="JSON artifact path.")
    parser.add_argument("--markdown-out", type=Path, default=DEFAULT_MD_OUT, help="Markdown artifact path.")
    parser.add_argument("--no-artifacts", action="store_true", help="Do not write JSON/Markdown artifacts.")
    parser.add_argument("--list-cases", action="store_true", help="Print test cases and exit.")
    parser.add_argument(
        "--case-filter",
        action="append",
        default=[],
        help="Only run cases whose name, host, or category contains this substring. Can be repeated.",
    )
    parser.add_argument("--extra-allow", action="append", default=[], metavar="HOST:PORT", help="Add an expected-allow probe.")
    parser.add_argument("--extra-deny", action="append", default=[], metavar="HOST:PORT", help="Add an expected-deny probe.")
    args = parser.parse_args(argv)

    cases = build_default_cases(args.platform_namespace)
    cases.extend(parse_extra_case(value, EXPECT_ALLOW) for value in args.extra_allow)
    cases.extend(parse_extra_case(value, EXPECT_DENY) for value in args.extra_deny)
    if args.full_auto:
        args.case_filter = []
        args.no_artifacts = False

    if args.case_filter:
        filters = [item.lower() for item in args.case_filter]
        cases = [
            case
            for case in cases
            if any(
                needle in case.name.lower()
                or needle in case.host.lower()
                or needle in case.category.lower()
                for needle in filters
            )
        ]

    if not cases:
        print("No audit cases selected.", file=sys.stderr)
        return 2

    if args.list_cases:
        for case in cases:
            print(f"{case.expect:5} dns={case.dns_expect:5} {case.host}:{case.port} {case.category} {case.name}")
        return 0

    metadata = runtime_metadata(args.platform_namespace)
    metadata["mode"] = "full-auto" if args.full_auto else "manual"
    print("Sandbox pod network policy audit")
    print(f"mode={metadata['mode']} cases={len(cases)}")
    print(f"whoami={metadata['user']} uid={metadata['uid']} gid={metadata['gid']}")
    print(f"cwd={metadata['cwd']}")
    print(f"hostname={metadata['hostname']} local_probe_ip={metadata['local_probe_ip']}")
    print(f"platform_namespace={metadata['platform_namespace']}")
    resolv = metadata.get("resolv_conf", {})
    if isinstance(resolv, dict):
        print(f"resolv_conf.nameservers={','.join(resolv.get('nameservers', []))}")

    results: List[Dict[str, object]] = []
    for index, case in enumerate(cases, start=1):
        print(f"[{index:03d}/{len(cases):03d}] {case.expect} {case.host}:{case.port} ({case.category})")
        results.append(probe_case(case, args.public_resolver, args.timeout, args.max_ips_per_host))

    print_console_summary(results)

    if args.no_artifacts:
        return 1 if any(result["status"] == "FAIL" for result in results) else 0

    write_outputs(
        metadata,
        results,
        None if args.no_artifacts else args.json_out,
        None if args.no_artifacts else args.markdown_out,
    )
    return 1 if any(result["status"] == "FAIL" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
