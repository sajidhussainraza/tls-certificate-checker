#!/usr/bin/env python3
"""TLS Certificate Checker.

A small, dependency-free Python CLI that audits a host's TLS setup:
certificate expiry, hostname match, self-signed certificates, supported
TLS versions and the negotiated cipher. It grades the host A-F and
explains each finding in plain language, so students and small teams can
see exactly why a site triggers browser warnings and how to fix it.

Standard library only (ssl, socket). No third-party packages, no
telemetry, nothing is stored.

Usage:
    python3 tls_certificate_checker.py example.com
    python3 tls_certificate_checker.py example.com --port 8443
    python3 tls_certificate_checker.py example.com --json
    python3 tls_certificate_checker.py example.com --fail-on high
    python3 tls_certificate_checker.py localhost --port 8443 --insecure
"""

import argparse
import json
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone

SEVERITY_WEIGHT = {"high": 25, "medium": 10, "low": 3}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5",
                       "anon", "ANON", "aNULL", "eNULL")

TLS_VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]


def grade(score):
    """Map a 0-100 score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def parse_cert_date(value):
    """Parse an OpenSSL-style cert date, e.g. 'Nov 12 00:00:00 2026 GMT'."""
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc)


def cert_names(cert):
    """Return (subject CN, issuer CN, list of SAN DNS names) for a cert dict."""
    def _cn(rdn_sequence):
        for rdn in rdn_sequence or []:
            for key, value in rdn:
                if key == "commonName":
                    return value
        return None

    subject_cn = _cn(cert.get("subject"))
    issuer_cn = _cn(cert.get("issuer"))
    sans = [value for kind, value in cert.get("subjectAltName", ())
            if kind == "DNS"]
    return subject_cn, issuer_cn, sans


def hostname_matches(hostname, sans, common_name):
    """True if hostname is covered by a SAN entry or the CN (exact or *.)."""
    hostname = hostname.lower()
    candidates = [name.lower() for name in sans]
    if not candidates and common_name:
        candidates = [common_name.lower()]
    for name in candidates:
        if name == hostname:
            return True
        if name.startswith("*.") and hostname.endswith(name[1:]) \
                and hostname.count(".") == name.count("."):
            return True
    return False


def check_certificate(cert, hostname, now=None):
    """Audit a parsed certificate dict. Returns a list of findings.

    Each finding is a dict: {"severity": ..., "message": ...}.
    Pure function: no network access, easy to unit test.
    """
    now = now or datetime.now(timezone.utc)
    findings = []
    subject_cn, issuer_cn, sans = cert_names(cert)

    # --- Expiry ---------------------------------------------------------
    try:
        not_after = parse_cert_date(cert["notAfter"])
        days_left = (not_after - now).days
    except (KeyError, ValueError):
        findings.append({
            "severity": "high",
            "message": "Certificate has no readable expiry date.",
        })
        return findings

    if days_left < 0:
        findings.append({
            "severity": "high",
            "message": f"Certificate EXPIRED {-days_left} day(s) ago "
                       f"(expired {cert['notAfter']}). Renew immediately.",
        })
    elif days_left < 7:
        findings.append({
            "severity": "high",
            "message": f"Certificate expires in {days_left} day(s) "
                       f"({cert['notAfter']}). Renew now.",
        })
    elif days_left < 30:
        findings.append({
            "severity": "medium",
            "message": f"Certificate expires in {days_left} day(s) "
                       f"({cert['notAfter']}). Schedule renewal.",
        })
    elif days_left < 90:
        findings.append({
            "severity": "low",
            "message": f"Certificate expires in {days_left} day(s). "
                       "Consider enabling auto-renewal.",
        })

    try:
        not_before = parse_cert_date(cert["notBefore"])
        if not_before > now:
            findings.append({
                "severity": "high",
                "message": f"Certificate is not yet valid "
                           f"(valid from {cert['notBefore']}). Check the "
                           "server clock or deploy the right certificate.",
            })
    except (KeyError, ValueError):
        pass

    # --- Hostname match -------------------------------------------------
    if not hostname_matches(hostname, sans, subject_cn):
        covered = ", ".join(sans) if sans else (subject_cn or "none")
        findings.append({
            "severity": "high",
            "message": f"Certificate does not cover '{hostname}'. "
                       f"It covers: {covered}. Browsers will show a "
                       "name-mismatch warning.",
        })

    # --- Self-signed ----------------------------------------------------
    if subject_cn and issuer_cn and subject_cn == issuer_cn:
        findings.append({
            "severity": "medium",
            "message": "Certificate appears self-signed (subject and "
                       "issuer are the same). Browsers will not trust it; "
                       "use a certificate from a public CA for anything "
                       "internet-facing.",
        })

    # --- Certificate version --------------------------------------------
    if cert.get("version", 3) < 3:
        findings.append({
            "severity": "low",
            "message": f"Certificate is X.509 version {cert['version']} "
                       "(v3 expected). Old versions lack extensions such "
                       "as Subject Alternative Names.",
        })

    return findings


def check_cipher(cipher):
    """Audit the negotiated cipher tuple (name, tls_version, bits)."""
    findings = []
    if not cipher:
        return findings
    name, _tls_version, bits = cipher
    if any(marker in name for marker in WEAK_CIPHER_MARKERS):
        findings.append({
            "severity": "high",
            "message": f"Weak cipher negotiated: {name}. Disable RC4, "
                       "DES/3DES, NULL and EXPORT ciphers on the server.",
        })
    elif bits < 128:
        findings.append({
            "severity": "medium",
            "message": f"Negotiated cipher uses only {bits}-bit keys "
                       f"({name}). Prefer 128-bit or stronger ciphers.",
        })
    return findings


def check_tls_versions(supported):
    """Audit which TLS versions the server accepts.

    `supported` maps e.g. {"TLS 1.0": True, "TLS 1.2": True}.
    """
    findings = []
    if supported.get("TLS 1.0"):
        findings.append({
            "severity": "high",
            "message": "Server still accepts TLS 1.0 (deprecated, "
                       "vulnerable to BEAST and other attacks). "
                       "Disable TLS 1.0 and 1.1.",
        })
    if supported.get("TLS 1.1"):
        findings.append({
            "severity": "high",
            "message": "Server still accepts TLS 1.1 (deprecated). "
                       "Disable TLS 1.0 and 1.1.",
        })
    if not supported.get("TLS 1.2") and not supported.get("TLS 1.3"):
        findings.append({
            "severity": "high",
            "message": "Server does not support TLS 1.2 or 1.3. "
                       "Modern browsers will refuse to connect.",
        })
    elif not supported.get("TLS 1.3"):
        findings.append({
            "severity": "low",
            "message": "Server does not support TLS 1.3. Enabling it "
                       "improves both security and handshake speed.",
        })
    return findings


def _read_tlv(data, offset):
    """Read one DER TLV element. Returns (tag, content_bytes, next_offset).

    Handles single-byte tags, short/long-form lengths, and multi-byte
    tag numbers. Raises ValueError on malformed input.
    """
    if offset >= len(data):
        raise ValueError("truncated DER data")
    first = data[offset]
    offset += 1
    if first & 0x1F == 0x1F:  # multi-byte tag number
        while True:
            if offset >= len(data):
                raise ValueError("truncated DER tag")
            byte = data[offset]
            offset += 1
            if not byte & 0x80:
                break
    if offset >= len(data):
        raise ValueError("truncated DER length")
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num_bytes = length_byte & 0x7F
        if num_bytes == 0 or num_bytes > 4 or offset + num_bytes > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[offset:offset + num_bytes], "big")
        offset += num_bytes
    else:
        length = length_byte
    if offset + length > len(data):
        raise ValueError("DER element overruns buffer")
    return first, data[offset:offset + length], offset + length


def _read_all(data):
    """Yield (tag, content) pairs for every TLV element in a buffer."""
    offset = 0
    while offset < len(data):
        tag, content, offset = _read_tlv(data, offset)
        yield tag, content


def _format_der_time(raw, tag):
    """Convert a DER UTCTime/GeneralizedTime value to the OpenSSL-style
    string getpeercert() returns, e.g. 'Nov 13 12:00:00 2026 GMT'."""
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    else:  # GeneralizedTime: YYYYMMDDHHMMSSZ
        year = int(text[0:4])
        rest = text[4:]
    month, day = int(rest[0:2]), int(rest[2:4])
    hour, minute, second = int(rest[4:6]), int(rest[6:8]), int(rest[8:10])
    dt = datetime(year, month, day, hour, minute, second,
                  tzinfo=timezone.utc)
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _name_cn(name_content):
    """Extract the commonName (OID 2.5.4.3) from a DER Name value."""
    for _set_tag, set_content in _read_all(name_content):
        for _seq_tag, seq_content in _read_all(set_content):
            parts = list(_read_all(seq_content))
            if len(parts) >= 2 and parts[0][0] == 0x06 \
                    and parts[0][1] == bytes([0x55, 0x04, 0x03]):
                return parts[1][1].decode("utf-8", "replace")
    return None


def _san_dns_names(extensions_content):
    """Extract DNS names from the subjectAltName extension (OID 2.5.29.17)."""
    names = []
    for _seq_tag, seq_content in _read_all(extensions_content):
        parts = list(_read_all(seq_content))
        if len(parts) < 2 or parts[0][0] != 0x06 \
                or parts[0][1] != bytes([0x55, 0x1D, 0x11]):
            continue
        value = parts[-1][1]  # OCTET STRING wrapping the GeneralNames SEQ
        for _seq_tag, general_names in _read_all(value):
            for tag, content in _read_all(general_names):
                if tag == 0x82:  # dNSName [2]
                    names.append(content.decode("utf-8", "replace"))
    return names


def parse_der_certificate(der):
    """Parse a DER-encoded X.509 certificate into a getpeercert()-style
    dict: subject/issuer (CN), notBefore/notAfter strings, subjectAltName
    DNS entries, serialNumber and version.

    Needed because getpeercert() returns an empty dict when certificate
    verification is disabled (the --insecure path), while the DER bytes
    are always available.
    """
    tag, cert_content, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER certificate")
    tag, tbs_content, _ = _read_tlv(cert_content, 0)
    if tag != 0x30:
        raise ValueError("no TBSCertificate")
    fields = list(_read_all(tbs_content))

    index = 0
    version = 3
    if fields and fields[0][0] == 0xA0:  # [0] explicit version
        version = int.from_bytes(
            list(_read_all(fields[0][1]))[0][1], "big") + 1
        index = 1

    serial = fields[index][1].hex() if len(fields) > index else None
    issuer = _name_cn(fields[index + 2][1]) if len(fields) > index + 2 else None
    validity = list(_read_all(fields[index + 3][1])) if len(fields) > index + 3 else []
    subject = _name_cn(fields[index + 4][1]) if len(fields) > index + 4 else None

    not_before = not_after = None
    if len(validity) >= 2:
        not_before = _format_der_time(validity[0][1], validity[0][0])
        not_after = _format_der_time(validity[1][1], validity[1][0])

    sans = []
    for tag, content in fields:
        if tag == 0xA3:  # [3] extensions
            for _seq_tag, seq_content in _read_all(content):
                sans = _san_dns_names(seq_content)

    return {
        "subject": ((("commonName", subject),),) if subject else (),
        "issuer": ((("commonName", issuer),),) if issuer else (),
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": tuple(("DNS", name) for name in sans),
        "serialNumber": serial,
        "version": version,
    }


def _connect(host, port, timeout, minimum=None, maximum=None,
             insecure=False):
    """Open one TLS connection and return (cert_dict, cipher, tls_version)."""
    if insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context()
    if minimum is not None:
        with warnings.catch_warnings():
            # Pinning TLS 1.0/1.1 is the point of the probe; silence the
            # deprecation warning those enum values raise.
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = minimum
    if maximum is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.maximum_version = maximum
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            try:
                cert = parse_der_certificate(
                    tls.getpeercert(binary_form=True))
            except Exception:
                cert = tls.getpeercert()
            return cert, tls.cipher(), tls.version()


def probe_tls_versions(host, port, timeout, insecure=False):
    """Try each TLS version on its own and record which ones the server
    accepts. A version counts as supported only if a full handshake
    succeeds with that version pinned."""
    supported = {}
    for label, version in TLS_VERSIONS:
        try:
            _connect(host, port, timeout, minimum=version, maximum=version,
                     insecure=insecure)
            supported[label] = True
        except Exception:
            supported[label] = False
    return supported


def fetch(host, port, timeout, insecure=False):
    """Fetch the live certificate, negotiated cipher and TLS version
    support for a host. Raises socket/SSL errors on connection failure."""
    cert, cipher, _tls_version = _connect(host, port, timeout,
                                          insecure=insecure)
    supported = probe_tls_versions(host, port, timeout, insecure=insecure)
    return cert, cipher, supported


def audit(host, port=443, timeout=10, insecure=False):
    """Run the full audit. Returns a report dict."""
    cert, cipher, supported = fetch(host, port, timeout, insecure=insecure)
    findings = []
    findings += check_certificate(cert, host)
    findings += check_cipher(cipher)
    findings += check_tls_versions(supported)

    score = 100
    for finding in findings:
        score -= SEVERITY_WEIGHT[finding["severity"]]
    score = max(0, score)

    subject_cn, issuer_cn, sans = cert_names(cert)
    return {
        "host": host,
        "port": port,
        "score": score,
        "grade": grade(score),
        "certificate": {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": sans,
            "serial": cert.get("serialNumber"),
        },
        "cipher": cipher[0] if cipher else None,
        "tls_versions_supported": [v for v, ok in supported.items() if ok],
        "findings": findings,
    }


def render_text(report):
    """Human-readable report."""
    lines = [
        f"TLS security report: {report['host']}:{report['port']}",
        f"Score: {report['score']}/100  Grade: {report['grade']}",
        "",
        f"  Subject:  {report['certificate']['subject']}",
        f"  Issuer:   {report['certificate']['issuer']}",
        f"  Valid:    {report['certificate']['not_before']} "
        f"to {report['certificate']['not_after']}",
        f"  SANs:     {', '.join(report['certificate']['san']) or '(none)'}",
        f"  Cipher:   {report['cipher'] or '(unknown)'}",
        f"  TLS:      {', '.join(report['tls_versions_supported']) or '(none detected)'}",
        "",
    ]
    if report["findings"]:
        lines.append(f"Findings ({len(report['findings'])}):")
        for finding in report["findings"]:
            lines.append(f"  [{finding['severity'].upper()}] "
                         f"{finding['message']}")
    else:
        lines.append("No findings: certificate, cipher and TLS versions "
                     "all look good.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit a host's TLS certificate, cipher and TLS versions.")
    parser.add_argument("host", help="hostname to check, e.g. example.com")
    parser.add_argument("--port", type=int, default=443,
                        help="TLS port (default: 443)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="connection timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip certificate trust verification so "
                             "self-signed or expired certificates can "
                             "still be inspected (findings are still "
                             "reported)")
    parser.add_argument("--json", action="store_true",
                        help="output machine-readable JSON")
    parser.add_argument("--fail-on", choices=["high", "medium", "low"],
                        default="high",
                        help="fail (exit 1) if findings at or above this "
                             "severity exist (default: high)")
    args = parser.parse_args(argv)

    try:
        report = audit(args.host, args.port, args.timeout,
                       insecure=args.insecure)
    except (socket.gaierror, socket.timeout, ConnectionError,
            ssl.SSLError, OSError) as exc:
        print(f"Error: could not complete a TLS handshake with "
              f"{args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))

    threshold = SEVERITY_RANK[args.fail_on]
    if any(SEVERITY_RANK[f["severity"]] >= threshold
           for f in report["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
