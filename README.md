# TLS Certificate Checker

A small, dependency-free Python CLI that audits a host's TLS setup:
certificate expiry, hostname match, self-signed certificates, the
negotiated cipher and supported TLS versions. It grades the host A-F
and explains each finding in plain language, so students and small
teams can see exactly why a site triggers browser warnings and how to
fix it.

Standard library only (`ssl`, `socket`). No third-party packages, no
telemetry, nothing is stored. The certificate is parsed from its DER
bytes with a small built-in ASN.1 reader, so inspection works even for
self-signed or expired certificates (with `--insecure`).

## What it checks

| Check | What a good result looks like |
| --- | --- |
| Expiry | Certificate valid for more than 90 days |
| Hostname | A SAN (or the CN) covers the host you asked for, wildcards included |
| Trust | Issued by a public CA, not self-signed |
| Cipher | A modern AEAD cipher with 128-bit or stronger keys |
| TLS versions | TLS 1.2 and 1.3 only; 1.0 and 1.1 disabled |

Findings are graded by severity:

| Severity | Examples |
| --- | --- |
| High | Expired certificate, expiring within 7 days, hostname mismatch, weak cipher (RC4/DES/NULL), TLS 1.0 or 1.1 still accepted, no TLS 1.2/1.3 |
| Medium | Expiring within 30 days, self-signed certificate, sub-128-bit cipher |
| Low | Expiring within 90 days, no TLS 1.3, pre-v3 certificate |

Score starts at 100 and deducts 25 / 10 / 3 per high / medium / low
finding: 90+ is A, 75+ B, 60+ C, 40+ D, below that F.

## Install

No installation needed. Python 3.8+ only, standard library only:

```bash
git clone https://github.com/sajidhussainraza/tls-certificate-checker.git
cd tls-certificate-checker
```

## Usage

Check a host:

```bash
python3 tls_certificate_checker.py example.com
```

Check a non-standard port:

```bash
python3 tls_certificate_checker.py example.com --port 8443
```

Inspect a self-signed or expired certificate instead of failing the
handshake (findings are still reported):

```bash
python3 tls_certificate_checker.py localhost --port 8443 --insecure
```

Machine-readable output:

```bash
python3 tls_certificate_checker.py example.com --json
```

Use it as a CI gate (fail only on high-severity findings):

```bash
python3 tls_certificate_checker.py example.com --fail-on high
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at/above `--fail-on` |
| 1 | Findings at/above `--fail-on` were found |
| 2 | Usage error (no TLS handshake possible, DNS failure) |

Note: one audit opens five short connections (one to fetch the
certificate, one per TLS version probed), so a full run can take a few
seconds on a slow network.

## Example

```
$ python3 tls_certificate_checker.py github.com
TLS security report: github.com:443
Score: 97/100  Grade: A

  Subject:  github.com
  Issuer:   Sectigo Public Server Authentication CA DV E36
  Valid:    Oct 30 00:00:00 2026 GMT to Jan 27 23:59:59 2027 GMT
  SANs:     github.com, www.github.com
  Cipher:   TLS_AES_128_GCM_SHA256
  TLS:      TLS 1.2, TLS 1.3

Findings (1):
  [LOW] Certificate expires in 75 day(s). Consider enabling auto-renewal.
```

The full output of that run is saved in
`examples/sample-output-github.com.txt` (captured 13 November 2026).

## Teaching notes

This tool pairs well with a lesson on TLS and browser trust: run it
against a site before and after renewing its certificate or disabling
old TLS versions, and watch the grade move. Good discussion points:

- Why browsers distrust a certificate whose SANs do not list the host,
  even when the CN matches (modern browsers ignore the CN entirely).
- Why TLS 1.0 and 1.1 are disabled everywhere now, and what breaks when
  a server only offers them.
- Why a self-signed certificate is fine for a lab but not for anything
  internet-facing, and how `--insecure` lets you inspect one safely.
- Why short-lived certificates (90 days, as Let's Encrypt issues) make
  the expiry check a prompt to automate renewal rather than a calendar
  reminder.

## Tests

```bash
python3 tests/run_tests.py   # 27 tests, no internet access needed
```

The pure-logic tests use fabricated certificate data, the DER parser is
tested against real certificates generated with `openssl`, and the
end-to-end audit runs against a real TLS server on localhost. (pytest
is also supported if it is installed: `python3 -m pytest tests/ -q`.)

## License

MIT
