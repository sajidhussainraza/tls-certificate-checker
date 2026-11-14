"""Tests for tls_certificate_checker.py.

Pure-logic tests run fully offline with fabricated certificate dicts.
The live test spins up a real TLS server on localhost using a
self-signed certificate generated with openssl, so the end-to-end
audit path is exercised without any internet access.
"""

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tls_certificate_checker as tcc  # noqa: E402

NOW = tcc.parse_cert_date("Nov 13 12:00:00 2026 GMT")


def make_cert(**overrides):
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Jan 01 00:00:00 2028 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "serialNumber": "01",
        "version": 3,
    }
    cert.update(overrides)
    return cert


class TestExpiry(unittest.TestCase):
    def test_valid_long_lived_cert_has_no_findings(self):
        self.assertEqual(tcc.check_certificate(make_cert(), "example.com", NOW), [])

    def test_expired_cert_is_high(self):
        cert = make_cert(notAfter="Nov 01 00:00:00 2026 GMT")
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("EXPIRED", findings[0]["message"])

    def test_expiring_within_a_week_is_high(self):
        cert = make_cert(notAfter="Nov 18 12:00:00 2026 GMT")
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertEqual(findings[0]["severity"], "high")

    def test_expiring_within_a_month_is_medium(self):
        cert = make_cert(notAfter="Dec 01 00:00:00 2026 GMT")
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_expiring_within_90_days_is_low(self):
        cert = make_cert(notAfter="Jan 01 00:00:00 2027 GMT")
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertEqual(findings[0]["severity"], "low")
        self.assertIn("48 day", findings[0]["message"])

    def test_not_yet_valid_cert_is_high(self):
        cert = make_cert(notBefore="Dec 01 00:00:00 2026 GMT")
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertTrue(any(f["severity"] == "high"
                            and "not yet valid" in f["message"]
                            for f in findings))

    def test_missing_expiry_is_high(self):
        cert = make_cert()
        del cert["notAfter"]
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertEqual(findings[0]["severity"], "high")


class TestHostnameMatch(unittest.TestCase):
    def test_wrong_host_is_high(self):
        findings = tcc.check_certificate(make_cert(), "other.com", NOW)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("does not cover", findings[0]["message"])

    def test_wildcard_san_covers_subdomain(self):
        cert = make_cert(subjectAltName=(("DNS", "*.example.com"),))
        self.assertEqual(tcc.check_certificate(cert, "api.example.com", NOW), [])

    def test_wildcard_does_not_cover_nested_subdomain(self):
        cert = make_cert(subjectAltName=(("DNS", "*.example.com"),))
        findings = tcc.check_certificate(cert, "a.b.example.com", NOW)
        self.assertTrue(any("does not cover" in f["message"] for f in findings))

    def test_cn_fallback_when_no_san(self):
        cert = make_cert(subjectAltName=())
        self.assertEqual(tcc.check_certificate(cert, "example.com", NOW), [])


class TestSelfSignedAndVersion(unittest.TestCase):
    def test_self_signed_is_medium(self):
        cert = make_cert(issuer=((("commonName", "example.com"),),),
                         subjectAltName=())
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertTrue(any(f["severity"] == "medium"
                            and "self-signed" in f["message"]
                            for f in findings))

    def test_old_cert_version_is_low(self):
        cert = make_cert(version=1)
        findings = tcc.check_certificate(cert, "example.com", NOW)
        self.assertTrue(any(f["severity"] == "low"
                            and "version 1" in f["message"]
                            for f in findings))


class TestCipherAndTlsVersions(unittest.TestCase):
    def test_weak_cipher_is_high(self):
        findings = tcc.check_cipher(("RC4-SHA", "TLSv1.2", 128))
        self.assertEqual(findings[0]["severity"], "high")

    def test_short_key_cipher_is_medium(self):
        findings = tcc.check_cipher(("DES-CBC-SHA", "TLSv1.2", 56))
        # DES is flagged as weak first, so use a non-flagged short key name
        findings = tcc.check_cipher(("AES-56-SHA", "TLSv1.2", 56))
        self.assertEqual(findings[0]["severity"], "medium")

    def test_strong_cipher_is_clean(self):
        self.assertEqual(
            tcc.check_cipher(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)), [])

    def test_tls10_supported_is_high(self):
        findings = tcc.check_tls_versions(
            {"TLS 1.0": True, "TLS 1.1": False,
             "TLS 1.2": True, "TLS 1.3": True})
        self.assertTrue(any("TLS 1.0" in f["message"] for f in findings))

    def test_no_modern_tls_is_high(self):
        findings = tcc.check_tls_versions(
            {"TLS 1.0": True, "TLS 1.1": True,
             "TLS 1.2": False, "TLS 1.3": False})
        self.assertTrue(any("TLS 1.2 or 1.3" in f["message"] for f in findings))

    def test_modern_only_is_clean(self):
        self.assertEqual(tcc.check_tls_versions(
            {"TLS 1.0": False, "TLS 1.1": False,
             "TLS 1.2": True, "TLS 1.3": True}), [])

    def test_missing_tls13_is_low(self):
        findings = tcc.check_tls_versions(
            {"TLS 1.0": False, "TLS 1.1": False,
             "TLS 1.2": True, "TLS 1.3": False})
        self.assertEqual(findings[0]["severity"], "low")


class TestGrading(unittest.TestCase):
    def test_grade_boundaries(self):
        self.assertEqual(tcc.grade(100), "A")
        self.assertEqual(tcc.grade(90), "A")
        self.assertEqual(tcc.grade(89), "B")
        self.assertEqual(tcc.grade(75), "B")
        self.assertEqual(tcc.grade(60), "C")
        self.assertEqual(tcc.grade(40), "D")
        self.assertEqual(tcc.grade(39), "F")
        self.assertEqual(tcc.grade(0), "F")


class TestDerParsing(unittest.TestCase):
    """parse_der_certificate against real openssl-generated certificates."""

    @staticmethod
    def _make_cert_der(subj, extra_args=()):
        tmpdir = tempfile.mkdtemp()
        cert_path = os.path.join(tmpdir, "cert.pem")
        key_path = os.path.join(tmpdir, "key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_path, "-out", cert_path, "-days", "365",
            "-subj", subj, *extra_args,
        ], check=True, capture_output=True)
        with open(cert_path, "rb") as fh:
            pem = fh.read()
        shutil.rmtree(tmpdir, ignore_errors=True)
        b64 = b"".join(line.strip() for line in pem.splitlines()
                       if not line.startswith(b"-----"))
        import base64
        return base64.b64decode(b64)

    def test_self_signed_with_san(self):
        der = self._make_cert_der(
            "/CN=example.com",
            ("-addext", "subjectAltName=DNS:example.com,DNS:www.example.com"))
        cert = tcc.parse_der_certificate(der)
        self.assertEqual(cert["subject"][0][0][1], "example.com")
        self.assertEqual(cert["issuer"][0][0][1], "example.com")
        self.assertEqual(cert["version"], 3)
        self.assertEqual([name for _kind, name in cert["subjectAltName"]],
                         ["example.com", "www.example.com"])
        self.assertIsNotNone(cert["notBefore"])
        self.assertIsNotNone(cert["notAfter"])
        # Parsed dates must survive a round trip through the checker:
        # the only finding for this fresh self-signed cert is the
        # self-signed warning itself.
        findings = tcc.check_certificate(cert, "example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("self-signed", findings[0]["message"])

    def test_wildcard_san(self):
        der = self._make_cert_der(
            "/CN=example.com",
            ("-addext", "subjectAltName=DNS:*.example.com",))
        cert = tcc.parse_der_certificate(der)
        self.assertEqual([name for _kind, name in cert["subjectAltName"]],
                         ["*.example.com"])

    def test_no_san_falls_back_to_cn(self):
        der = self._make_cert_der("/CN=plain.example.com")
        cert = tcc.parse_der_certificate(der)
        self.assertEqual(cert["subjectAltName"], ())
        findings = tcc.check_certificate(cert, "plain.example.com")
        self.assertTrue(all("does not cover" not in f["message"]
                            for f in findings))

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            tcc.parse_der_certificate(b"not a certificate")


class TestLiveLocalServer(unittest.TestCase):
    """End-to-end audit against a real TLS server on localhost."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.cert = os.path.join(cls.tmpdir, "cert.pem")
        cls.key = os.path.join(cls.tmpdir, "key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", cls.key, "-out", cls.cert, "-days", "365",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, cls.key)
        cls.sock = socket.socket()
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.listen(5)
        cls.port = cls.sock.getsockname()[1]
        cls.stop = threading.Event()

        def serve():
            while not cls.stop.is_set():
                try:
                    conn, _ = cls.sock.accept()
                except OSError:
                    return
                try:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except Exception:
                    pass

        cls.thread = threading.Thread(target=serve, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()
        cls.sock.close()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_audit_localhost_flags_self_signed_and_name_ok(self):
        report = tcc.audit("localhost", self.port, timeout=5, insecure=True)
        self.assertEqual(report["host"], "localhost")
        # Only finding is the medium self-signed one: 100 - 10 = 90 -> A
        self.assertEqual(report["score"], 90)
        self.assertEqual(report["grade"], "A")
        self.assertTrue(any("self-signed" in f["message"]
                            for f in report["findings"]))
        self.assertIn("TLS 1.2", report["tls_versions_supported"])
        self.assertFalse(any("does not cover" in f["message"]
                             for f in report["findings"]))

    def test_audit_wrong_hostname_flags_mismatch(self):
        report = tcc.audit("127.0.0.1", self.port, timeout=5, insecure=True)
        self.assertTrue(any("does not cover" in f["message"]
                            for f in report["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
