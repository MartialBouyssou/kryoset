import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kryoset.api.tls import generate_self_signed_cert


def test_generates_cert_and_key(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    c, k = generate_self_signed_cert(cert_path, key_path)
    assert c.exists()
    assert k.exists()


def test_cert_is_valid_pem(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert cert.subject is not None


def test_cert_has_localhost_san(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    ip_addrs = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
    assert "localhost" in dns_names
    assert "127.0.0.1" in ip_addrs


def test_key_is_rsa_2048(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    key = load_pem_private_key(key_path.read_bytes(), password=None)
    assert key.key_size == 2048


def test_reuses_existing_files(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    mtime_cert = cert_path.stat().st_mtime
    mtime_key = key_path.stat().st_mtime
    generate_self_signed_cert(cert_path, key_path)
    assert cert_path.stat().st_mtime == mtime_cert
    assert key_path.stat().st_mtime == mtime_key


def test_key_file_permissions(tmp_path):
    import stat
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    mode = key_path.stat().st_mode
    assert stat.S_IMODE(mode) == 0o600
