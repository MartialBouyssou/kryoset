import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_CERT_PATH = Path.home() / ".kryoset" / "api_cert.pem"
DEFAULT_KEY_PATH = Path.home() / ".kryoset" / "api_key.pem"


def generate_self_signed_cert(
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
) -> tuple[Path, Path]:
    """
    Generate a self-signed TLS certificate with SAN for localhost and 127.0.0.1.

    If the certificate and key files already exist they are reused without
    regeneration.

    Args:
        cert_path: Destination path for the PEM-encoded certificate.
        key_path: Destination path for the PEM-encoded private key.

    Returns:
        A tuple of (cert_path, key_path) pointing to the files on disk.
    """
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    cert_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kryoset"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    import os
    os.chmod(key_path, 0o600)

    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path
