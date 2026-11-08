"""
Безопасность API серверного агента:
- генерация и загрузка self-signed TLS-сертификата;
- генерация и проверка токена доступа;
- SHA-256 отпечаток сертификата для ручной сверки сторон.
"""

import os
import ssl
import socket
import secrets
import hashlib
import ipaddress
import datetime

from common.config import API_TOKEN

CERT_FILENAME = "server.crt"
KEY_FILENAME = "server.key"


def ensure_self_signed_cert(certs_dir: str) -> tuple:
    """
    Возвращает (cert_path, key_path).
    Генерирует self-signed сертификат при первом запуске.
    Требует пакет cryptography.
    """
    cert_path = os.path.join(certs_dir, CERT_FILENAME)
    key_path = os.path.join(certs_dir, KEY_FILENAME)
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as e:
        raise RuntimeError(
            "Для работы TLS требуется пакет cryptography: pip install cryptography"
        ) from e

    os.makedirs(certs_dir, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = socket.gethostname()

    san_entries = [
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        for info in socket.getaddrinfo(hostname, None):
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(info[4][0])))
            except ValueError:
                pass
    except Exception:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Assessment Server"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


def build_server_ssl_context(certs_dir: str) -> ssl.SSLContext:
    """SSL-контекст сервера с сертификатом из certs_dir (генерируется при необходимости)."""
    cert_path, key_path = ensure_self_signed_cert(certs_dir)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def get_cert_fingerprint(certs_dir: str) -> str:
    """SHA-256 отпечаток сертификата сервера (для ручной сверки с атакующей стороной)."""
    cert_path = os.path.join(certs_dir, CERT_FILENAME)
    if not os.path.exists(cert_path):
        return ""
    with open(cert_path, "rb") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read().decode())
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def generate_token() -> str:
    """Токен доступа: статичный из конфигурации или случайный при каждом запуске."""
    return API_TOKEN or secrets.token_hex(16)


def check_token(provided: str, expected: str) -> bool:
    """Проверка токена с защитой от тайминг-атак."""
    if not expected or not provided:
        return False
    return secrets.compare_digest(provided, expected)
