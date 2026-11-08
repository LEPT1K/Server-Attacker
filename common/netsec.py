"""
Клиентская часть TLS для связи атакующего агента с серверным:
- SSL-контекст без проверки цепочки (self-signed сертификат сервера);
- получение SHA-256 отпечатка сертификата сервера для ручной сверки.
"""

import ssl
import socket
import hashlib


def build_client_ssl_context() -> ssl.SSLContext:
    """
    SSL-контекст клиента для self-signed сертификата:
    цепочка не проверяется, подлинность контролируется сверкой отпечатка.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_server_fingerprint(host: str, port: int, timeout: float = 5.0) -> str:
    """SHA-256 отпечаток сертификата удалённого сервера (для сверки на стороне атакующего)."""
    try:
        ctx = build_client_ssl_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return ""
        digest = hashlib.sha256(der).hexdigest().upper()
        return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    except Exception:
        return ""
