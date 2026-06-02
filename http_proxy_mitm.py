import ipaddress
import select
import socket
import ssl
import threading
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 5555
MAX_CONNECTIONS = 50
BUFFER_SIZE = 4096
MITM_HTTPS = True
CERTS_DIR = Path("certs")
CA_KEY_PATH = CERTS_DIR / "mitm_ca_key.pem"
CA_CERT_PATH = CERTS_DIR / "mitm_ca_cert.pem"

KNOWN_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "CONNECT",
}


def parse_http_target(request_text, url):
    """Return target host/port for regular HTTP requests."""
    if url.startswith("http://"):
        url = url[7:]
        host_port = url.split("/", 1)[0]
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            return host, int(port)
        return host_port, 80

    for line in request_text.splitlines()[1:]:
        if line.lower().startswith("host:"):
            host_port = line.split(":", 1)[1].strip()
            if ":" in host_port:
                host, port = host_port.rsplit(":", 1)
                return host, int(port)
            return host_port, 80

    raise ValueError("Host header not found in HTTP request")


def _load_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)


def _load_certificate(path):
    with open(path, "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())


def ensure_ca_files():
    """Create a local CA certificate for HTTPS MITM if it does not exist."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        return

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PythonHacking"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PythonHacking MITM CA"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as key_file:
        key_file.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CA_CERT_PATH, "wb") as cert_file:
        cert_file.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[*] Created local MITM CA key: {CA_KEY_PATH}")
    print(f"[*] Created local MITM CA cert: {CA_CERT_PATH}")


def _build_san(host):
    try:
        return x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))])
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(host)])


def get_or_create_host_cert(host):
    """Generate a host certificate signed by local CA and return cert/key paths."""
    safe_host = host.replace(":", "_").replace("/", "_")
    cert_path = CERTS_DIR / f"{safe_host}.crt.pem"
    key_path = CERTS_DIR / f"{safe_host}.key.pem"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    ca_key = _load_private_key(CA_KEY_PATH)
    ca_cert = _load_certificate(CA_CERT_PATH)

    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])

    host_cert = (
        x509.CertificateBuilder()
        .subject_name(host_subject)
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=30))
        .add_extension(_build_san(host), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(key_path, "wb") as key_file:
        key_file.write(
            host_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as cert_file:
        cert_file.write(host_cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


def log_request_line(request_line):
    parts = request_line.split()
    if len(parts) < 2:
        return

    method = parts[0].upper()
    if method in KNOWN_METHODS:
        target = parts[1]
        print(f"[HTTP] {method} {target}")


def relay_data(client_socket, server_socket, parse_client_http=False):
    """Relay data in both directions and optionally parse client request lines."""
    sockets = [client_socket, server_socket]
    partial_line = b""

    while True:
        readable, _, _ = select.select(sockets, [], [], 1)
        if not readable:
            continue

        for current in readable:
            peer = server_socket if current is client_socket else client_socket
            data = current.recv(BUFFER_SIZE)
            if not data:
                return

            if parse_client_http and current is client_socket:
                partial_line += data
                while b"\r\n" in partial_line:
                    line, partial_line = partial_line.split(b"\r\n", 1)
                    if not line:
                        break
                    log_request_line(line.decode(errors="replace"))

            peer.sendall(data)


def handle_connect(client_socket, host, port):
    """Handle CONNECT requests with optional HTTPS interception."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_server_socket:
        raw_server_socket.connect((host, port))
        print(f"[*] Connected to target server at {host}:{port}")

        if not MITM_HTTPS:
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            print("[*] CONNECT tunnel established (pass-through mode).")
            relay_data(client_socket, raw_server_socket, parse_client_http=False)
            return

        ensure_ca_files()
        cert_path, key_path = get_or_create_host_cert(host)

        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        server_context = ssl.create_default_context()

        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        with client_context.wrap_socket(client_socket, server_side=True) as client_tls_socket:
            with server_context.wrap_socket(raw_server_socket, server_hostname=host) as server_tls_socket:
                print(f"[*] CONNECT MITM active for {host}:{port}")
                relay_data(client_tls_socket, server_tls_socket, parse_client_http=True)


def handle_plain_http(client_socket, request, request_text):
    lines = request_text.splitlines()
    if not lines:
        return

    parts = lines[0].split()
    if len(parts) < 2:
        return

    method, url = parts[0], parts[1]
    log_request_line(lines[0])
    host, port = parse_http_target(request_text, url)
    print(f"[*] Target Host: {host}, Target Port: {port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect((host, port))
        server_socket.sendall(request)
        relay_data(server_socket, client_socket, parse_client_http=False)


def handle_client(client_socket):
    """Handle incoming client connections and forward requests to target server."""
    try:
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            return

        request_text = request.decode(errors="replace")
        lines = request_text.splitlines()
        if not lines:
            return

        first_line = lines[0]
        parts = first_line.split()
        if len(parts) < 2:
            return

        method, url = parts[0], parts[1]

        if method.upper() == "CONNECT":
            if ":" in url:
                host, port_text = url.rsplit(":", 1)
                port = int(port_text)
            else:
                host, port = url, 443
            print(f"[*] CONNECT {host}:{port}")
            handle_connect(client_socket, host, port)
        else:
            handle_plain_http(client_socket, request, request_text)

    except Exception as error:
        print(f"[!] Error handling client: {error}")
    finally:
        client_socket.close()


def start_proxy():
    """Start the HTTP/HTTPS proxy server."""
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((PROXY_HOST, PROXY_PORT))
    proxy_socket.listen(MAX_CONNECTIONS)

    print(f"[*] Proxy listening on {PROXY_HOST}:{PROXY_PORT}")
    print(f"[*] HTTPS MITM mode: {'ON' if MITM_HTTPS else 'OFF'}")
    if MITM_HTTPS:
        print(f"[*] Trust this CA in your browser/system: {CA_CERT_PATH.resolve()}")

    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,), daemon=True)
        client_handler.start()


if __name__ == "__main__":
    start_proxy()
