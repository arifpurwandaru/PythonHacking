import socket
import threading
import select

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 5555
MAX_CONNECTIONS = 50
BUFFER_SIZE = 4096


def parse_http_target(request_text, url):
    """Return target host/port for regular HTTP requests."""
    if url.startswith("http://"):
        url = url[7:]
        host_port = url.split('/')[0]
        if ':' in host_port:
            host, port = host_port.rsplit(':', 1)
            return host, int(port)
        return host_port, 80

    # Browsers can send relative paths to proxies, so fall back to Host header.
    for line in request_text.splitlines()[1:]:
        if line.lower().startswith("host:"):
            host_port = line.split(':', 1)[1].strip()
            if ':' in host_port:
                host, port = host_port.rsplit(':', 1)
                return host, int(port)
            return host_port, 80

    raise ValueError("Host header not found in HTTP request")


def tunnel_data(client_socket, server_socket):
    """Relay data in both directions for HTTPS CONNECT tunnels."""
    sockets = [client_socket, server_socket]
    while True:
        readable, _, _ = select.select(sockets, [], [], 1)
        if not readable:
            continue

        for current in readable:
            peer = server_socket if current is client_socket else client_socket
            data = current.recv(BUFFER_SIZE)
            if not data:
                return
            peer.sendall(data)

def handle_client(client_socket):
    """Handle incoming client connections and forward requests to the target server."""
    try:
        # Receive the client's request
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            return

        request_text = request.decode(errors='replace')
        print(f"[*] Received request:\n{request_text}")

        # Parse the HTTP request to extract the target host and port
        lines = request_text.splitlines()
        if len(lines) > 0:
            first_line = lines[0]
            parts = first_line.split()
            if len(parts) >= 2:
                method, url = parts[0], parts[1]
                print(f"[*] Method: {method}, URL: {url}")

                if method.upper() == 'CONNECT':
                    if ':' in url:
                        host, port = url.rsplit(':', 1)
                        port = int(port)
                    else:
                        host, port = url, 443
                else:
                    host, port = parse_http_target(request_text, url)

                print(f"[*] Target Host: {host}, Target Port: {port}")

                # Create a socket to connect to the target server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                    server_socket.connect((host, port))
                    print(f"[*] Connected to target server at {host}:{port}")

                    if method.upper() == 'CONNECT':
                        # Signal tunnel establishment, then proxy encrypted bytes both ways.
                        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        tunnel_data(client_socket, server_socket)
                    else:
                        # Forward the client's request to the target server
                        server_socket.sendall(request)

                        # Receive the response from the target server and forward it back to the client
                        while True:
                            response = server_socket.recv(BUFFER_SIZE)
                            if len(response) == 0:
                                break  # No more data from server
                            client_socket.sendall(response)

    except Exception as e:
        print(f"[!] Error handling client: {e}")
    finally:
        client_socket.close()
        print("[*] Closed client connection.")

def start_proxy():
    """Start the HTTP proxy server."""
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((PROXY_HOST, PROXY_PORT))
    proxy_socket.listen(MAX_CONNECTIONS)
    print(f"[*] HTTP Proxy Server listening on {PROXY_HOST}:{PROXY_PORT}")

    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


start_proxy()