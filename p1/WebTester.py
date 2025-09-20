#!/usr/bin/env python3
import sys
import socket
from urllib.parse import urlparse
from typing import Tuple


DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
RECV_BUF = 4096
SOCKET_TIMEOUT = 10 # seconds

# ---------------------------
# Utility Functions
# ---------------------------

def parse_uri(uri: str) -> Tuple[str, str, int, str]:
    """
    Parse the given URI into components (protocol, host, port, path).
    Default port: 80 for HTTP, 443 for HTTPS.
    """
    to_parse = uri if "://" in uri else "http://" + uri
    parsed = urlparse(to_parse)
    
    scheme = parsed.scheme or "http"
    host = parsed.hostname
    path = parsed.path or "/"
    
    if not path:
        path = "/"
    if parsed.port is not None:
        port = parsed.port
    else:
        port = DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT
    
    return scheme.lower(), host, port, path


def build_http_request(host: str, path: str) -> str:
    """
    Build a basic HTTP/1.1 GET request string.
    """
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request

def send_request(host: str, port: int, request: str) -> str:
    """
    Send the HTTP request to the given host/port and return the raw response.
    """
    data = bytearray()
    addr = (host, port)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect(addr)
        sock.sendall(request.encode('ascii', errors='strict'))
        
        while True:
            chunk = sock.recv(RECV_BUF)
            if not chunk:
                break
            data.extend(chunk)
            
    return data.decode('iso-8859-1', errors='replace')

def split_response(response: str) -> Tuple[str, str]:
    """
    Split response into header and body.
    """
    sep = "\r\n\r\n"
    idx = response.find(sep)
    if idx == -1:
        #treat as header only
        return response, ""
    return response[:idx], response[idx + len(sep):]

def parse_response(response):
    """
    Split response into header and body.
    """
    parts = response.split("\r\n\r\n", 1)
    header = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    return header, body


# ---------------------------
# Analysis Routines
# ---------------------------

def check_http2_support(header):
    """
    Placeholder: Check if server supports HTTP/2.
    """
    # TODO: Implement proper detection.
    return "no"


def extract_cookies(header):
    """
    Extract cookies from response header.
    """
    cookies = []
    for line in header.split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            cookies.append(line[len("Set-Cookie: "):])
    return cookies


def check_password_protection(header):
    """
    Determine if page is password-protected.
    """
    if "401 Unauthorized" in header or "403 Forbidden" in header:
        return "yes"
    return "no"


# ---------------------------
# Main
# ---------------------------

def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 WebTester.py <URL>")
    return 1

    uri = sys.argv[1].strip()

    try:
        scheme, host, port, path = parse_uri(uri)
    except ValueError as e:
        print(f"Error: {e}")
    return 2


    if scheme == 'https':
        print("[Warning] HTTPS/TLS not implemented in this step. Use http:// for now.")


    request = build_http_request(host, path)


    #  debug: show the outgoing request
    print("--- Request begin ---")
    # Show the request line and Host header explicitly, like the spec's example
    print(request.rstrip("\r\n"))
    print("--- Request end ---\n")


    try:
        raw = send_request(host, port, request)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"Network error: {e}")
    return 3


    header, body = split_response(raw)


    print("--- Response header ---")
    print(header)
    print("\n--- Response body (first 200 chars) ---")
    print(body[:200] + ("..." if len(body) > 200 else ""))


    # No final summary yet — will be added after implementing later steps.
    return 0




if __name__ == "__main__":
    raise SystemExit(main())