#!/usr/bin/env python3
import sys
import socket
import ssl
from urllib.parse import urlparse
from typing import Tuple, List, Optional

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
RECV_BUF = 4096
SOCKET_TIMEOUT = 10  # seconds
MAX_REDIRECTS = 5
# If True, do not follow redirects to HTTPS (assignment focuses on HTTP)
STRICT_HTTP = False

# ---------------------------
# Utility Functions
# ---------------------------

def parse_uri(uri: str) -> Tuple[str, str, int, str]:
    """
    Parse the given URI into components (scheme, host, port, path?query).
    Defaults: 80 for HTTP, 443 for HTTPS.
    """
    to_parse = uri if "://" in uri else "http://" + uri
    parsed = urlparse(to_parse)

    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname
    if not host:
        raise ValueError("No host found in URI")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if parsed.port is not None:
        port = parsed.port
    else:
        port = DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT

    return scheme, host, port, path


def build_http_request(host: str, path: str) -> str:
    """
    Build a basic HTTP/1.1 GET request string.
    """
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "User-Agent: WebTester/1.0\r\n"
        "\r\n"
    )

# ---------------------------
# TLS / I/O
# ---------------------------

def _open_tcp(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    s.connect((host, port))
    return s

def _wrap_tls(sock: socket.socket, host: str, alpn_protocols: List[str]) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()  # verifies certs by default
    # ALPN list order is preference order.
    try:
        ctx.set_alpn_protocols(alpn_protocols)
    except NotImplementedError:
        # ALPN may be unavailable on very old OpenSSL; proceed without it.
        pass
    return ctx.wrap_socket(sock, server_hostname=host)

def alpn_probe_https(host: str, port: int) -> Optional[str]:
    """
    Do a short TLS handshake to learn which ALPN the server would pick.
    Returns 'h2', 'http/1.1', or None if unknown.
    """
    try:
        s = _open_tcp(host, port)
        try:
            tls = _wrap_tls(s, host, ["h2", "http/1.1"])
            try:
                # We don't send HTTP data; handshake finished already.
                return tls.selected_alpn_protocol()
            finally:
                tls.close()
        except ssl.SSLError:
            s.close()
            return None
    except (OSError, socket.timeout):
        return None

def send_request(scheme: str, host: str, port: int, request: str) -> str:
    """
    Send the HTTP/1.1 request over TCP or TLS (for HTTPS) and return the raw response as text.
    """
    data = bytearray()

    if scheme == "https":
        # First probe ALPN to see if server supports h2; record for heuristics.
        # Then reopen with http/1.1 to keep our parser simple.
        alpn = alpn_probe_https(host, port)  # may be 'h2', 'http/1.1', or None
        # Keep a tiny note in the request (not required; can remove)
        # Open real TLS channel pinned to http/1.1 so response is parseable.
        s = _open_tcp(host, port)
        try:
            tls = _wrap_tls(s, host, ["http/1.1"])
            try:
                tls.sendall(request.encode("ascii", errors="strict"))
                while True:
                    chunk = tls.recv(RECV_BUF)
                    if not chunk:
                        break
                    data.extend(chunk)
            finally:
                tls.close()
        finally:
            # _wrap_tls takes ownership; ensure underlying is closed on failure paths
            try:
                s.close()
            except Exception:
                pass
        # Store ALPN hint at the start of the buffer as a faux header for later detection logic.
        # (We won't print it; we just parse it out of band.)
        # Alternatively, return both bytes+alpn; but to keep signature, we embed a marker.
        marker = f"\r\nX-ALPN-SELECTED: {alpn or ''}\r\n"
        return marker + data.decode("iso-8859-1", errors="replace")

    # Plain HTTP
    with _open_tcp(host, port) as sock:
        sock.sendall(request.encode("ascii", errors="strict"))
        while True:
            chunk = sock.recv(RECV_BUF)
            if not chunk:
                break
            data.extend(chunk)

    return data.decode("iso-8859-1", errors="replace")


# ---------------------------
# Parsing helpers
# ---------------------------

def split_response(response: str) -> Tuple[str, str]:
    """
    Split response into header and body.
    (Strips any internal X-ALPN-SELECTED marker we might have prepended.)
    """
    # Remove the internal marker if present
    if response.startswith("\r\nX-ALPN-SELECTED:"):
        # Drop the first marker line
        nl = response.find("\r\n", 2)
        if nl != -1:
            response = response[nl+2:]

    sep = "\r\n\r\n"
    idx = response.find(sep)
    if idx == -1:
        return response, ""
    return response[:idx], response[idx + len(sep):]

def parse_status_line(header: str) -> Tuple[str, int, str]:
    first = header.split("\r\n", 1)[0]
    parts = first.split(" ", 2)
    if len(parts) < 2:
        return ("", 0, "")
    http_version = parts[0]
    try:
        code = int(parts[1])
    except ValueError:
        code = 0
    reason = parts[2] if len(parts) > 2 else ""
    return http_version, code, reason

def get_header_field_values(header: str, name_lc: str) -> List[str]:
    values = []
    for line in header.split("\r\n"):
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() == name_lc:
            values.append(v.strip())
    return values

# ---------------------------
# Analysis helpers
# ---------------------------

def pick_alpn_marker(raw_response: str) -> Optional[str]:
    """
    If we injected an ALPN marker, extract it.
    """
    if raw_response.startswith("\r\nX-ALPN-SELECTED:"):
        end = raw_response.find("\r\n", 2)
        if end != -1:
            sel = raw_response[len("\r\nX-ALPN-SELECTED: "):end]
            return sel or None
    return None

def detect_http2_support(headers_seen: List[str], status_lines: List[str], alpn_selected: Optional[str]) -> str:
    # 1) If ALPN probe picked 'h2', the server supports HTTP/2.
    if (alpn_selected or "").lower() == "h2":
        return "yes"

    # 2) Heuristics in headers
    for sl in status_lines:
        if sl.upper().startswith("HTTP/2"):
            return "yes"

    for h in headers_seen:
        alt_svc = " ".join(get_header_field_values(h, "alt-svc")).lower()
        if "h2" in alt_svc:
            return "yes"
        upgrades = ",".join(get_header_field_values(h, "upgrade")).lower()
        if "h2c" in upgrades:
            return "yes"

    return "no"

def extract_cookie_triplets(header: str) -> List[Tuple[str, Optional[str], Optional[str]]]:
    out = []
    set_cookies = get_header_field_values(header, "set-cookie")
    for sc in set_cookies:
        parts = [p.strip() for p in sc.split(";")]
        if not parts:
            continue
        first = parts[0]
        cookie_name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
        expires = None
        domain = None
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                k_lc = k.strip().lower()
                v = v.strip()
                if k_lc == "expires":
                    expires = v
                elif k_lc == "domain":
                    domain = v
        out.append((cookie_name, expires, domain))
    return out

def is_password_protected(headers_seen: List[str], codes_seen: List[int]) -> str:
    if any(c in (401, 403) for c in codes_seen):
        return "yes"
    for h in headers_seen:
        if get_header_field_values(h, "www-authenticate"):
            return "yes"
    return "no"

# ---------------------------
# Main
# ---------------------------

def main() -> int:
    # Accept CLI arg or stdin
    if len(sys.argv) == 2:
        uri = sys.argv[1].strip()
    else:
        data = sys.stdin.read().strip()
        if not data:
            print("Usage: python3 WebTester.py <URL>\n(or pipe a URL via stdin)")
            return 1
        uri = data

    try:
        scheme, host, port, path = parse_uri(uri)
    except ValueError as e:
        print(f"Error: {e}")
        return 2

    headers_seen: List[str] = []
    status_lines: List[str] = []
    codes_seen: List[int] = []
    alpn_selected: Optional[str] = None  # last HTTPS ALPN result (if any)

    current_scheme = scheme
    current_host = host
    current_port = port
    current_path = path

    debug_preview_printed = False

    for _ in range(MAX_REDIRECTS + 1):
        request = build_http_request(current_host, current_path)

        # Debug preview (print once)
        if not debug_preview_printed:
            print("--- Request begin ---")
            print(request.rstrip("\r\n"))
            print("--- Request end ---\n")
            debug_preview_printed = True

        # Send request over HTTP or HTTPS
        try:
            raw = send_request(current_scheme, current_host, current_port, request)
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
            print(f"Network error: {e}")
            return 3

        # Capture ALPN if present in our internal marker
        sel = pick_alpn_marker(raw)
        if sel is not None:
            alpn_selected = sel

        header, body = split_response(raw)
        headers_seen.append(header)
        status_line = header.split("\r\n", 1)[0]
        status_lines.append(status_line)
        http_version, code, reason = parse_status_line(header)
        codes_seen.append(code)

        # Show short response preview
        print("--- Response header ---")
        print(header)
        print("\n--- Response body (first 200 chars) ---")
        print(body[:200] + ("..." if len(body) > 200 else ""))

        # Redirect handling
        if code in (301, 302, 303, 307, 308):
            loc_vals = get_header_field_values(header, "location")
            if not loc_vals:
                break
            new_uri = loc_vals[0]
            try:
                ns, nh, np, npath = parse_uri(new_uri)
            except ValueError:
                if new_uri.startswith("/"):
                    ns, nh, np, npath = current_scheme, current_host, current_port, new_uri
                else:
                    break

            if ns == "https" and STRICT_HTTP:
                print("[Info] Redirect target is HTTPS, but STRICT_HTTP is enabled. "
                      "Stopping here per assignment focus on HTTP.")
                break

            current_scheme = ns or "http"
            current_host = nh
            current_port = np or (DEFAULT_HTTPS_PORT if current_scheme == "https" else DEFAULT_HTTP_PORT)
            current_path = npath
            print(f"\n[Info] Following redirect to {current_scheme}://{current_host}:{current_port}{current_path}\n")
            continue

        # Not a redirect -> done
        break

    # Compose final report
    http2 = detect_http2_support(headers_seen, status_lines, alpn_selected)
    cookies = extract_cookie_triplets(headers_seen[-1] if headers_seen else "")
    pw = is_password_protected(headers_seen, codes_seen)

    print()
    print(f"website: {host}")
    print(f"1. Supports http2: {http2}")
    print("2. List of Cookies:")
    if cookies:
        for name, expires, domain in cookies:
            line = f"cookie name: {name}"
            if expires:
                line += f", expires time: {expires}"
            if domain:
                line += f"; domain name: {domain}"
            print(line)
    print(f"3. Password-protected: {pw}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
