import sys, socket, ssl, re
from urllib.parse import urlparse, urljoin

MAX_REDIRECTS = 10
BUF_SIZE = 60000
USER_AGENT = "WebTester-CSC361/1.0"

def parse_uri(uri: str):
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', uri):
        uri = 'http://' + uri
    u = urlparse(uri)
    scheme = u.scheme.lower()
    host = u.hostname
    port = u.port or (443 if scheme == 'https' else 80)
    path = u.path or '/'
    if u.query:
        path += '?' + u.query
    return scheme, host, port, path

def open_connection(scheme, host, port, want_h2=False):
    """
    Returns (socklike, selected_alpn) or raises a descriptive exception.
    Never returns None.
    """
    if not host:
        raise ValueError(f"No host parsed from URL (scheme={scheme!r}, port={port!r})")

    try:
        s = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        raise ConnectionError(f"TCP connect to {host}:{port} failed: {e}") from e

    selected_alpn = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        # Offer HTTP/2 via ALPN to detect support (ignore if not supported on this Python/OpenSSL)
        if want_h2:
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
        try:
            ssock = ctx.wrap_socket(s, server_hostname=host)
        except Exception as e:
            try:
                s.close()
            finally:
                raise ssl.SSLError(f"TLS handshake with {host}:{port} failed: {e}") from e
        try:
            selected_alpn = ssock.selected_alpn_protocol()
        except Exception:
            selected_alpn = None
        return ssock, selected_alpn

    # Plain HTTP
    return s, selected_alpn

    
def build_request(host, path):
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "Connection: close",
            f"User-Agent: {USER_AGENT}",
            "",
            ""
        ]
        return "\r\n".join(lines).encode("ascii", errors="strict")
    
def recv_all(sock):
    chunks = []
    while True:
        data = sock.recv(BUF_SIZE)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)

def split_header_body(resp_bytes: bytes):
    # handle \r\n\r\n or \n\n just in case
    sep = resp_bytes.find(b"\r\n\r\n")
    if sep == -1:
        sep = resp_bytes.find(b"\n\n")
        if sep == -1:
            return resp_bytes, b""
        hdr = resp_bytes[:sep]
        body = resp_bytes[sep+2:]
        return hdr, body
    hdr = resp_bytes[:sep]
    body = resp_bytes[sep+4:]
    return hdr, body

def parse_status_line(header_text: str):
    first = header_text.split("\r\n", 1)[0]
    m = re.match(r'^HTTP/(\d\.\d)\s+(\d{3})\s*(.*)$', first, re.I)
    if not m:
        return None, None, None
    return m.group(1), int(m.group(2)), m.group(3).strip()

def get_header_fields(header_text: str):
    fields = {}
    lines = header_text.split("\r\n")[1:]  # skip status line
    for line in lines:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields.setdefault(k.strip().lower(), []).append(v.strip())
    return fields

def resolve_redirect(current_url: str, location_value: str):
    return urljoin(current_url, location_value)

def extract_cookies(header_fields):
    cookies = []
    for v in header_fields.get("set-cookie", []):
        # Split attributes by ';'
        parts = [p.strip() for p in v.split(";")]
        if not parts:
            continue
        name_value = parts[0]
        if "=" not in name_value:
            continue
        cookie_name = name_value.split("=", 1)[0].strip()
        expires = None
        domain = None
        for attr in parts[1:]:
            if attr.lower().startswith("expires="):
                expires = attr[len("expires="):].strip()
            elif attr.lower().startswith("domain="):
                domain = attr[len("domain="):].strip()
        cookies.append({"name": cookie_name, "expires": expires, "domain": domain})
    return cookies

def has_password_protect(status_code, header_fields):
    # Consider 401 as password-protected (basic/digest/bearer)
    if status_code == 401:
        return True
    # Some setups respond 403 for protected areas; the spec example focuses on 401
    # Keep it conservative per assignment: only 401 -> yes
    return False

def advertised_h2(header_fields):
    for v in header_fields.get("alt-svc", []):
        if "h2" in v.lower():  # lowercased check
            return True
    return False


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 WebTester.py <url_or_host>")
        sys.exit(1)

    user_input = sys.argv[1]
    scheme, host, port, path = parse_uri(user_input)
    # We’ll track ALPN on the first HTTPS hop and on the final hop if it changed hosts
    alpn_detected = None

    current_url = f"{scheme}://{host}{(':'+str(port)) if (scheme=='http' and port!=80) or (scheme=='https' and port!=443) else ''}{path}"
    cookies_accum = []
    status_code = None
    header_fields = {}
    redirects = 0

    while redirects <= MAX_REDIRECTS:
        scheme, host, port, path = parse_uri(current_url)
        try:
            sock, selected_alpn = open_connection(scheme, host, port, want_h2=True)
        except Exception as e:
            print(f"website: {host or '(unknown)'}")
            print("1. Supports http2: no")
            print("2. List of Cookies:")
            print(f"3. Password-protected: no")
            # Optional: print a helpful note to stderr for debugging
            # import sys; print(f"[error] {e}", file=sys.stderr)
            return

        req = build_request(host if port in (80,443) else f"{host}:{port}", path)
        sock.sendall(req)
        raw = recv_all(sock)
        sock.close()

        header_bytes, body = split_header_body(raw)
        # HTTP headers are ASCII / ISO-8859-1 by spec
        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        http_ver, status_code, reason = parse_status_line(header_text)
        header_fields = get_header_fields(header_text)

        # Gather cookies from this hop too (the spec’s final list can include what the server sets along the way)
        cookies_accum.extend(extract_cookies(header_fields))

        # Redirect?
        if status_code in (301, 302, 303, 307, 308):
            locs = header_fields.get("location", [])
            if not locs:
                break
            current_url = resolve_redirect(current_url, locs[-1])
            redirects += 1
            continue
        break

    # Decide HTTP/2 support
    supports_h2 = False
    if alpn_detected == "h2":
        supports_h2 = True
    elif advertised_h2(header_fields):
        supports_h2 = True

    # Print final output (as per assignment’s example)
    # “website:” wants just the host (no scheme)
    final_host = urlparse(current_url).hostname or host

    print(f"website: {final_host}")
    print(f"1. Supports http2: {'yes' if supports_h2 else 'no'}")
    print("2. List of Cookies:")
    if cookies_accum:
        for c in cookies_accum:
            parts = [f"cookie name: {c['name']}"]
            if c.get("expires"):
                parts.append(f"expires time: {c['expires']}")
            if c.get("domain"):
                parts.append(f"domain name: {c['domain']}")
            print(", ".join(parts))
    # If none found, still print nothing else—matches example style
    print(f"3. Password-protected: {'yes' if has_password_protect(status_code, header_fields) else 'no'}")

if __name__ == "__main__":
    main()