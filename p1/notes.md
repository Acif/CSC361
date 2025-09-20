# WebTester.py — Function-by-function breakdown

This document explains what each part of the provided `WebTester.py` does, how it works, and important edge cases. It’s organized in the order the code appears.

---

## Module-level constants

- `MAX_REDIRECTS = 10`  
  Upper bound on the number of HTTP redirects the client will follow to prevent infinite loops.

- `BUF_SIZE = 65536`  
  Socket receive buffer size (64 KiB per `recv` call).

- `USER_AGENT = "CSC361-WebTester/1.0"`  
  Advertised User-Agent string sent in the request headers.

---

## `parse_uri(uri: str)`

**Purpose:** Normalize and dissect a user-provided URI/host into `(scheme, host, port, path)` suitable for making a connection and HTTP request.

**How it works:**
1. If the string doesn’t start with a scheme (`http://` or `https://`), it **assumes HTTP** and prepends `http://` so that `urlparse` can handle bare hosts like `example.com`.
2. Uses `urllib.parse.urlparse` to split the URL into components.
3. Selects default port **80** for HTTP and **443** for HTTPS when the URL lacks an explicit port.
4. Ensures the **path** is never empty: defaults to `/` and appends `?query` when needed.

**Returns:** `(scheme, host, port, path)`

**Edge cases:**
- Bare hostnames without scheme (e.g., `www.uvic.ca`) are accepted.
- Non-standard ports (e.g., `https://example.com:8443/`) are preserved.
- Empty path becomes `/` to build a valid request line.

---

## `open_connection(scheme, host, port, want_h2=False)`

**Purpose:** Establish a TCP connection, and if HTTPS is used, wrap it in TLS. Optionally offers **ALPN** protocols to detect HTTP/2 support.

**How it works:**
1. Calls `socket.create_connection((host, port), timeout=10)` to open a TCP socket.
2. If `scheme == "https"`:
   - Creates a default TLS context via `ssl.create_default_context()`.
   - If `want_h2` is `True`, attempts `ctx.set_alpn_protocols(["h2", "http/1.1"])` to advertise HTTP/2 support during the TLS handshake.
   - Wraps the TCP socket using `ctx.wrap_socket(..., server_hostname=host)` for SNI.
   - Reads the selected ALPN with `ssock.selected_alpn_protocol()` (may be `None` if not supported by the server or platform).
3. For plain HTTP, returns the raw TCP socket and `None` for ALPN.

**Returns:** `(socket_or_sslsocket, selected_alpn_protocol)` where `selected_alpn_protocol` is one of `"h2"`, `"http/1.1"`, or `None`.

**Edge cases:**
- Some Python builds/platforms may not support `set_alpn_protocols`—the `NotImplementedError` is swallowed and ALPN detection is skipped.
- Timeouts or DNS failures raise exceptions before this function returns (caller doesn’t catch them here).

---

## `build_request(host, path)`

**Purpose:** Construct a minimal but valid **HTTP/1.1 GET** request as bytes.

**How it works:**
- Builds the start-line `GET {path} HTTP/1.1` and essential headers:
  - `Host: {host}` (includes `:port` when non-default)
  - `Connection: close` (server will close the connection after the response)
  - `Accept: */*`
  - `User-Agent: {USER_AGENT}`
- Joins with `\r\n` and ends with an empty line to terminate the header block.
- Encodes as ASCII bytes (per HTTP/1.1 header rules).

**Returns:** `bytes` representing the full request headers (no body).

**Edge cases:**
- Path must start with `/` (ensured by `parse_uri` logic).
- Host header may include a port (e.g., `example.com:8080`) when necessary.

---

## `recv_all(sock)`

**Purpose:** Read all available response bytes from the socket until EOF.

**How it works:**
- Loops over `sock.recv(BUF_SIZE)` and collects chunks until `recv` returns empty (server closed connection).
- Concatenates and returns the full byte string.

**Notes & edge cases:**
- Works for both content-length and chunked responses because the connection is closed (`Connection: close`), so EOF reliably signals the end.
- For very large responses, it stores all bytes in memory (acceptable for this assignment; not streaming).

---

## `split_header_body(resp_bytes: bytes)`

**Purpose:** Separate the HTTP response into a **header block** and a **body** byte sequence.

**How it works:**
1. Searches for the sequence `\r\n\r\n` (standard header terminator).  
2. Falls back to `\n\n` if CRLF isn’t present (some servers use LF-only, though not strictly compliant).
3. Returns a tuple `(header_bytes, body_bytes)`.

**Edge cases:**
- If no separator is found, the whole response is treated as headers and body is empty—defensive behavior to avoid crashes.

---

## `parse_status_line(header_text: str)`

**Purpose:** Extract the HTTP version, numeric status code, and reason phrase from the **first line** of the response headers.

**How it works:**
- Grabs the first line (status line) and matches it with a regex:  
  `^HTTP/(\d\.\d)\s+(\d{3})\s*(.*)$`
- Returns `(http_version, status_code:int, reason:str)` or `(None, None, None)` if parsing fails.

**Edge cases:**
- Non-HTTP responses or malformed status lines won’t crash the program; they result in `None` values.

---

## `get_header_fields(header_text: str)`

**Purpose:** Parse the remaining header lines into a **case-insensitive multimap** (dict of `lowercase_name -> [values...]`).

**How it works:**
- Splits headers into lines (skipping the status line).
- For each line containing a colon, splits into `name: value` once.
- Lowercases the header name and appends the trimmed value to a list in the dict.

**Returns:** `dict[str, list[str]]`

**Edge cases:**
- Ignores malformed lines (e.g., without `:`).  
- Doesn’t explicitly handle header *folding* (deprecated in RFCs); most servers use one line per field.

---

## `resolve_redirect(current_url: str, location_value: str)`

**Purpose:** Produce an absolute URL for the next request when following a redirect.

**How it works:**
- Uses `urllib.parse.urljoin` to resolve `Location:` that might be relative (e.g., `/login`) or absolute (`https://…`).

**Returns:** Absolute URL string.

---

## `extract_cookies(header_fields)`

**Purpose:** Pull out **cookie name**, and optionally **expires** and **domain** from each `Set-Cookie` header. (Other attributes are ignored by design.)

**How it works:**
1. Iterates `header_fields.get("set-cookie", [])` to get all cookie header values.
2. Splits each value by `;` into parts: the **first** part is `name=value` and subsequent parts are attributes.
3. Extracts the cookie **name** (text before the first `=`).  
4. Scans attributes for `expires=` and `domain=` (case-insensitive) and stores their values if present.
5. Appends a dict like `{"name": "...", "expires": "...", "domain": "..."}` to the results list.

**Returns:** `list[dict]`

**Edge cases:**
- Cookies with multiple `=` in the value are fine because only the **first** `=` is used to split out the name.
- Attributes are treated as plain strings; no RFC6265 date parsing (that’s intentional for the assignment).

---

## `has_password_protect(status_code, header_fields)`

**Purpose:** Determine if the **final** resource is password-protected for the assignment’s definition.

**How it works:**
- Returns `True` if the final HTTP status code is **401 Unauthorized**.
- Returns `False` otherwise (even for `403 Forbidden`).

**Rationale:** The assignment ties “password-protected” explicitly to `401` (presence of `WWW-Authenticate`). Staying conservative avoids false positives.

---

## `advertised_h2(header_fields)`

**Purpose:** Heuristic for HTTP/2 support when ALPN info isn’t available.

**How it works:**
- Checks any `Alt-Svc` header for tokens containing `"h2"`. If present, likely indicates the origin can serve HTTP/2 (usually over HTTPS).

**Returns:** `True`/`False`

**Edge cases:**
- `Alt-Svc` can be complex; this keeps detection simple and permissive.

---

## `main()`

**Purpose:** Orchestrates the full CLI workflow from argument parsing to printing the final report.

**Flow:**

1. **Argument check** — requires exactly one argument: `python3 WebTester.py <url_or_host>`.
2. **Initial parsing** — calls `parse_uri` to get `(scheme, host, port, path)` and builds `current_url`.
3. **Redirect loop** (up to `MAX_REDIRECTS`):
   - Opens a connection via `open_connection`, advertising ALPN (`h2`, `http/1.1`) for HTTPS.
   - Builds and sends request with `build_request`.
   - Receives the entire response via `recv_all`.
   - Splits headers/body with `split_header_body`.
   - Parses the **status line** and **headers** (`parse_status_line`, `get_header_fields`).
   - Accumulates cookies from **this hop** via `extract_cookies` (by design, the list can include cookies from intermediate redirects).
   - If status is a redirect (`301/302/303/307/308`) and `Location` exists, resolve the next `current_url` with `resolve_redirect` and iterate.
   - Otherwise, break out of the loop (final response reached).
4. **HTTP/2 detection** — declares support if:
   - TLS **ALPN** selected `"h2"`, **or**
   - `advertised_h2(header_fields)` is `True`.
5. **Password protection** — `has_password_protect(status_code, header_fields)` — `yes` iff final status is **401**.
6. **Output formatting** — prints:
   - `website: <host>` (final host only, no scheme)
   - `1. Supports http2: yes|no`
   - `2. List of Cookies:` followed by one line per cookie with available fields
   - `3. Password-protected: yes|no`

**Edge cases & safeguards:**
- Redirects without `Location` stop the loop gracefully.
- If the server never terminates headers properly, parsing degrades gracefully without crashing.
- ALPN may be `None` on older OpenSSL/Python builds; the `Alt-Svc` check provides a fallback signal.

---

## Putting it together (mental model)

- **Networking:** `open_connection` → `build_request` → `recv_all`  
- **Parsing:** `split_header_body` → `parse_status_line` → `get_header_fields`  
- **Policy:** `extract_cookies`, redirect handling, HTTP/2 detection, 401 check  
- **Reporting:** Final printout in the required shape.

---

## Common modifications (if you need them)

- **Custom redirect cap:** change `MAX_REDIRECTS`.
- **More cookie attributes:** extend `extract_cookies` to parse `path`, `secure`, `httponly`, `samesite`.
- **Chunked decoding:** not necessary here because we read-to-EOF, but you could parse `Transfer-Encoding: chunked` to count bytes precisely.
- **Stricter HTTP/2 check:** require ALPN `"h2"` only (drop the `Alt-Svc` heuristic) if your grader expects that.

