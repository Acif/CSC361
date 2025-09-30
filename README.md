# Create a markdown file containing the full study guide content

content = """# ECS 361 – Computer Communications & Networks  
## Comprehensive Study Guide (Introduction, Application Layer – HTTP & DNS, Transport Layer)

---

## 1. Introduction to Computer Networks

### 1.1 Course Overview
- **Objectives**:
  1. Understand networking principles and operations.
  2. Gain experience implementing and using protocols.
  3. Learn basic research methodologies in networking.
- **Topics Covered**:
  - Introduction to the Internet, protocols, and layering.
  - Application Layer (HTTP, DNS, sockets).
  - Transport Layer (UDP, TCP, congestion control).
  - Network Layer (IP, routing).
  - Link Layer (Ethernet, Wi-Fi, MAC techniques).
- **Workload**:
  - 3 programming assignments (13–16% each).
  - 3 midterms (15% each).
  - Labs & reports: 10%.

**Study Tip:**  
Keep Kurose & Ross textbook handy for deeper explanations.

---

### 1.2 Internet Overview
- The Internet is a **“network of networks”**—interconnected ISPs:
  - Tier-1 ISPs: AT&T, NTT, Sprint.
  - Regional/local ISPs connect to tier-1.
  - Content Provider Networks: e.g., Google, Facebook (private backbones).
- Protocols:
  - Examples: **HTTP, TCP/IP, Wi-Fi, 4G/5G, Ethernet**.
- Standards:
  - **RFC (Request for Comments)** by IETF defines Internet standards.

**Example:**  
A web request from your browser to `www.example.com` uses:
- **Application Layer:** HTTP  
- **Transport Layer:** TCP  
- **Network Layer:** IP  
- **Link Layer:** Ethernet/Wi-Fi  

---

### 1.3 Protocols and Layering
- **Protocol:** Agreement between two parties on communication rules.
- **Layering Principle:** Breaks network architecture into layers with defined interfaces.
- **Reference Models:**
  - **OSI Model:** 7 layers.
  - **TCP/IP Model:** 5 layers – Application, Transport, Network, Link, Physical.
- **Encapsulation:**  
  Data is wrapped in headers as it moves down layers:
  - Message → Segment → Datagram → Frame.

**Key Formula:**  
Transmission delay: \( d_{trans} = \frac{L}{R} \)  
- L = packet size (bits), R = link bandwidth (bps).

---

### 1.4 Switching Methods
- **Packet Switching (store-and-forward):**
  - Routers forward complete packets hop-by-hop.
  - Efficient resource sharing, but may cause **queueing delays** and **packet loss**.
- **Circuit Switching:**
  - Dedicated resources reserved end-to-end for a connection.
  - Guaranteed performance but inefficient if idle.

**Example:**  
- Circuit switching allows only **10 users** on a 1 Gbps link if each needs 100 Mbps.  
- Packet switching supports ~35 users if not all active simultaneously.

---

### 1.5 Delay, Loss, and Throughput
- **Four Delay Components:** \( d_{nodal} = d_{proc} + d_{queue} + d_{trans} + d_{prop} \)
  - Processing delay
  - Queueing delay
  - Transmission delay
  - Propagation delay
- **Throughput:** Bottleneck link determines overall rate.

---

#### **Study Pointers (Introduction)**
- Understand the **layering concept** thoroughly.
- Be able to calculate **delay and throughput**.
- Know differences between **circuit vs. packet switching**.

---

## 2. Application Layer – The World Wide Web (HTTP)

### 2.1 Sockets
- **Socket:** (IP address + port number) endpoint for communication.
- Acts as a **door** between application and transport layers.

---

### 2.2 Web & HTTP Overview
- **Web Objects:** HTML files, images, audio, etc.
- **Web Page:** Base HTML + embedded objects (referenced by URLs).
- **Client-Server Model:**
  - Browser = client.
  - Web server = server.
- **HTTP uses TCP (port 80)** for reliable communication.
- **HTTP is stateless:** Server does not remember past requests.

**Example:**  
`https://www.someschool.edu/someDept/pic.gif`  
- Hostname: `www.someschool.edu`  
- Path: `/someDept/pic.gif`

---

### 2.3 HTTP Connections
- **Non-Persistent HTTP (HTTP/1.0):**
  - 1 TCP connection per object.
  - Requires **2 RTTs per object** → slower.
- **Persistent HTTP (HTTP/1.1):**
  - Single TCP connection reused for multiple objects.
  - Reduces delay to ~1 RTT for subsequent objects.

---

### 2.4 HTTP Message Structure
- **Request Message:** ASCII text.
  - Request line: Method, URL, Version.
  - Headers: Key-value pairs (e.g., Host, User-Agent).
  - Body: Optional (e.g., form data).
- **Response Message:** ASCII text.

  - Status line: Version, Status code, Phrase.
  - Headers: Key-value pairs (e.g., Content-Type).
  - Body: Requested object.
**Common Methods:**
  - GET: Retrieve data.
  - POST: Submit data to be processed.
  - PUT: Update existing resource.
  - DELETE: Remove resource.
**Status Codes:**
  - 200 OK: Success.
  - 404 Not Found: Resource not found.
  - 500 Internal Server Error: Server error.
---
### Cookies
- **Cookies:** Small data files stored on client by server. 
- Used for session management, personalization, tracking.
- Sent in HTTP headers: `Set-Cookie` (server to client), `Cookie` (client to server).
**Example:**
  - User logs in → server sets cookie with session ID.
  - Subsequent requests include cookie for authentication.
---### Web Caching

### Web Caching
- **Cache:** Temporary storage of web objects closer to client.
- Reduces latency and network traffic.
- **Types of Caches:**  
  - Browser cache
  - Proxy cache
  - Content Delivery Networks (CDNs)
- **Cache Validation:**
  - `If-Modified-Since` header to check if object has changed.
- **Freshness:** Controlled by `Cache-Control` and `Expires` headers.
---
