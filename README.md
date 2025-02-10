TOpPLUG HUNTER🕷🐼
   ## Hello 👋

<h1 align="center">ꪶ🐼🕷TOpPLUG🕷🐼-Hunterꫂ<br></h1>
<p align="center">
<img src="https://i.imgur.com/Gw7jtD0.jpeg" />
</p>
<h1 align="center">ꪶ🐼🕷TOpPLUG🕷🐼-Hunterꫂ<br></h1>
<p align="center">
<img src="https://i.imgur.com/rl.jpeg" />
</p>
<h1 align="center">ꪶ🐼🕷TOpPLUG🕷🐼-Hunterꫂ<br></h1>
<p align="center">
<img src="https://i.imgur.cOtwByV.jpeg" />
</p>
<p align="center">
🐼🕷TOpPLUG🕷🐼 Hunter Multiscanner <a href="https://github.com/Juancollado2003" target="_blank">TOpPLUG</a> using <a href="https://github.com/Juancollado2003/Ipv6_scanner." target="_blank">/ipv6_scanner</a> and <a href="https://www.python.org/" target="_blank">Python</a>. Don't forget to upgrade 
</p>
<p align="center">
  <a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=EB+Garamond&weight=800&size=28&duration=4000&pause=1000&random=false&width=435&lines=+_____🐼🕷TOpPLUG🕷🐼_____;HOST+UNLIMITED+x+HUNTER+FraZer;DEVELOPED+BY+🐼🕷TOpPLUG🕷🐼;REALESE+DATE+2%2F7%2F2025." alt="Typing SVG" /></a>
</p>
# ```Hunter Info```

Key Changes from original: 

1. **Replaced `multithreading` with `threading`**: This is a more standard approach.
2. **Improved Error Handling**: Added more detailed error messages.
3. **Proxy Validation**: Added a check to ensure the proxy is correctly formatted.
4. **WebSocket Protocol Handling**: Improved WebSocket handling with better error messages.
5. **Progress Feedback**: Added print statements to provide feedback to the user.
6. **Process IPs as they are generated (without waiting for the entire generation to complete).
7. **Use multiple threads to scan IPs in parallel (based on --threads).
8. **Avoid excessive RAM usage when the CIDR block is large.
9. **Control data flow with queue.Queue, preventing bottlenecks.
10. **Autoinstall dependencies. 


Below is the **full IPv6-compatible scanner**, including all original modes:  

✅ **Direct HTTP Scanner** (`direct`)  
✅ **Proxy Scanner** (`proxy`)  
✅ **SSL Scanner** (`ssl`)  
✅ **UDP Scanner** (`udp`)  
✅ **Ping Scanner** (`ping`)  
✅ **WebSocket Scanner** (`ws`)  

---

### **Key IPv6 Updates:**
- **Supports IPv6 address formatting** (`[IPv6]:port`) for HTTP/WebSocket requests.  
- **Uses `socket.AF_INET6`** for direct connections and UDP scanning.  
- **`ping6` or `ping -6`** is used for IPv6 pings.  
- **Handles IPv6 proxies, SSL handshakes, and WebSockets.**  

---

### **Full IPv6 Scanner Script**


---

### **How to Use**
#### **Scan IPv6 for open WebSocket servers**
```sh
python ipv6_scanner.py -c 2001:db8::/64 -m ws
```
#### **Perform direct HTTP scan**
```sh
python ipv6_scanner.py -f ipv6_hosts.txt -m direct -p 80,443
```
#### **Scan IPv6 hosts for SSL**
```sh
python ipv6_scanner.py -c 2607:f8b0::/32 -m ssl
```
#### **Ping IPv6 hosts**
```sh
python ipv6_scanner.py -c 2001:db8::/64 -m ping
```
---
### **Scanning the IPv6 Address Block: `2606:4700:9a9a:263d:32c5:0:69e8:7997`**
Here’s a list of **all possible scanning techniques** you can use for this IPv6 host.

---

## **1️⃣ Ping the IPv6 Host (Check if it's Reachable)**
### **Command:**
```sh
ping6 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
### **Python Script:**
```python
import subprocess

ipv6_address = "2606:4700:9a9a:263d:32c5:0:69e8:7997"
command = ["ping6", "-c", "4", ipv6_address]  # Use "ping -6" on Windows

result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print(result.stdout.decode())
```
✅ **Use case:** Checks if the host is **alive** and responding.

---

## **2️⃣ Scan Open TCP Ports (Nmap)**
### **Command:**
```sh
nmap -6 -Pn -p- 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Scans all **TCP** ports.

### **Scan Common TCP Ports**
```sh
nmap -6 -Pn -F 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Fast scan on the top 100 ports.

---

## **3️⃣ Scan Open UDP Ports (Nmap)**
### **Command:**
```sh
nmap -6 -sU -Pn -p- 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Scans **UDP** ports (e.g., DNS `53`, NTP `123`).

---

## **4️⃣ Perform a Full Service & OS Scan**
### **Command:**
```sh
nmap -6 -A -Pn 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:**  
- Detects running services  
- Identifies OS and software versions  

---

## **5️⃣ Scan for Web Services (HTTP/HTTPS)**
### **Check if the Website is Running**
```sh
curl -6 -I http://[2606:4700:9a9a:263d:32c5:0:69e8:7997]
curl -6 -I https://[2606:4700:9a9a:263d:32c5:0:69e8:7997]
```
✅ **Use case:** Detects if a **website** is running.

### **Run a Web Vulnerability Scan**
```sh
nikto -h http://[2606:4700:9a9a:263d:32c5:0:69e8:7997]
```
✅ **Use case:** Scans for **web security issues**.

---

## **6️⃣ Enumerate Subdomains**
### **Command (Nmap & DNS)**:
```sh
nmap -6 --script dns-brute -sn 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Finds **related subdomains**.

---

## **7️⃣ Perform an SSL/TLS Security Test**
### **Command:**
```sh
openssl s_client -connect [2606:4700:9a9a:263d:32c5:0:69e8:7997]:443
```
✅ **Use case:** Checks if **SSL/TLS** is enabled.

---

## **8️⃣ Scan for WebSockets**
### **Python Script:**
```python
import websocket

ipv6_host = "2606:4700:9a9a:263d:32c5:0:69e8:7997"
url = f"ws://[{ipv6_host}]"

try:
    ws = websocket.create_connection(url)
    ws.send("ping")
    response = ws.recv()
    print(f"WebSocket Response: {response}")
    ws.close()
except Exception as e:
    print(f"Failed: {e}")
```
✅ **Use case:** Checks if a **WebSocket server** is running.

---

## **9️⃣ Scan for Open Proxies**
### **Command:**
```sh
nmap -6 -p 3128,8080,1080 --script http-open-proxy 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Checks if the host is **acting as an open proxy**.

---

## **🔟 Scan for SMB or FTP Services**
### **Command (SMB):**
```sh
nmap -6 -p 445 --script smb-os-discovery 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Checks for **Windows SMB** vulnerabilities.

### **Command (FTP):**
```sh
nmap -6 -p 21 --script ftp-anon 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Checks if **anonymous FTP access** is allowed.

---

## **1️⃣1️⃣ Scan for Open Email (SMTP) Services**
### **Command:**
```sh
nmap -6 -p 25,587,465 --script smtp-open-relay 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Detects **SMTP relay vulnerabilities**.

---

## **1️⃣2️⃣ Scan for VoIP (SIP) Services**
### **Command:**
```sh
nmap -6 -p 5060,5061 --script sip-methods 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Checks if the host is running **VoIP services**.

---

## **1️⃣3️⃣ Scan for IPv6 Neighbor Discovery Spoofing**
### **Command:**
```sh
nmap -6 --script ipv6-ra-flood 2606:4700:9a9a:263d:32c5:0:69e8:7997
```
✅ **Use case:** Tests if the host is **vulnerable to IPv6 spoofing attacks**.

---

### **📌 Summary: All IPv6 Scanning Methods**
| Scan Type  | Command |
|------------|---------|
| **Ping** | `ping6 2606:4700:9a9a:263d:32c5:0:69e8:7997` |
| **Full TCP Scan** | `nmap -6 -p- 2606:4700:9a9a:263d:32c5:0:69e8:7997` |
| **Full UDP Scan** | `nmap -6 -sU -p- 2606:4700:9a9a:263d:32c5:0:69e8:7997` |
| **OS & Service Detection** | `nmap -6 -A -Pn 2606:4700:9a9a:263d:32c5:0:69e8:7997` |
| **Web Scan (Nikto)** | `nikto -h http://[2606:4700:9a9a:263d:32c5:0:69e8:7997]` |
| **SSL Scan** | `openssl s_client -connect [2606:4700:9a9a:263d:32c5:0:69e8:7997]:443` |
| **Proxy Detection** | `nmap -6 -p 3128,8080,1080 --script http-open-proxy 2606:4700:9a9a:263d:32c5:0:69e8:7997` |

---

### **💡 Need More?**
### **Scanning an IPv6 Block Using the Python Scanner Script**
Now, let's scan the entire **IPv6 block** using the custom Python scanner I provided earlier.  

---

### **📌 Example: Scanning the Entire IPv6 Block**
Let's assume the IPv6 block is **`2606:4700:9a9a:263d::/64`**  
To scan all hosts in this block, use the following **command**:

```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m direct -p 80,443
```

---

## **🔥 Full Command Examples for Scanning IPv6 Blocks**
### **1️⃣ Scan All Hosts in an IPv6 Block for Live Systems (Ping)**
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m ping
```
✅ **Finds which IPv6 addresses are responding.**

---

### **2️⃣ Scan for Open Web Services in an IPv6 Block**
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m direct -p 80,443
```
✅ **Finds active websites in the IPv6 subnet.**

---

### **3️⃣ Scan for Open UDP Ports (DNS, NTP)**
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m udp -p 53,123
```
✅ **Finds open UDP services like DNS (`53`) and NTP (`123`).**

---

### **4️⃣ Scan for SSL Services (HTTPS, Secure SMTP)**
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m ssl
```
✅ **Finds IPv6 servers with SSL/TLS enabled.**

---

### **5️⃣ Scan IPv6 Hosts for WebSockets**
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m ws
```
✅ **Detects WebSocket-enabled servers.**

---

### **6️⃣ Scan IPv6 Block Using a Proxy**
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m proxy -P [PROXY_IPV6]:8080
```
✅ **Scans IPv6 hosts using a proxy.**

---

## **💡 How It Works**
- The script **generates all IPv6 hosts** from the CIDR block.  
- Each host is **scanned based on the selected mode** (`ping`, `ssl`, `udp`, etc.).  
- **Results can be saved to a file** using `-o output.txt`.

---

## **💾 Save Results to a File**
To save the scan results:
```sh
python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m direct -p 80,443 -o results.txt
```
✅ **All results will be saved in `results.txt`.**

---

### **🔍 Need More?**
Got it! You provided this IPv6 address:  
**`2606:4700:9a9a:263d:32c5:0:69e8:7997`**  

Now, let's generate **CIDR blocks** from this address and show **how to scan them using the IPv6 scanner.**  

---

## **📌 Generating CIDR Blocks from Your IPv6 Address**
Each CIDR block represents a **range of addresses** based on the prefix size.

### **1️⃣ Scan the Entire /48 Block (Largest Subnet)**
- **IPv6 Block:** `2606:4700:9a9a::/48`  
- **Range:** `2606:4700:9a9a:0000:0000:0000:0000:0000` → `2606:4700:9a9a:FFFF:FFFF:FFFF:FFFF:FFFF`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a::/48 -m ping
  ```
✅ **Finds all active devices in this block.**

---

### **2️⃣ Scan the /56 Block**
- **IPv6 Block:** `2606:4700:9a9a:2600::/56`  
- **Range:** `2606:4700:9a9a:2600:0000:0000:0000:0000` → `2606:4700:9a9a:26FF:FFFF:FFFF:FFFF:FFFF`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a:2600::/56 -m ping
  ```
✅ **Finds devices in this subnet.**

---

### **3️⃣ Scan the /64 Block (Most Common for Local Networks)**
- **IPv6 Block:** `2606:4700:9a9a:263d::/64`  
- **Range:** `2606:4700:9a9a:263d:0000:0000:0000:0000` → `2606:4700:9a9a:263d:FFFF:FFFF:FFFF:FFFF`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m ping
  ```
✅ **Finds all live hosts in the `/64` subnet.**

---

### **4️⃣ Scan the /80 Block**
- **IPv6 Block:** `2606:4700:9a9a:263d:32c5::/80`  
- **Range:** `2606:4700:9a9a:263d:32c5:0000:0000:0000` → `2606:4700:9a9a:263d:32c5:FFFF:FFFF:FFFF`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5::/80 -m ping
  ```
✅ **Finds devices in a more specific subnet.**

---

### **5️⃣ Scan the /96 Block (Narrower Scan)**
- **IPv6 Block:** `2606:4700:9a9a:263d:32c5:0::/96`  
- **Range:** `2606:4700:9a9a:263d:32c5:0000:0000:0000` → `2606:4700:9a9a:263d:32c5:0000:FFFF:FFFF`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5:0::/96 -m ping
  ```
✅ **Useful for very specific network ranges.**

---

### **6️⃣ Scan the /112 Block (Even Smaller Scan)**
- **IPv6 Block:** `2606:4700:9a9a:263d:32c5:0:69e8::/112`  
- **Range:** `2606:4700:9a9a:263d:32c5:0:69e8:0000` → `2606:4700:9a9a:263d:32c5:0:69e8:FFFF`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5:0:69e8::/112 -m ping
  ```
✅ **Great for scanning a small segment of devices.**

---

### **7️⃣ Scan the /128 Block (Just One Device)**
- **IPv6 Block:** `2606:4700:9a9a:263d:32c5:0:69e8:7997/128`  
- **Range:** Only `2606:4700:9a9a:263d:32c5:0:69e8:7997`  
- **Command:**
  ```sh
  python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5:0:69e8:7997/128 -m ping
  ```
✅ **Tests if the single IPv6 address is alive.**

---

## **🔍 Summary: IPv6 CIDR Blocks for Your Address**
| **CIDR Block** | **Range** | **Scan Command** |
|--------------|----------|----------------|
| `/48` | `2606:4700:9a9a::/48` | `python ipv6_scanner.py -c 2606:4700:9a9a::/48 -m ping` |
| `/56` | `2606:4700:9a9a:2600::/56` | `python ipv6_scanner.py -c 2606:4700:9a9a:2600::/56 -m ping` |
| `/64` | `2606:4700:9a9a:263d::/64` | `python ipv6_scanner.py -c 2606:4700:9a9a:263d::/64 -m ping` |
| `/80` | `2606:4700:9a9a:263d:32c5::/80` | `python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5::/80 -m ping` |
| `/96` | `2606:4700:9a9a:263d:32c5:0::/96` | `python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5:0::/96 -m ping` |
| `/112` | `2606:4700:9a9a:263d:32c5:0:69e8::/112` | `python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5:0:69e8::/112 -m ping` |
| `/128` | `2606:4700:9a9a:263d:32c5:0:69e8:7997/128` | `python ipv6_scanner.py -c 2606:4700:9a9a:263d:32c5:0:69e8:7997/128 -m ping` |

---

### **📌 Which CIDR Block Should You Scan?**
- **/48 or /56:** Large-scale scans (many devices).  
- **/64:** The most common subnet size.  
- **/80 or /96:** Targeted scans for small segments.  
- **/112:** Very specific scan (only a few devices).  
- **/128:** Single device check.  

---

## **🔥 Next Steps**
- Do you need **automated IPv6 subnet scanning**?  
- Want to **scan for open ports** in the block instead of just pinging?  
- Need a **brute-force IPv6 scanner** to find hidden devices?  
Here’s the **`requirements.txt`** file for the IPv6 scanner script.  

---

### **📌 `requirements.txt`**
```txt
websocket-client
ipaddress
argparse
multithreading
requests
```

---

### **📌 How to Install the Dependencies**
Run this command in your terminal to install everything:  
```sh
pip install -r requirements.txt
```

✅ **Need more features?** Let me know if you want additional libraries added! 🚀
Let me know, and I’ll help set it up! 🚀


This script is **fully IPv6-compatible**, supporting **HTTP, Proxy, SSL, UDP, WebSockets, and Ping scanning**. Let me know if you need any modifications!
D
