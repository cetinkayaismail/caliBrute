# CaliBrute - Advanced HTTP Brute-Forcer

**CaliBrute** is a highly intelligent, high-performance HTTP brute-forcing engine written in Go. It is specifically designed to bypass modern Web Application Firewalls (WAFs), evade rate limits, and eliminate the frustrating "false positive" storms common in traditional brute-force tools.

While standard tools blindly throw payloads at a server and guess success based on static status codes, **CaliBrute** acts like a human. It reads raw Burp Suite requests, automatically calibrates itself to understand how the target application responds to failed logins, and dynamically adjusts its expectations for every single user it attacks.

---

##  Key Features

### 1. Auto-Calibration Engine & Smart Detection
Traditional tools break when a target application reflects the username in the error message (e.g., *"The password for C0ldd is incorrect"* vs *"User admin not found"*). This reflection changes the `Content-Length` dynamically, causing massive false positives.
* **Per-User Baselines:** CaliBrute automatically sends hidden dummy requests for *each* username before starting the attack.
* **Reflection Multipliers:** It mathematically calculates how many times the username and password are reflected in the response body.
* **Fuzzy Matching:** It establishes a baseline expected length and only flags a success if the response length deviates beyond a fuzzy threshold or if a `3xx Redirect` occurs.

### 2. Seamless Burp Suite Integration (Auto-Inject)
No need to manually construct complex `curl` commands or manually place `^USER^` and `^PASS^` markers.
* Simply right-click a request in Burp Suite, select **"Copy to file"**, and feed it to CaliBrute.
* **Auto-Inject:** CaliBrute automatically scans the request body (both Form Data and JSON) for common credential fields (e.g., `log`, `user`, `pwd`, `password`) and injects the payloads intelligently.
* It recalculates the exact `Content-Length` on the fly so the HTTP structure is never broken.

### 3. Account Lockout Prevention
* **Pass-First Strategy:** By default, CaliBrute iterates through *all users* for a single password before moving to the next password. This horizontal brute-forcing technique drastically reduces the chance of triggering account lockouts on the target system.

### 4. Advanced Stealth & WAF Evasion
When you need to fly completely under the radar, the `--stealth` flag activates a suite of evasion tactics:
* **Proxy Rotation:** Supply a file with `--proxies` to automatically route your traffic through a rotating list of HTTP and SOCKS5 proxies. Each attempt utilizes a fresh proxy to bypass IP-based rate limiting entirely.
* **IP Spoofing:** Randomizes `X-Forwarded-For`, `X-Real-IP`, and `X-Client-IP` headers on every single request to confuse backend logging systems.
* **User-Agent Rotation:** Cycles through a curated list of modern, legitimate browser User-Agents so traffic doesn't look like a script.
* **Jitter Delays:** Adds human-like randomized delays (1-5 seconds) between requests to avoid triggering time-based anomaly detectors.
* **Statelessness:** Enforces `Connection: close` and completely drops cookies between attempts to prevent session-based tracking.

### 5. Early Exit & Clean UI
When CaliBrute finds a valid credential, it doesn't waste time and resources testing the remaining millions of passwords.
* It instantly sends a stop signal to all running worker threads.
* Flushes the remaining in-flight requests.
* Prints a beautifully formatted, bright green summary table at the very bottom of your terminal so the valid credentials stand out.

---

## 🚀 Installation

Ensure you have Go installed on your system. You can compile CaliBrute natively or statically.

```bash
# Clone the repository
git clone https://github.com/yourusername/CaliBrute.git
cd CaliBrute

# Standard Build
make build

# Static Build (Recommended for CTF machines & cross-compatibility)
make build-static
```

---

## 🛠️ Usage

### Basic Usage
The simplest way to use CaliBrute is to provide a raw request file and your wordlists. CaliBrute will automatically detect the username/password fields and inject the payloads.

```bash
./calibrute -r req.txt -u admin -P /usr/share/wordlists/rockyou.txt
```

### Overriding the Target Host
If your raw request file is missing a `Host` header, or if you are attacking an IP directly without DNS (common in CTF environments), you can override the target:

```bash
./calibrute -r req.txt -u C0ldd -P rockyou.txt --target 10.10.10.50
```

### Stealth Mode & Proxy Rotation
Enable stealth mode to bypass behavioral WAFs. Note that stealth mode forces a single thread to maintain human-like behavior. You can drastically enhance this by supplying a rotating proxy list.

```bash
# Basic Stealth Mode (IP Spoofing, User-Agent Rotation, Jitter)
./calibrute -r req.txt -U users.txt -P passwords.txt --stealth

# Maximum Stealth (Combine with HTTP/SOCKS5 Proxy Rotation)
./calibrute -r req.txt -u admin -P rockyou.txt --stealth --proxies proxies.txt
```

If you don't need stealth and want maximum speed, crank up the threads:

```bash
./calibrute -r req.txt -U users.txt -P passwords.txt -t 100
```

### Manual Overrides
If you already know exactly what a successful login looks like, you can bypass the Auto-Calibration engine and tell CaliBrute exactly what to look for:

```bash
# Match exactly HTTP Status 302
./calibrute -r req.txt -U users.txt -p pass123 --mc 302

# Match a specific string in the response body
./calibrute -r req.txt -u admin -p pass123 --ms "Welcome back, Admin"
```

---

## 📊 Example Output

```text
   ______      ___ ____                __       
  / ____/___ _/ (_) __ )_______  __/ /____   
 / /   / __ '/ / / __  / ___/ / / / __/ _ \  
/ /___/ /_/ / / / /_/ / /  / /_/ / /_/  __/  
\____/\__,_/_/_/_____/_/   \__,_/\__/\___/   
   v1.0 | Advanced HTTP Brute-Forcer

[*] Loaded 1 users and 14344380 passwords.
[*] Target: 10.112.134.23
[*] Generating baselines...
[+] Baseline for user 'C0ldd': Len 1489, Pass reflected 0x
[+] Baselines established.

[FAIL] [Attempt: 0] User: C0ldd | Pass: 123456 | Status: 200 | Len: 1489
[FAIL] [Attempt: 1] User: C0ldd | Pass: password | Status: 200 | Len: 1489
[SUCCESS] [Attempt: 1222] User: C0ldd | Pass: 9876543210 | Status: 302 | Len: 0 | Reason: Status Code Redirect (3xx)

[*] Finished. Total successes: 1

========================================================================
                  [+] VALID CREDENTIALS FOUND [+]                       
========================================================================
  [✓] Username : C0ldd           | Password : 9876543210 
========================================================================
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to check the [issues page](https://github.com/yourusername/CaliBrute/issues) if you want to contribute.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

*Disclaimer: This tool was created for educational purposes, CTF environments, and authorized penetration testing only. Do not use CaliBrute against systems you do not have explicit permission to test.*
