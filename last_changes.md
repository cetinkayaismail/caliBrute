# Last Changes

The recent improvements and bug fixes made to the CaliBrute project are summarized below:

### 1. IP Spoofing Bug Fix (`pkg/utils/utils.go`)
- Fixed a byte-to-string conversion logic error in the `GenerateSpoofedIP` function that produced invalid characters in HTTP headers.
- Formatted the spoofed IP addresses properly using `fmt.Sprintf` to generate valid dotted-decimal IPv4 address strings.

### 2. HTTP Client & Transport Reuse (`pkg/utils/utils.go` & `pkg/engine/engine.go`)
- Replaced the practice of creating a new HTTP client for every single request with a single shared `http.Client` managed in the `Engine` struct. This utilizes Go's connection pooling and prevents socket/port exhaustion under high thread counts.
- Refactored the proxy rotation logic to run on the shared `http.Transport`. Each outgoing request now dynamically resolves a proxy using the `transport.Proxy` callback instead of instantiating new clients.

### 3. Rate Limit & Block Auto-Retry Mechanism (`pkg/engine/engine.go`)
- Restructured the single request sequence inside the worker loop into a retry loop (up to 5 attempts).
- When a rate limit or block (`res.IsBlocked`) is detected, the engine pauses for 30 seconds and retries the exact same user/pass attempt instead of skipping it.
- Monitored the `stopChan` concurrently during this 30-second pause to guarantee that the application terminates immediately if another worker finds valid credentials.

### 4. Content-Type Aware Auto-Inject Parser (`pkg/parser/parser.go`)
- Upgraded the `autoInjectPlaceholders` function to check the `Content-Type` header of the Burp Suite request template.
- Implemented robust, parameter-bounded regex patterns for both JSON bodies and URL-encoded form data to replace login fields without corrupting neighboring payloads.
- Added support for auto-injecting into blank parameters (e.g., `username=&password=`).

---
*The project has been compiled and verified successfully after these changes.*
