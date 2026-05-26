package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"calibrute/pkg/models"
)

// ReadTemplate reads the raw Burp Suite request file and extracts necessary info.
func ReadTemplate(filePath string, overrideHost string) (*models.RawRequest, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read request file: %v", err)
	}

	rawStr := string(content)

	// Ensure standard HTTP line endings (\r\n) for http.ReadRequest to work correctly
	rawStr = strings.ReplaceAll(rawStr, "\r\n", "\n")
	rawStr = strings.ReplaceAll(rawStr, "\n", "\r\n")

	// Automatically inject placeholders if they are not present
	rawStr = autoInjectPlaceholders(rawStr)

	// Extract Host header (using multiline regex to handle any line endings safely)
	hostRegex := regexp.MustCompile(`(?im)^Host:\s*([^\s\r\n]+)`)
	matches := hostRegex.FindStringSubmatch(rawStr)
	
	var host string
	if len(matches) > 1 {
		host = strings.TrimSpace(matches[1])
	}

	if host == "" {
		if overrideHost != "" {
			host = overrideHost
		} else {
			return nil, fmt.Errorf("could not find 'Host:' header in the raw request. Use --target to specify it manually")
		}
	} else if overrideHost != "" {
		host = overrideHost
	}

	// Guess SSL based on port
	isSSL := false
	if strings.HasSuffix(host, ":443") || strings.HasSuffix(host, ":8443") {
		isSSL = true
	}

	return &models.RawRequest{
		RawContent: rawStr,
		Host:       host,
		IsSSL:      isSSL,
	}, nil
}

// autoInjectPlaceholders tries to automatically find username and password fields in form data or JSON
// and replaces their values with ^USER^ and ^PASS^ placeholders.
func autoInjectPlaceholders(raw string) string {
	// If the user already manually placed the markers, respect them and don't auto-inject
	if strings.Contains(raw, "^USER^") || strings.Contains(raw, "^PASS^") {
		return raw
	}

	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers := parts[0]
	var body string
	if len(parts) > 1 {
		body = parts[1]
	}

	if body == "" {
		return raw
	}

	// Extract Content-Type header to see if it is JSON
	contentType := ""
	ctRegex := regexp.MustCompile(`(?im)^Content-Type:\s*([^\s\r\n;]+)`)
	ctMatches := ctRegex.FindStringSubmatch(headers)
	if len(ctMatches) > 1 {
		contentType = strings.ToLower(ctMatches[1])
	}

	if strings.Contains(contentType, "json") {
		// 1. JSON Heuristics (e.g. {"username": "admin", "password": "1"})
		// Match the keys and replace their values securely
		userJsonRe := regexp.MustCompile(`(?i)"(user|username|log|email|account|usr)"\s*:\s*"[^"]*"`)
		body = userJsonRe.ReplaceAllString(body, `"${1}":"^USER^"`)

		passJsonRe := regexp.MustCompile(`(?i)"(pass|password|pwd|psw)"\s*:\s*"[^"]*"`)
		body = passJsonRe.ReplaceAllString(body, `"${1}":"^PASS^"`)
	} else {
		// 2. Form Data / URL Encoded Heuristics (e.g. log=admin&pwd=1)
		// We use parameter boundaries to match correctly and safely support empty/null inputs (e.g., username=&password=)
		userFormRe := regexp.MustCompile(`(?i)(^|&)(user|username|log|email|account|usr)=[^&\s]*`)
		body = userFormRe.ReplaceAllString(body, "${1}${2}=^USER^")

		passFormRe := regexp.MustCompile(`(?i)(^|&)(pass|password|pwd|psw)=[^&\s]*`)
		body = passFormRe.ReplaceAllString(body, "${1}${2}=^PASS^")
	}

	if len(parts) > 1 {
		return headers + "\r\n\r\n" + body
	}
	return headers
}

// BuildRequest creates a ready-to-execute *http.Request with the placeholders replaced.
func BuildRequest(tpl *models.RawRequest, user, pass string) (*http.Request, error) {
	// 1. Replace placeholders
	payload := tpl.RawContent
	payload = strings.ReplaceAll(payload, "^USER^", user)
	payload = strings.ReplaceAll(payload, "^PASS^", pass)

	// Calculate the correct Content-Length based on the new body
	parts := strings.SplitN(payload, "\r\n\r\n", 2)
	bodyLength := 0
	if len(parts) == 2 {
		bodyLength = len(parts[1])
	}

	clRegex := regexp.MustCompile(`(?im)^Content-Length:\s*\d+`)
	if clRegex.MatchString(parts[0]) {
		// Replace existing Content-Length
		parts[0] = clRegex.ReplaceAllString(parts[0], fmt.Sprintf("Content-Length: %d", bodyLength))
		if len(parts) == 2 {
			payload = parts[0] + "\r\n\r\n" + parts[1]
		} else {
			payload = parts[0] + "\r\n\r\n"
		}
	} else if bodyLength > 0 {
		// Add Content-Length if it didn't exist
		parts[0] += fmt.Sprintf("\r\nContent-Length: %d", bodyLength)
		payload = parts[0] + "\r\n\r\n" + parts[1]
	}

	// 2. Parse into http.Request
	reader := bufio.NewReader(strings.NewReader(payload))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP request: %v", err)
	}

	// 3. Fix client request requirements
	// Client requests must not have RequestURI set
	req.RequestURI = ""

	// Set URL Scheme and Host
	scheme := "http"
	if tpl.IsSSL {
		scheme = "https"
	}
	req.URL.Scheme = scheme
	req.URL.Host = tpl.Host // Force use of tpl.Host (which includes --target overrides)
	req.Host = tpl.Host     // Force Host header to match

	// 4. Handle body correctly for multiple reads if necessary (though we create a new req every time)
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %v", err)
		}
		// Calculate precise new Content-Length after placeholder replacement
		req.ContentLength = int64(len(bodyBytes))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
		
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return req, nil
}
