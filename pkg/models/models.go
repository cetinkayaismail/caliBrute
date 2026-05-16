package models

import "net/http"

// Config holds all the global configuration options for the brute-force attack.
type Config struct {
	RequestFile  string
	UserList     []string // Expanded user list (from flag or file)
	PassList     []string // Expanded password list (from flag or file)
	Threads      int
	StealthMode  bool
	Proxy        string
	ProxyList    []string
	Mode         string // "pass-first" or "user-first"
	Fuzzy        int    // Bytes allowed to differ for a match
	VerboseLevel int    // 0: Normal, 1: Verbose, 2: Very Verbose
	Timeout      int    // Timeout in milliseconds
	OutputFile   string
	ResumeIndex  int    // Line to resume from
	Target       string // Explicit target host (overrides Host header)

	// Manual matchers
	MatchCode   int
	MatchString string
	MatchLength int
}

// RawRequest represents the unparsed template from Burp Suite
type RawRequest struct {
	RawContent string // The entire file content
	Host       string
	IsSSL      bool // Derived from port or explicitly set
}

// Attempt represents a single brute-force attempt combination
type Attempt struct {
	User  string
	Pass  string
	Index int // Used for resume functionality
}

// Baseline represents the response from the initial dummy requests
type Baseline struct {
	StatusCode     int
	Length         int // Length of base dummy request
	Headers        http.Header
	UserMultiplier int // How many times User is reflected
	PassMultiplier int // How many times Pass is reflected
	BaseUserLen    int
	BasePassLen    int
	BodyHash       string // SHA256 of the body
	Body           string // Truncated or full body for structural analysis
}

// Result represents the outcome of a single attempt
type Result struct {
	Index          int
	User           string
	Pass           string
	StatusCode     int
	Length         int
	ExpectedLength int
	IsSuccess      bool
	IsBlocked      bool   // Flag for rate-limiting/WAF
	Reason         string // E.g., "Status Code Changed", "Length Difference", "Redirect"
}
