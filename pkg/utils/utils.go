package utils

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"calibrute/pkg/models"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
}

// GetRandomUserAgent returns a random modern User-Agent string
func GetRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// GenerateSpoofedIP generates a random IP address string for X-Forwarded-For
func GenerateSpoofedIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(256),
	)
}

// BuildClient creates an HTTP client based on the configuration
func BuildClient(cfg *models.Config) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // Ignore self-signed certs for testing
		DisableKeepAlives: cfg.StealthMode,                       // If stealth, close connections
	}

	// Handle Proxy & Dynamic Proxy Rotation
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else if len(cfg.ProxyList) > 0 {
		// Dynamically rotate proxy for each request
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			p := cfg.ProxyList[rand.Intn(len(cfg.ProxyList))]
			proxyURL, err := url.Parse(p)
			if err != nil {
				return nil, err
			}
			return proxyURL, nil
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Do not follow redirects, we want to catch 302s
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

// ApplyStealthHeaders modifies the request in-place for stealth mode
func ApplyStealthHeaders(req *http.Request) {
	req.Header.Set("User-Agent", GetRandomUserAgent())
	
	ip := GenerateSpoofedIP()
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Client-IP", ip)
	
	req.Header.Set("Connection", "close")
}

// JitterDelay sleeps for a random duration between 1-5 seconds if stealth is on
func JitterDelay(stealth bool) {
	if !stealth {
		return
	}
	// Sleep between 1000ms and 5000ms
	delay := rand.Intn(4000) + 1000
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// GetSHA256 returns the SHA256 hash of a string
func GetSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
