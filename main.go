package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"calibrute/pkg/engine"
	"calibrute/pkg/models"
	"calibrute/pkg/parser"
)

func main() {
    fmt.Println(`
   ______      ___ ____                __       
  / ____/___ _/ (_) __ )_______  __/ /____   
 / /   / __ '/ / / __  / ___/ / / / __/ _ \  
/ /___/ /_/ / / / /_/ / /  / /_/ / /_/  __/  
\____/\__,_/_/_/_____/_/   \__,_/\__/\___/   
   v1.0 | Advanced HTTP Brute-Forcer
	`)

	// Setup flags
	reqFile := flag.String("r", "", "Path to raw HTTP request file")
	users := flag.String("u", "", "Single user or comma-separated list of users")
	userFile := flag.String("U", "", "Path to username list file")
	passes := flag.String("p", "", "Single password or comma-separated list of passwords")
	passFile := flag.String("P", "", "Path to password list file")
	threads := flag.Int("t", 5, "Number of concurrent threads")
	stealth := flag.Bool("stealth", false, "Enable stealth mode (jitter, single-thread, UA rotation, IP spoofing)")
	proxy := flag.String("proxy", "", "Single proxy URL (e.g. http://127.0.0.1:8080)")
	proxyList := flag.String("proxy-list", "", "Path to proxy list file")
	mode := flag.String("mode", "pass-first", "Iteration mode: 'pass-first' or 'user-first'")
	fuzzy := flag.Int("fuzzy", 2, "Fuzzy length threshold for smart detection")
	v := flag.Bool("v", false, "Verbose output")
	vv := flag.Bool("vv", false, "Very verbose output")
	timeout := flag.Int("timeout", 10000, "Request timeout in ms")
	resume := flag.Int("resume", 0, "Resume from specific attempt index")
	target := flag.String("target", "", "Explicit target host (e.g., 10.10.10.10:80). Overrides/Provides Host header if missing.")
	
	// Manual Matchers
	mc := flag.Int("mc", 0, "Match specific status code")
	ms := flag.String("ms", "", "Match specific string in response body")
	ml := flag.Int("ml", 0, "Match specific response length")

	flag.Parse()

	if *reqFile == "" {
		fmt.Println("Error: Request file (-r) is required.")
		flag.Usage()
		os.Exit(1)
	}

	// Build configuration
	cfg := &models.Config{
		RequestFile:  *reqFile,
		Threads:      *threads,
		StealthMode:  *stealth,
		Proxy:        *proxy,
		Mode:         *mode,
		Fuzzy:        *fuzzy,
		Timeout:      *timeout,
		ResumeIndex:  *resume,
		Target:       *target,
		MatchCode:    *mc,
		MatchString:  *ms,
		MatchLength:  *ml,
	}

	if *stealth {
		cfg.Threads = 1 // Enforce single thread in stealth mode
	}

	if *v {
		cfg.VerboseLevel = 1
	}
	if *vv {
		cfg.VerboseLevel = 2
	}

	// Load Users
	if *users != "" {
		cfg.UserList = strings.Split(*users, ",")
	} else if *userFile != "" {
		cfg.UserList = loadLines(*userFile)
	} else {
		log.Fatal("Error: No users provided. Use -u or -U")
	}

	// Load Passwords
	if *passes != "" {
		cfg.PassList = strings.Split(*passes, ",")
	} else if *passFile != "" {
		cfg.PassList = loadLines(*passFile)
	} else {
		log.Fatal("Error: No passwords provided. Use -p or -P")
	}

	// Load Proxies
	if *proxyList != "" {
		cfg.ProxyList = loadLines(*proxyList)
	}

	// Parse Template
	tpl, err := parser.ReadTemplate(cfg.RequestFile, cfg.Target)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	fmt.Printf("[*] Loaded %d users and %d passwords.\n", len(cfg.UserList), len(cfg.PassList))
	fmt.Printf("[*] Target: %s\n", tpl.Host)
	if cfg.StealthMode {
		fmt.Println("[!] Stealth mode ACTIVE: Single-threaded, Jitter enabled, IP spoofing on.")
	}

	// Start Engine
	eng := engine.NewEngine(cfg, tpl)
	err = eng.Start()
	if err != nil {
		log.Fatalf("Engine failed: %v", err)
	}
}

func loadLines(filePath string) []string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file %s: %v", filePath, err)
	}
	lines := strings.Split(string(content), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
