package engine

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"

	"calibrute/pkg/models"
	"calibrute/pkg/parser"
	"calibrute/pkg/scanner"
	"calibrute/pkg/utils"
)

type Engine struct {
	Config   *models.Config
	Template  *models.RawRequest
	Baselines map[string]*models.Baseline
}

func NewEngine(cfg *models.Config, tpl *models.RawRequest) *Engine {
	return &Engine{
		Config:    cfg,
		Template:  tpl,
		Baselines: make(map[string]*models.Baseline),
	}
}

// Start kicks off the brute force process
func (e *Engine) Start() error {
	// 1. Generate Baseline if manual overrides are not completely satisfying
	if e.Config.MatchCode == 0 && e.Config.MatchLength == 0 && e.Config.MatchString == "" {
		if e.Config.VerboseLevel > 0 {
			log.Println("[*] Generating baselines...")
		}
		err := e.generateBaselines()
		if err != nil {
			return fmt.Errorf("failed to generate baselines: %v", err)
		}
		if e.Config.VerboseLevel > 0 {
			log.Println("[+] Baselines established.")
		}
	}

	// 2. Generate Work Items
	attempts := make(chan models.Attempt, e.Config.Threads*2)
	results := make(chan models.Result, e.Config.Threads*2)

	var wg sync.WaitGroup
	stopChan := make(chan struct{})
	var stopOnce sync.Once

	// 3. Start Workers
	for i := 0; i < e.Config.Threads; i++ {
		wg.Add(1)
		go e.worker(attempts, results, &wg, stopChan)
	}

	// 4. Start Result Processor
	done := make(chan bool)
	var successCount int32
	var successes []models.Result

	go func() {
		for res := range results {
			if res.IsSuccess {
				atomic.AddInt32(&successCount, 1)
				successes = append(successes, res)
				fmt.Printf("\n[SUCCESS] [Attempt: %d] User: %s | Pass: %s | Status: %d | Len: %d | Reason: %s\n", res.Index, res.User, res.Pass, res.StatusCode, res.Length, res.Reason)
				stopOnce.Do(func() {
					close(stopChan) // Signal all workers and feeder to stop
				})
			} else if e.Config.VerboseLevel >= 1 {
				fmt.Printf("[FAIL] [Attempt: %d] User: %s | Pass: %s | Status: %d | Len: %d\n", res.Index, res.User, res.Pass, res.StatusCode, res.Length)
			}
		}
		done <- true
	}()

	// 5. Feed work
	e.feedAttempts(attempts, stopChan)
	close(attempts)

	// Wait for workers to finish
	wg.Wait()
	close(results)

	<-done

	fmt.Printf("\n[*] Finished. Total successes: %d\n", atomic.LoadInt32(&successCount))
	
	// Print successes in Bright Green at the very bottom
	if len(successes) > 0 {
		green := "\033[1;32m"
		reset := "\033[0m"
		fmt.Printf("\n%s========================================================================%s\n", green, reset)
		fmt.Printf("%s                  [+] VALID CREDENTIALS FOUND [+]                       %s\n", green, reset)
		fmt.Printf("%s========================================================================%s\n", green, reset)
		for _, s := range successes {
			fmt.Printf("%s  [✓] Username : %-15s | Password : %-15s %s\n", green, s.User, s.Pass, reset)
		}
		fmt.Printf("%s========================================================================%s\n\n", green, reset)
	}

	return nil
}

func (e *Engine) generateBaselines() error {
	client, err := utils.BuildClient(e.Config)
	if err != nil {
		return err
	}

	sendReq := func(u, p string) (int, int, http.Header, error) {
		req, err := parser.BuildRequest(e.Template, u, p)
		if err != nil {
			return 0, 0, nil, err
		}
		if e.Config.StealthMode {
			utils.ApplyStealthHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0, nil, err
		}
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, len(bodyBytes), resp.Header, nil
	}

	for _, user := range e.Config.UserList {
		basePass := "calibrutedummypass"
		s1, l1, h1, err := sendReq(user, basePass)
		if err != nil {
			return err
		}

		passX := "calibrutedummypassXX"
		_, l2, _, err := sendReq(user, passX)
		if err != nil {
			return err
		}

		passMultiplier := (l2 - l1) / (len(passX) - len(basePass))
		if passMultiplier < 0 {
			passMultiplier = 0
		}

		e.Baselines[user] = &models.Baseline{
			StatusCode:     s1,
			Length:         l1,
			Headers:        h1,
			BasePassLen:    len(basePass),
			PassMultiplier: passMultiplier,
		}

		if e.Config.VerboseLevel > 0 {
			log.Printf("[+] Baseline for user '%s': Len %d, Pass reflected %dx", user, l1, passMultiplier)
		}
	}

	return nil
}

func (e *Engine) worker(attempts <-chan models.Attempt, results chan<- models.Result, wg *sync.WaitGroup, stopChan <-chan struct{}) {
	defer wg.Done()

	// Each worker needs its own client to avoid race conditions on proxy rotation, though we can build per request if stealth
	
	for attempt := range attempts {
		select {
		case <-stopChan:
			return // Exit immediately if a success was found
		default:
		}

		if attempt.Index < e.Config.ResumeIndex {
			continue // Skip until resume index
		}

		utils.JitterDelay(e.Config.StealthMode)

		req, err := parser.BuildRequest(e.Template, attempt.User, attempt.Pass)
		if err != nil {
			if e.Config.VerboseLevel > 0 {
				log.Printf("[-] Failed to build request for %s:%s -> %v\n", attempt.User, attempt.Pass, err)
			}
			continue
		}

		if e.Config.StealthMode {
			utils.ApplyStealthHeaders(req)
		}

		if e.Config.VerboseLevel >= 2 {
			dump, _ := httputil.DumpRequestOut(req, true)
			log.Printf("\n--- OUTGOING REQUEST ---\n%s\n------------------------\n", string(dump))
		}

		// Build client per request to handle proxy rotation properly
		client, _ := utils.BuildClient(e.Config)
		
		resp, err := client.Do(req)
		if err != nil {
			if e.Config.VerboseLevel > 0 {
				log.Printf("[-] Request failed: %v\n", err)
			}
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(bodyBytes)

		// Pre-analysis MatchString check
		if e.Config.MatchString != "" && strings.Contains(bodyStr, e.Config.MatchString) {
			res := models.Result{
				Index:      attempt.Index,
				User:       attempt.User,
				Pass:       attempt.Pass,
				StatusCode: resp.StatusCode,
				Length:     len(bodyBytes),
				IsSuccess:  true,
				Reason:     "Matched String",
			}
			results <- res
			continue
		}

		// Analyze
		var bl *models.Baseline
		if e.Baselines != nil {
			bl = e.Baselines[attempt.User]
		}
		res := scanner.AnalyzeResult(attempt, resp.StatusCode, len(bodyBytes), resp.Header, bl, e.Config)
		results <- res
	}
}

func (e *Engine) feedAttempts(attempts chan<- models.Attempt, stopChan <-chan struct{}) {
	index := 0
	if e.Config.Mode == "user-first" {
		for _, user := range e.Config.UserList {
			for _, pass := range e.Config.PassList {
				select {
				case <-stopChan:
					return
				case attempts <- models.Attempt{User: user, Pass: pass, Index: index}:
					index++
				}
			}
		}
	} else {
		// Default: pass-first (reduces account lockouts)
		for _, pass := range e.Config.PassList {
			for _, user := range e.Config.UserList {
				select {
				case <-stopChan:
					return
				case attempts <- models.Attempt{User: user, Pass: pass, Index: index}:
					index++
				}
			}
		}
	}
}
