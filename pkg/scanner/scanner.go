package scanner

import (
	"calibrute/pkg/models"
	"calibrute/pkg/utils"
	"strings"
)

// AbsInt returns the absolute value of an integer
func AbsInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

var successKeywords = []string{"dashboard", "welcome", "logout", "settings", "profile", "admin", "success", "my account", "authenticated"}
var failureKeywords = []string{"invalid", "incorrect", "failed", "error", "denied", "wrong", "unauthorized", "retry"}
var blockKeywords = []string{"rate limit", "too many requests", "blocked", "waf", "captcha", "security check", "ip banned", "access denied"}

// AnalyzeResult compares the current attempt's response against the baseline and configuration
func AnalyzeResult(attempt models.Attempt, statusCode int, length int, body string, headers map[string][]string, baseline *models.Baseline, cfg *models.Config) models.Result {
	res := models.Result{
		Index:      attempt.Index,
		User:       attempt.User,
		Pass:       attempt.Pass,
		StatusCode: statusCode,
		Length:     length,
		IsSuccess:  false,
	}

	bodyLower := strings.ToLower(body)

	// 0. Rate Limit / Block Detection (Highest Priority)
	if statusCode == 429 {
		res.IsBlocked = true
		res.Reason = "Rate Limited (429)"
		return res
	}

	for _, blockWord := range blockKeywords {
		if strings.Contains(bodyLower, blockWord) {
			res.IsBlocked = true
			res.Reason = "Block Detected: " + blockWord
			return res
		}
	}

	// 1. Manual Overrides Strategy
	if cfg.MatchCode != 0 || cfg.MatchString != "" || cfg.MatchLength != 0 {
		if cfg.MatchCode != 0 && statusCode == cfg.MatchCode {
			res.IsSuccess = true
			res.Reason = "Matched Status Code"
			return res
		}
		if cfg.MatchLength != 0 && length == cfg.MatchLength {
			res.IsSuccess = true
			res.Reason = "Matched Content Length"
			return res
		}
		// MatchString is handled by engine, but we could add it here too
		return res
	}

	// 2. Smart Baseline Strategy
	if baseline == nil {
		return res
	}

	// a) Exact Match Check (Hash)
	currentHash := utils.GetSHA256(body)
	if currentHash == baseline.BodyHash {
		// Content is identical to failure baseline
		return res
	}

	// b) Heuristic Scoring
	score := 0

	// Status Code Change
	if statusCode != baseline.StatusCode {
		if statusCode >= 200 && statusCode < 300 {
			score += 50
		}
		if statusCode >= 300 && statusCode < 400 {
			// Redirect Analysis
			loc := ""
			if val, ok := headers["Location"]; ok && len(val) > 0 {
				loc = strings.ToLower(val[0])
			}

			isFailureRedirect := false
			failRedirectWords := []string{"login", "auth", "error", "fail", "wrong"}
			for _, w := range failRedirectWords {
				if strings.Contains(loc, w) {
					isFailureRedirect = true
					break
				}
			}

			if isFailureRedirect {
				score -= 30
			} else {
				score += 60 // Likely a dashboard redirect
				res.Reason = "Redirect to " + loc
			}
		}
	}

	// Keyword Analysis
	for _, kw := range successKeywords {
		if strings.Contains(bodyLower, kw) {
			score += 40
			res.Reason = "Found Success Keyword: " + kw
		}
	}

	for _, kw := range failureKeywords {
		if strings.Contains(bodyLower, kw) {
			score -= 40
		}
	}

	// Length Analysis
	expectedLength := baseline.Length +
		(len(attempt.User)-baseline.BaseUserLen)*baseline.UserMultiplier +
		(len(attempt.Pass)-baseline.BasePassLen)*baseline.PassMultiplier

	res.ExpectedLength = expectedLength
	lenDiff := AbsInt(length - expectedLength)
	if lenDiff > cfg.Fuzzy {
		score += 30
	}

	// Header Analysis
	if _, ok := headers["Set-Cookie"]; ok {
		if _, baselineOk := baseline.Headers["Set-Cookie"]; !baselineOk {
			score += 20
		}
	}

	// Final Decision
	if score >= 50 {
		res.IsSuccess = true
		if res.Reason == "" {
			res.Reason = "Heuristic Match"
		}
	}

	return res
}
