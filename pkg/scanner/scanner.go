package scanner

import (
	"calibrute/pkg/models"
)

// AbsInt returns the absolute value of an integer
func AbsInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// AnalyzeResult compares the current attempt's response against the baseline and configuration
func AnalyzeResult(attempt models.Attempt, statusCode int, length int, headers map[string][]string, baseline *models.Baseline, cfg *models.Config) models.Result {
	res := models.Result{
		Index:      attempt.Index,
		User:       attempt.User,
		Pass:       attempt.Pass,
		StatusCode: statusCode,
		Length:     length,
		IsSuccess:  false,
	}

	// 1. Manual Overrides Strategy
	if cfg.MatchCode != 0 || cfg.MatchString != "" || cfg.MatchLength != 0 {
		// If manual matchers are used, we ignore baseline completely
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
		// MatchString is handled by the engine reading the body directly, 
		// so if it was found, we assume engine passes a specific flag, but 
		// for now we'll handle MatchString logic in the Engine before calling Analyze.
		return res
	}

	// 2. Smart Baseline Strategy
	if baseline == nil {
		// Should not happen unless baseline failed
		return res
	}

	// a) Status Code Change
	if statusCode != baseline.StatusCode {
		// Specifically flag 3xx redirects
		if statusCode >= 300 && statusCode < 400 {
			res.IsSuccess = true
			res.Reason = "Status Code Redirect (3xx)"
			return res
		}

		// Any other significant status change (e.g. 401 -> 200)
		res.IsSuccess = true
		res.Reason = "Status Code Changed"
		return res
	}

	// b) Fuzzy Length Change using Auto-Calibrated Expected Length
	expectedLength := baseline.Length +
		(len(attempt.User)-baseline.BaseUserLen)*baseline.UserMultiplier +
		(len(attempt.Pass)-baseline.BasePassLen)*baseline.PassMultiplier

	res.ExpectedLength = expectedLength

	// If the difference between actual length and expected length is greater than fuzzy threshold
	if AbsInt(length-expectedLength) > cfg.Fuzzy {
		res.IsSuccess = true
		res.Reason = "Content Length Changed"
		return res
	}

	// c) Header Delta Change (Looking for new Set-Cookie or Location)
	if _, ok := headers["Set-Cookie"]; ok {
		if _, baselineOk := baseline.Headers["Set-Cookie"]; !baselineOk {
			res.IsSuccess = true
			res.Reason = "New Set-Cookie Header"
			return res
		}
	}
	
	if _, ok := headers["Location"]; ok {
		if _, baselineOk := baseline.Headers["Location"]; !baselineOk {
			res.IsSuccess = true
			res.Reason = "New Location Header"
			return res
		}
	}

	return res
}
