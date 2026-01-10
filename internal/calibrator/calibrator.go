package calibrator

import (
	"fmt"

	"github.com/morkin1792/flatsqli/internal/fingerprint"
	"github.com/morkin1792/flatsqli/internal/requester"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// CalibrationResult holds the fingerprints for TRUE, FALSE, and ERROR conditions
type CalibrationResult struct {
	TrueFingerprint  *fingerprint.Fingerprint
	FalseFingerprint *fingerprint.Fingerprint
	ErrorFingerprint *fingerprint.Fingerprint
	CanDifferentiate bool
	ErrorMatchesTrue bool // If true, ERROR response looks like TRUE
}

// Calibration payloads - pure boolean conditions for CASE WHEN context
// The marker is placed inside a condition like: CASE WHEN (<PAYLOAD>) THEN 'a' ELSE 'b' END
// So we just need to send boolean conditions directly
var (
	// TRUE conditions - should always evaluate to true
	truePayloads = []string{
		"3=4-1",
		"'q'='q'",
		"1<4",
		"4>1",
	}

	// FALSE conditions - should always evaluate to false
	falsePayloads = []string{
		"1=4",
		"'q'='b'",
		"1>4",
		"4<1",
	}

	// ERROR conditions - intentional syntax errors
	errorPayloads = []string{
		"1='",
		"(1=3",
		"1=3)",
		"SELECT",
	}
)

// Calibrator handles the calibration process
type Calibrator struct {
	requester *requester.Requester
	verbose   bool
}

// New creates a new Calibrator
func New(req *requester.Requester, verbose bool) *Calibrator {
	return &Calibrator{
		requester: req,
		verbose:   verbose,
	}
}

// Calibrate performs the calibration to detect TRUE, FALSE, and ERROR fingerprints
func (c *Calibrator) Calibrate() (*CalibrationResult, error) {
	result := &CalibrationResult{}

	// Warmup request to flush stale connections/DNS (especially after VPN changes)
	// This request is discarded - it ensures fresh TCP connection and DNS resolution
	ui.Verbose(c.verbose, "Sending warmup request...")
	_, _ = c.requester.Send("3=3") // Ignore result

	// Try to find working TRUE/FALSE pair
	ui.Verbose(c.verbose, "Testing TRUE conditions...")
	trueResp, truePayload, err := c.findWorkingPayload(truePayloads)
	if err != nil {
		return nil, fmt.Errorf("failed to get TRUE response: %w", err)
	}
	result.TrueFingerprint = trueResp.Fingerprint
	ui.Verbose(c.verbose, "TRUE payload: %s", truePayload)

	ui.Verbose(c.verbose, "Testing FALSE conditions...")
	falseResp, falsePayload, err := c.findWorkingPayload(falsePayloads)
	if err != nil {
		return nil, fmt.Errorf("failed to get FALSE response: %w", err)
	}
	result.FalseFingerprint = falseResp.Fingerprint
	ui.Verbose(c.verbose, "FALSE payload: %s", falsePayload)

	ui.Verbose(c.verbose, "Testing ERROR conditions...")
	errorResp, errorPayload, err := c.findWorkingPayload(errorPayloads)
	if err != nil {
		// Error payloads might fail, that's okay
		ui.Verbose(c.verbose, "Could not get ERROR response, using FALSE as fallback")
		result.ErrorFingerprint = result.FalseFingerprint
	} else {
		result.ErrorFingerprint = errorResp.Fingerprint
		ui.Verbose(c.verbose, "ERROR payload: %s", errorPayload)
	}

	// Check if we can differentiate TRUE from FALSE
	result.CanDifferentiate = !result.TrueFingerprint.Equals(result.FalseFingerprint)

	// Determine if ERROR looks like TRUE or FALSE
	if result.ErrorFingerprint != nil {
		result.ErrorMatchesTrue = result.ErrorFingerprint.Equals(result.TrueFingerprint)
	}

	return result, nil
}

// findWorkingPayload tries payloads until one works (returns a response)
func (c *Calibrator) findWorkingPayload(payloads []string) (*requester.Response, string, error) {
	var lastErr error

	for _, payload := range payloads {
		resp, err := c.requester.Send(payload)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, payload, nil
	}

	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", fmt.Errorf("no payload succeeded")
}

// IsTrue checks if a fingerprint matches the TRUE condition
func (r *CalibrationResult) IsTrue(fp *fingerprint.Fingerprint) bool {
	return r.TrueFingerprint.Equals(fp)
}

// IsFalse checks if a fingerprint matches the FALSE condition
func (r *CalibrationResult) IsFalse(fp *fingerprint.Fingerprint) bool {
	return r.FalseFingerprint.Equals(fp)
}

// IsError checks if a fingerprint matches the ERROR condition
func (r *CalibrationResult) IsError(fp *fingerprint.Fingerprint) bool {
	return r.ErrorFingerprint.Equals(fp)
}

// GetMatchType determines what type of match a fingerprint is
func (r *CalibrationResult) GetMatchType(fp *fingerprint.Fingerprint) fingerprint.MatchType {
	if r.IsTrue(fp) {
		return fingerprint.MatchTrue
	}
	if r.IsFalse(fp) {
		return fingerprint.MatchFalse
	}
	if r.IsError(fp) {
		return fingerprint.MatchError
	}
	return fingerprint.MatchUnknown
}
