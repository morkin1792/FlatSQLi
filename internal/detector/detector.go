package detector

import (
	"fmt"
	"strings"

	"github.com/morkin1792/flatsqli/internal/calibrator"
	"github.com/morkin1792/flatsqli/internal/fingerprint"
	"github.com/morkin1792/flatsqli/internal/payloads"
	"github.com/morkin1792/flatsqli/internal/requester"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// DatabaseType represents the detected database type
type DatabaseType int

const (
	Unknown DatabaseType = iota
	MySQL
	MSSQL
	PostgreSQL
	Oracle
)

// String returns the string representation of the database type
func (d DatabaseType) String() string {
	switch d {
	case MySQL:
		return "mysql"
	case MSSQL:
		return "mssql"
	case PostgreSQL:
		return "postgres"
	case Oracle:
		return "oracle"
	default:
		return "unknown"
	}
}

// ParseDatabaseType parses a string to DatabaseType
func ParseDatabaseType(s string) DatabaseType {
	switch strings.ToLower(s) {
	case "mysql", "mariadb":
		return MySQL
	case "mssql", "sqlserver", "sql server":
		return MSSQL
	case "postgres", "postgresql", "pgsql":
		return PostgreSQL
	case "oracle", "ora":
		return Oracle
	default:
		return Unknown
	}
}

// ToPayloadType converts detector.DatabaseType to payloads.DatabaseType
func (d DatabaseType) ToPayloadType() payloads.DatabaseType {
	switch d {
	case MySQL:
		return payloads.MySQL
	case MSSQL:
		return payloads.MSSQL
	case PostgreSQL:
		return payloads.PostgreSQL
	case Oracle:
		return payloads.Oracle
	default:
		return payloads.Unknown
	}
}

// Detector handles database type detection
type Detector struct {
	requester   *requester.Requester
	calibration *calibrator.CalibrationResult
	verbose     bool
}

// New creates a new Detector
func New(req *requester.Requester, cal *calibrator.CalibrationResult, verbose bool) *Detector {
	return &Detector{
		requester:   req,
		calibration: cal,
		verbose:     verbose,
	}
}

// Detect attempts to detect the database type and extract version
func (d *Detector) Detect() (DatabaseType, string, error) {
	ui.Verbose(d.verbose, "Starting database detection...")

	detectionPayloads := payloads.GetAllVersionDetectionPayloads()

	// Try each detection payload
	for _, dp := range detectionPayloads {
		ui.Verbose(d.verbose, "Testing %s using %s", dp.Name, dp.Description)

		// First, send the FALSE query to see if we get a non-error response
		falseResp, err := d.requester.Send(dp.FalseQuery)
		if err != nil {
			ui.Verbose(d.verbose, "Request failed: %v", err)
			continue
		}

		// Check if this looks like an error (syntax error = not this DB)
		falseMatch := d.calibration.GetMatchType(falseResp.Fingerprint)

		// If the FALSE query returns an error, this isn't the right database
		if falseMatch == fingerprint.MatchError {
			ui.Verbose(d.verbose, "FALSE query returned error - not %s", dp.Name)
			continue
		}

		// Now send the TRUE query
		trueResp, err := d.requester.Send(dp.TrueQuery)
		if err != nil {
			ui.Verbose(d.verbose, "Request failed: %v", err)
			continue
		}

		trueMatch := d.calibration.GetMatchType(trueResp.Fingerprint)

		// For a valid detection:
		// - TRUE query should return TRUE fingerprint
		// - FALSE query should return FALSE fingerprint
		if trueMatch == fingerprint.MatchTrue && falseMatch == fingerprint.MatchFalse {
			ui.Verbose(d.verbose, "Database detected as %s!", dp.Name)

			// Now extract the version
			dbType := d.convertPayloadDB(dp.Database)
			version, err := d.extractVersion(dbType)
			if err != nil {
				ui.Verbose(d.verbose, "Warning: Could not extract version: %v", err)
				return dbType, "", nil
			}

			return dbType, version, nil
		}

		ui.Verbose(d.verbose, "TRUE=%s, FALSE=%s - not a match", trueMatch, falseMatch)
	}

	return Unknown, "", fmt.Errorf("could not detect database type")
}

// extractVersion extracts the version string from the database
func (d *Detector) extractVersion(dbType DatabaseType) (string, error) {
	payloadGen := payloads.GetPayloadsForDatabase(dbType.ToPayloadType())
	if payloadGen == nil {
		return "", fmt.Errorf("no payload generator for database type")
	}

	queries := payloadGen.GetVersionQueries()
	if len(queries) == 0 {
		return "", fmt.Errorf("no version queries available")
	}

	var bestVersion string

	// Try each version query
	for _, query := range queries {
		ui.Verbose(d.verbose, "Extracting version using: %s", query)

		version, err := d.extractString(query, payloadGen)

		// Keep the longest version found, even if there was an error
		if len(version) > len(bestVersion) {
			bestVersion = version
		}

		if err != nil {
			ui.Verbose(d.verbose, "Extraction failed/incomplete: %v", err)
			continue
		}

		// If we got a result without error, it's likely the best one
		if version != "" {
			return version, nil
		}
	}

	if bestVersion != "" {
		ui.Verbose(d.verbose, "Returning best partial version found")
		return bestVersion, nil
	}

	return "", fmt.Errorf("could not extract version")
}

// extractString extracts a string value using binary search
func (d *Detector) extractString(query string, payloadGen payloads.DatabasePayloads) (string, error) {
	// First, find the length
	length, err := d.findLength(query, payloadGen)
	if err != nil {
		return "", err
	}

	if length == 0 {
		return "", nil
	}

	// Cap length at 64 for version detection (reasonable max)
	maxLen := 64
	if length > maxLen {
		ui.Verbose(d.verbose, "String length %d exceeds max %d, capping", length, maxLen)
		length = maxLen
	}

	ui.Verbose(d.verbose, "String length: %d", length)

	// Extract each character using prefix-based optimization
	result := make([]byte, 0, length)
	for i := 1; i <= length; i++ {
		char, err := d.findCharWithPrefixes(query, i, string(result), payloadGen)
		if err != nil {
			ui.ProgressDone()
			// Return what we have so far, WITH the error
			if len(result) > 0 {
				return string(result), err
			}
			return "", err
		}
		result = append(result, char)
		// Show live progress with extracted chars and position
		ui.Progress("Extracting: %s [%d/%d]", string(result), i, length)
	}
	ui.ProgressDone()

	return string(result), nil
}

// findLength finds the length of a query result using binary search
func (d *Detector) findLength(query string, payloadGen payloads.DatabasePayloads) (int, error) {
	low := 0
	high := 256 // Max reasonable length for version string

	for low < high {
		mid := (low + high + 1) / 2
		payload := payloadGen.GetLengthPayload(query, mid-1) // LENGTH > mid-1

		resp, err := d.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if d.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return low, nil
}

// findChar finds a character at a position using binary search
func (d *Detector) findChar(query string, pos int, payloadGen payloads.DatabasePayloads) (byte, error) {
	low := 32   // Space (printable ASCII start)
	high := 126 // ~ (printable ASCII end)

	for low < high {
		mid := (low + high + 1) / 2
		payload := payloadGen.GetCharPayload(query, pos, mid-1) // ASCII > mid-1

		resp, err := d.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if d.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return byte(low), nil
}

// findCharWithPrefixes tries to find a character using known version prefixes first,
// then falls back to binary search if no prefix matches.
func (d *Detector) findCharWithPrefixes(query string, pos int, currentResult string, payloadGen payloads.DatabasePayloads) (byte, error) {
	// Get candidate prefixes that match what we have so far
	prefixes := payloads.GetVersionPrefixes(payloadGen.GetType())
	var candidates []string
	for _, p := range prefixes {
		if len(p) >= pos && strings.HasPrefix(p, currentResult) {
			candidates = append(candidates, p)
		}
	}

	// If we have candidates, try equality check for each unique char at this position
	if len(candidates) > 0 {
		uniqueChars := d.getUniqueCharsAtPosition(candidates, pos)
		for _, c := range uniqueChars {
			// Try equality check: ASCII(char) = c
			payload := payloadGen.GetEqualityPayload(query, pos, int(c))
			resp, err := d.requester.Send(payload)
			if err != nil {
				// On error, fall back to binary search
				return d.findChar(query, pos, payloadGen)
			}
			if d.calibration.IsTrue(resp.Fingerprint) {
				return c, nil
			}
		}
	}

	// No prefix match - fall back to binary search
	return d.findChar(query, pos, payloadGen)
}

// getUniqueCharsAtPosition returns unique characters at the given position (1-indexed)
// from a list of prefix strings.
func (d *Detector) getUniqueCharsAtPosition(prefixes []string, pos int) []byte {
	seen := make(map[byte]bool)
	var result []byte
	for _, p := range prefixes {
		if pos <= len(p) {
			c := p[pos-1] // pos is 1-indexed
			if !seen[c] {
				seen[c] = true
				result = append(result, c)
			}
		}
	}
	return result
}

// convertPayloadDB converts payloads.DatabaseType to detector.DatabaseType
func (d *Detector) convertPayloadDB(pdb payloads.DatabaseType) DatabaseType {
	switch pdb {
	case payloads.MySQL:
		return MySQL
	case payloads.MSSQL:
		return MSSQL
	case payloads.PostgreSQL:
		return PostgreSQL
	case payloads.Oracle:
		return Oracle
	default:
		return Unknown
	}
}
