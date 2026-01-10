package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// Fingerprint represents response characteristics for comparison
type Fingerprint struct {
	StatusCode          int
	ContentLength       int
	WordCount           int
	LineCount           int
	BodyHash            string
	ContainsMatchString bool // True if the match string was found in response
}

// New creates a fingerprint from response data
func New(statusCode int, body []byte) *Fingerprint {
	return NewWithMatchString(statusCode, body, "")
}

// NewWithMatchString creates a fingerprint and checks for match string presence
func NewWithMatchString(statusCode int, body []byte, matchString string) *Fingerprint {
	bodyStr := string(body)

	hash := md5.Sum(body)

	containsMatch := false
	if matchString != "" {
		containsMatch = strings.Contains(bodyStr, matchString)
	}

	return &Fingerprint{
		StatusCode:          statusCode,
		ContentLength:       len(body),
		WordCount:           countWords(bodyStr),
		LineCount:           countLines(bodyStr),
		BodyHash:            hex.EncodeToString(hash[:]),
		ContainsMatchString: containsMatch,
	}
}

// Equals checks if two fingerprints are effectively the same
func (f *Fingerprint) Equals(other *Fingerprint) bool {
	if f == nil || other == nil {
		return false
	}

	// If match string was used, it takes priority
	if f.ContainsMatchString != other.ContainsMatchString {
		return false
	}

	// Primary check: status code
	if f.StatusCode != other.StatusCode {
		return false
	}

	// Secondary check: word count (exact match)
	if f.WordCount == other.WordCount {
		return true
	}

	// Tertiary check: content length within tolerance (5%)
	tolerance := float64(f.ContentLength) * 0.05
	diff := float64(f.ContentLength - other.ContentLength)
	if diff < 0 {
		diff = -diff
	}

	return diff <= tolerance
}

// IsSimilar is a more relaxed comparison
func (f *Fingerprint) IsSimilar(other *Fingerprint) bool {
	if f == nil || other == nil {
		return false
	}

	// Only status code match required
	return f.StatusCode == other.StatusCode
}

// Diff returns a description of differences between fingerprints
func (f *Fingerprint) Diff(other *Fingerprint) string {
	if f == nil || other == nil {
		return "nil fingerprint"
	}

	var diffs []string

	if f.StatusCode != other.StatusCode {
		diffs = append(diffs, "status code")
	}
	if f.WordCount != other.WordCount {
		diffs = append(diffs, "word count")
	}
	if f.ContentLength != other.ContentLength {
		diffs = append(diffs, "content length")
	}
	if f.BodyHash != other.BodyHash {
		diffs = append(diffs, "body content")
	}

	if len(diffs) == 0 {
		return "identical"
	}

	return strings.Join(diffs, ", ")
}

// countWords counts the number of words in a string
func countWords(s string) int {
	words := strings.Fields(s)
	return len(words)
}

// countLines counts the number of lines in a string
func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// MatchType represents how a response matches a reference
type MatchType int

const (
	MatchUnknown MatchType = iota
	MatchTrue
	MatchFalse
	MatchError
)

func (m MatchType) String() string {
	switch m {
	case MatchTrue:
		return "TRUE"
	case MatchFalse:
		return "FALSE"
	case MatchError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
