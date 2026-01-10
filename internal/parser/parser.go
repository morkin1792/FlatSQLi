package parser

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Supported markers for payload injection
var markers = []string{"<PAYLOAD>", "<FUZZ>", "<INJECT>"}

// ParsedRequest represents a parsed HTTP request
type ParsedRequest struct {
	Method         string
	Scheme         string
	Host           string
	Path           string
	Headers        map[string]string
	Body           string
	RawRequest     string
	MarkerPosition int
	MarkerType     string
}

// ParseRequestFile reads and parses an HTTP request from a file
func ParseRequestFile(filepath string) (*ParsedRequest, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParseRequest(string(content))
}

// ParseRequest parses a raw HTTP request string
func ParseRequest(raw string) (*ParsedRequest, error) {
	// Normalize line endings
	raw = strings.ReplaceAll(raw, "\r\n", "\n")

	req := &ParsedRequest{
		Headers:        make(map[string]string),
		RawRequest:     raw,
		MarkerPosition: -1,
		Scheme:         "https", // Default to HTTPS
	}

	// Find marker
	for _, marker := range markers {
		pos := strings.Index(raw, marker)
		if pos != -1 {
			req.MarkerPosition = pos
			req.MarkerType = marker
			break
		}
	}

	// Split into lines
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}

	// Parse request line (e.g., "GET /path HTTP/1.1")
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	req.Method = parts[0]
	req.Path = parts[1]

	// Parse headers
	headerSection := true
	bodyLines := []string{}

	for i := 1; i < len(lines); i++ {
		line := lines[i]

		// Empty line separates headers from body
		if strings.TrimSpace(line) == "" {
			headerSection = false
			continue
		}

		if headerSection {
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				key := strings.TrimSpace(line[:colonIdx])
				value := strings.TrimSpace(line[colonIdx+1:])
				req.Headers[key] = value

				// Extract host
				if strings.ToLower(key) == "host" {
					req.Host = value
				}
			}
		} else {
			bodyLines = append(bodyLines, line)
		}
	}

	req.Body = strings.Join(bodyLines, "\n")

	// Try to determine scheme from URL or default
	if strings.HasPrefix(req.Path, "http://") {
		req.Scheme = "http"
		parsedURL, _ := url.Parse(req.Path)
		if parsedURL != nil {
			req.Host = parsedURL.Host
			req.Path = parsedURL.RequestURI()
		}
	} else if strings.HasPrefix(req.Path, "https://") {
		req.Scheme = "https"
		parsedURL, _ := url.Parse(req.Path)
		if parsedURL != nil {
			req.Host = parsedURL.Host
			req.Path = parsedURL.RequestURI()
		}
	}

	if req.Host == "" {
		return nil, fmt.Errorf("no Host header found in request")
	}

	return req, nil
}

// ReplaceMarker replaces the marker in the raw request with the given payload
func (p *ParsedRequest) ReplaceMarker(payload string) string {
	if p.MarkerType == "" {
		return p.RawRequest
	}

	// URL-encode the payload if the marker is in the URL (first line)
	encodedPayload := payload
	if p.isMarkerInURL() {
		encodedPayload = url.QueryEscape(payload)
	}

	// Escape special regex characters if marker contains them
	escapedMarker := regexp.QuoteMeta(p.MarkerType)
	re := regexp.MustCompile(escapedMarker)

	// Replace only the first occurrence
	return re.ReplaceAllStringFunc(p.RawRequest, func(match string) string {
		return encodedPayload
	})
}

// isMarkerInURL checks if the marker is in the URL (first line of request)
func (p *ParsedRequest) isMarkerInURL() bool {
	firstLineEnd := strings.Index(p.RawRequest, "\n")
	if firstLineEnd == -1 {
		firstLineEnd = len(p.RawRequest)
	}
	return p.MarkerPosition < firstLineEnd && p.MarkerPosition >= 0
}

// GetTargetURL returns the full target URL
func (p *ParsedRequest) GetTargetURL() string {
	return fmt.Sprintf("%s://%s%s", p.Scheme, p.Host, p.Path)
}

// Clone creates a copy of the parsed request
func (p *ParsedRequest) Clone() *ParsedRequest {
	headers := make(map[string]string)
	for k, v := range p.Headers {
		headers[k] = v
	}

	return &ParsedRequest{
		Method:         p.Method,
		Scheme:         p.Scheme,
		Host:           p.Host,
		Path:           p.Path,
		Headers:        headers,
		Body:           p.Body,
		RawRequest:     p.RawRequest,
		MarkerPosition: p.MarkerPosition,
		MarkerType:     p.MarkerType,
	}
}

// BuildRequest creates a new ParsedRequest with the payload injected
func (p *ParsedRequest) BuildRequest(payload string) (*ParsedRequest, error) {
	newRaw := p.ReplaceMarker(payload)
	newReq, err := ParseRequest(newRaw)
	if err != nil {
		return nil, err
	}
	// Preserve the scheme from the original request (for -ph flag)
	newReq.Scheme = p.Scheme
	return newReq, nil
}

// IsInBody returns true if the marker is in the request body
func (p *ParsedRequest) IsInBody() bool {
	bodyStart := strings.Index(p.RawRequest, "\n\n")
	if bodyStart == -1 {
		bodyStart = strings.Index(p.RawRequest, "\r\n\r\n")
	}
	if bodyStart == -1 {
		return false
	}
	return p.MarkerPosition > bodyStart
}

// ScanFile reads a file and returns the scanner
func ScanFile(filepath string) (*bufio.Scanner, *os.File, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, nil, err
	}
	return bufio.NewScanner(file), file, nil
}

// ParseURLFile reads a file with URLs (one per line) and returns them
func ParseURLFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open URL file: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading URL file: %w", err)
	}

	return urls, nil
}

// ParseRequestsDirectory reads all request files in a directory
func ParseRequestsDirectory(dirpath string) ([]*ParsedRequest, error) {
	entries, err := os.ReadDir(dirpath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var requests []*ParsedRequest
	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories
		}

		filePath := dirpath + "/" + entry.Name()
		req, err := ParseRequestFile(filePath)
		if err != nil {
			// Skip files that can't be parsed as requests
			continue
		}
		req.RawRequest = strings.TrimSpace(req.RawRequest) // Clean up
		requests = append(requests, req)
	}

	return requests, nil
}

// URLToRequest converts a URL string to a ParsedRequest for scanning
func URLToRequest(rawURL string) (*ParsedRequest, error) {
	// Ensure URL has scheme
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Host == "" {
		return nil, fmt.Errorf("missing host in URL")
	}

	path := parsedURL.RequestURI()
	if path == "" {
		path = "/"
	}

	// Build a minimal raw request
	rawRequest := fmt.Sprintf("GET %s HTTP/1.1\nHost: %s\nUser-Agent: flatsqli/1.0\nAccept: */*\nConnection: close\n",
		path, parsedURL.Host)

	return &ParsedRequest{
		Method:         "GET",
		Scheme:         parsedURL.Scheme,
		Host:           parsedURL.Host,
		Path:           path,
		Headers:        map[string]string{"Host": parsedURL.Host, "User-Agent": "flatsqli/1.0", "Accept": "*/*", "Connection": "close"},
		Body:           "",
		RawRequest:     rawRequest,
		MarkerPosition: -1,
	}, nil
}
