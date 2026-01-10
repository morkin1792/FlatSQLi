package requester

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/morkin1792/flatsqli/internal/fingerprint"
	"github.com/morkin1792/flatsqli/internal/parser"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// Response represents an HTTP response with fingerprint
type Response struct {
	StatusCode  int
	Body        []byte
	Headers     http.Header
	Fingerprint *fingerprint.Fingerprint
	Duration    time.Duration
}

// Requester handles HTTP requests with payload injection
type Requester struct {
	baseRequest   *parser.ParsedRequest
	client        *http.Client
	verbose       bool
	requestNum    int
	matchString   string
	customHeaders map[string]string
}

// New creates a new Requester
func New(baseRequest *parser.ParsedRequest, timeout int, proxyURL string, verbose bool) (*Requester, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true, // New connection per request to avoid stale data
	}

	// Configure proxy if provided
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
		ui.Verbose(verbose, "Using proxy: %s", proxyURL)
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		// Don't follow redirects automatically
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Requester{
		baseRequest: baseRequest,
		client:      client,
		verbose:     verbose,
		requestNum:  0,
		matchString: "",
	}, nil
}

// SetMatchString sets the match string for response differentiation
func (r *Requester) SetMatchString(s string) {
	r.matchString = s
}

// SetHeaders sets custom headers that will override existing ones
func (r *Requester) SetHeaders(headers []string) {
	r.customHeaders = make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			r.customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
}

// Send sends a request with the given payload injected
func (r *Requester) Send(payload string) (*Response, error) {
	r.requestNum++

	// Replace marker with payload
	modifiedReq, err := r.baseRequest.BuildRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Build the full URL
	targetURL := modifiedReq.GetTargetURL()

	ui.Verbose(r.verbose, "[Req #%d] %s %s (payload: %s)", r.requestNum, modifiedReq.Method, targetURL, truncatePayload(payload, 50))

	// Create HTTP request logic encapsulated for retry
	sendAttempt := func() (*Response, error) {
		var bodyReader io.Reader
		if modifiedReq.Body != "" {
			bodyReader = strings.NewReader(modifiedReq.Body)
		}

		httpReq, err := http.NewRequest(modifiedReq.Method, targetURL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Set headers from request
		for key, value := range modifiedReq.Headers {
			if strings.ToLower(key) == "host" {
				continue
			}
			httpReq.Header.Set(key, value)
		}

		// Apply custom headers (override existing)
		for key, value := range r.customHeaders {
			httpReq.Header.Set(key, value)
		}

		// Add cache-busting headers to prevent proxy caching
		httpReq.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		httpReq.Header.Set("Pragma", "no-cache")

		// Send request
		start := time.Now()
		resp, err := r.client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()
		duration := time.Since(start)

		// Read body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		// Create fingerprint
		fp := fingerprint.NewWithMatchString(resp.StatusCode, body, r.matchString)

		response := &Response{
			StatusCode:  resp.StatusCode,
			Body:        body,
			Headers:     resp.Header,
			Fingerprint: fp,
			Duration:    duration,
		}

		ui.Verbose(r.verbose, "[Resp #%d] Status: %d, Words: %d, Length: %d, Time: %dms",
			r.requestNum, fp.StatusCode, fp.WordCount, fp.ContentLength, duration.Milliseconds())

		return response, nil
	}

	// Retry loop
	var lastErr error
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(500*(i)) * time.Millisecond)
			ui.Verbose(r.verbose, "Retrying request... (%d/3)", i+1)
		}

		resp, err := sendAttempt()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		// Only retry on error (network/transport), not on valid HTTP response
	}

	return nil, lastErr
}

// SendRaw sends a raw payload without modification
func (r *Requester) SendRaw(rawRequest string) (*Response, error) {
	tempReq, err := parser.ParseRequest(rawRequest)
	if err != nil {
		return nil, err
	}

	// Preserve scheme from original base request (for -ph flag)
	tempReq.Scheme = r.baseRequest.Scheme

	oldBase := r.baseRequest
	r.baseRequest = tempReq
	defer func() { r.baseRequest = oldBase }()

	return r.Send("")
}

// GetRequestCount returns the number of requests made
func (r *Requester) GetRequestCount() int {
	return r.requestNum
}

// GetHost returns the target host
func (r *Requester) GetHost() string {
	return r.baseRequest.Host
}

// truncatePayload truncates a payload for display
func truncatePayload(payload string, maxLen int) string {
	if len(payload) <= maxLen {
		return payload
	}
	return payload[:maxLen] + "..."
}
