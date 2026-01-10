package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/morkin1792/flatsqli/internal/parser"
	"github.com/morkin1792/flatsqli/internal/requester"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// Parameter represents a discovered parameter
type Parameter struct {
	Name     string
	Value    string
	Location string // "url", "body-form", "body-json"
	Path     string // JSON path if applicable
}

// ScanResult represents the result of scanning a parameter
type ScanResult struct {
	Parameter      Parameter
	IsVulnerable   bool
	VulnType       string // "error-based", "concat-based"
	Details        string
	WorkingPayload string
}

// Scanner handles SQLi auto-discovery
type Scanner struct {
	baseRequest *parser.ParsedRequest
	requester   *requester.Requester
	verbose     bool
}

// New creates a new Scanner
func New(baseReq *parser.ParsedRequest, req *requester.Requester, verbose bool) *Scanner {
	return &Scanner{
		baseRequest: baseReq,
		requester:   req,
		verbose:     verbose,
	}
}

// DiscoverParameters extracts all parameters from the request
func (s *Scanner) DiscoverParameters() []Parameter {
	var params []Parameter

	// Parse URL parameters
	urlParams := s.parseURLParams()
	params = append(params, urlParams...)

	// Parse body parameters
	bodyParams := s.parseBodyParams()
	params = append(params, bodyParams...)

	return params
}

// parseURLParams extracts parameters from the URL query string
func (s *Scanner) parseURLParams() []Parameter {
	var params []Parameter

	// Find query string in path
	if idx := strings.Index(s.baseRequest.Path, "?"); idx != -1 {
		queryStr := s.baseRequest.Path[idx+1:]
		values, err := url.ParseQuery(queryStr)
		if err != nil {
			return params
		}

		for name, vals := range values {
			if len(vals) > 0 {
				params = append(params, Parameter{
					Name:     name,
					Value:    vals[0],
					Location: "url",
				})
			}
		}
	}

	return params
}

// parseBodyParams extracts parameters from the request body
func (s *Scanner) parseBodyParams() []Parameter {
	var params []Parameter

	body := s.baseRequest.Body
	if body == "" {
		return params
	}

	contentType := ""
	for k, v := range s.baseRequest.Headers {
		if strings.ToLower(k) == "content-type" {
			contentType = strings.ToLower(v)
			break
		}
	}

	// JSON body
	if strings.Contains(contentType, "application/json") {
		params = append(params, s.parseJSONParams(body)...)
	}

	// Form-urlencoded body
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		params = append(params, s.parseFormParams(body)...)
	}

	return params
}

// parseJSONParams extracts parameters from JSON body
func (s *Scanner) parseJSONParams(body string) []Parameter {
	var params []Parameter
	var data map[string]interface{}

	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return params
	}

	s.extractJSONParams(data, "", &params)
	return params
}

// extractJSONParams recursively extracts JSON parameters
func (s *Scanner) extractJSONParams(data map[string]interface{}, prefix string, params *[]Parameter) {
	for key, value := range data {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		switch v := value.(type) {
		case string:
			*params = append(*params, Parameter{
				Name:     key,
				Value:    v,
				Location: "body-json",
				Path:     path,
			})
		case map[string]interface{}:
			s.extractJSONParams(v, path, params)
		}
	}
}

// parseFormParams extracts parameters from form-urlencoded body
func (s *Scanner) parseFormParams(body string) []Parameter {
	var params []Parameter

	values, err := url.ParseQuery(body)
	if err != nil {
		return params
	}

	for name, vals := range values {
		if len(vals) > 0 {
			params = append(params, Parameter{
				Name:     name,
				Value:    vals[0],
				Location: "body-form",
			})
		}
	}

	return params
}

// ScanParameter tests a single parameter for SQLi
func (s *Scanner) ScanParameter(param Parameter) *ScanResult {
	result := &ScanResult{
		Parameter:    param,
		IsVulnerable: false,
	}

	ui.Verbose(s.verbose, "Testing parameter: %s (%s)", param.Name, param.Location)

	// Step 1: Test ' vs '' for error-based detection
	singleQuote := s.sendWithValue(param, param.Value+"'")
	doubleQuote := s.sendWithValue(param, param.Value+"''")

	if singleQuote != nil && doubleQuote != nil {
		if !singleQuote.Fingerprint.Equals(doubleQuote.Fingerprint) {
			result.IsVulnerable = true
			result.VulnType = "error-based"
			result.Details = "Different responses for ' vs ''"
			result.WorkingPayload = param.Value + "'"
			ui.Verbose(s.verbose, "Found error-based SQLi in %s", param.Name)
			return result
		}
	}

	// Step 2: Test if parameter affects response at all
	original := s.sendWithValue(param, "info")
	random := s.sendWithValue(param, "xxxx")

	if original == nil || random == nil {
		return result
	}

	if original.Fingerprint.Equals(random.Fingerprint) {
		// Parameter doesn't affect response - no SQLi
		ui.Verbose(s.verbose, "Parameter %s doesn't affect response", param.Name)
		return result
	}

	// Step 3: Test concat payloads
	concatPayloads := []struct {
		payload string
		dbType  string
	}{
		{"in'||'fo", "Oracle/PostgreSQL"},
		{"in'+'fo", "MSSQL"},
		{"CONCAT('in','fo')", "MySQL"},
		{"'in'||'fo'", "Oracle/PostgreSQL (full)"},
		{"'in'+'fo'", "MSSQL (full)"},
	}

	for _, cp := range concatPayloads {
		resp := s.sendWithValue(param, cp.payload)
		if resp != nil && original.Fingerprint.Equals(resp.Fingerprint) {
			result.IsVulnerable = true
			result.VulnType = "concat-based"
			result.Details = "Concat payload matches original - " + cp.dbType
			result.WorkingPayload = cp.payload
			ui.Verbose(s.verbose, "Found concat-based SQLi in %s using %s", param.Name, cp.dbType)
			return result
		}
	}

	return result
}

// ScanAll scans all discovered parameters
func (s *Scanner) ScanAll() []*ScanResult {
	params := s.DiscoverParameters()
	var results []*ScanResult

	ui.Info("Discovered %d parameters to scan", len(params))

	for _, param := range params {
		result := s.ScanParameter(param)
		results = append(results, result)
	}

	return results
}

// sendWithValue sends a request with a parameter value replaced
func (s *Scanner) sendWithValue(param Parameter, newValue string) *requester.Response {
	// Build modified request based on parameter location
	var modifiedRaw string

	switch param.Location {
	case "url":
		modifiedRaw = s.replaceURLParam(param.Name, newValue)
	case "body-form":
		modifiedRaw = s.replaceFormParam(param.Name, newValue)
	case "body-json":
		modifiedRaw = s.replaceJSONParam(param.Path, newValue)
	default:
		return nil
	}

	// Use SendRaw which preserves proxy/timeout settings from the existing requester
	resp, err := s.requester.SendRaw(modifiedRaw)
	if err != nil {
		return nil
	}

	return resp
}

// replaceURLParam replaces a URL parameter value
func (s *Scanner) replaceURLParam(name, newValue string) string {
	raw := s.baseRequest.RawRequest
	path := s.baseRequest.Path

	// Parse existing query
	if idx := strings.Index(path, "?"); idx != -1 {
		basePath := path[:idx]
		queryStr := path[idx+1:]
		values, _ := url.ParseQuery(queryStr)
		values.Set(name, newValue)
		newPath := basePath + "?" + values.Encode()

		// Replace in raw request
		raw = strings.Replace(raw, path, newPath, 1)
	}

	return raw
}

// replaceFormParam replaces a form body parameter value
func (s *Scanner) replaceFormParam(name, newValue string) string {
	raw := s.baseRequest.RawRequest
	body := s.baseRequest.Body

	values, _ := url.ParseQuery(body)
	values.Set(name, newValue)
	newBody := values.Encode()

	raw = strings.Replace(raw, body, newBody, 1)
	return raw
}

// replaceJSONParam replaces a JSON body parameter value
func (s *Scanner) replaceJSONParam(path, newValue string) string {
	raw := s.baseRequest.RawRequest
	body := s.baseRequest.Body

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return raw
	}

	// Set value at path
	parts := strings.Split(path, ".")
	s.setJSONValue(data, parts, newValue)

	newBody, err := json.Marshal(data)
	if err != nil {
		return raw
	}

	raw = strings.Replace(raw, body, string(newBody), 1)
	return raw
}

// setJSONValue sets a value at a JSON path
func (s *Scanner) setJSONValue(data map[string]interface{}, path []string, value string) {
	if len(path) == 1 {
		data[path[0]] = value
		return
	}

	if next, ok := data[path[0]].(map[string]interface{}); ok {
		s.setJSONValue(next, path[1:], value)
	}
}

// PrintResults prints scan results
func PrintResults(results []*ScanResult) {
	vulnerable := 0
	for _, r := range results {
		if r.IsVulnerable {
			vulnerable++
		}
	}

	if vulnerable == 0 {
		ui.Info("No SQL injection vulnerabilities found")
		return
	}

	ui.Success("Found %d potential SQL injection point(s):", vulnerable)
	fmt.Println()

	for _, r := range results {
		if r.IsVulnerable {
			ui.Success("Parameter: %s", r.Parameter.Name)
			ui.Info("  Location: %s", r.Parameter.Location)
			ui.Info("  Type: %s", r.VulnType)
			ui.Info("  Details: %s", r.Details)
			ui.Info("  Payload: %s", r.WorkingPayload)
			fmt.Println()
		}
	}
}
