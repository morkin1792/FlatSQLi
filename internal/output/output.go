package output

import (
	"fmt"
	"os"
	"sync"
)

// Writer handles output to file with immediate flush for crash resilience
type Writer struct {
	file           *os.File
	filePath       string
	mu             sync.Mutex
	isURLs         bool // true for URL list input, false for request directory
	hasItems       bool
	headersWritten bool
	urlBlockOpened bool
}

// New creates a writer for the given path. Returns nil if path is empty.
func New(path string, isURLInput bool) (*Writer, error) {
	if path == "" {
		return nil, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	w := &Writer{
		file:     file,
		filePath: path,
		isURLs:   isURLInput,
	}

	// Write header title only (code block will be opened when first item is written or after headers)
	if isURLInput {
		w.writeString("## Potential SQLi Vulnerable URLs\n\n")
	} else {
		w.writeString("## Potential SQLi Vulnerable Requests\n\n")
	}

	return w, nil
}

// WriteHeaders writes custom headers section to the output
func (w *Writer) WriteHeaders(headers []string) {
	if w == nil || len(headers) == 0 {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.writeString("### Custom Headers Used\n\n```\n")
	for _, h := range headers {
		w.writeString(h + "\n")
	}
	w.writeString("```\n\n")

	// Write section header for vulnerable items
	if w.isURLs {
		w.writeString("### Vulnerable URLs\n\n")
	} else {
		w.writeString("### Vulnerable Requests\n\n")
	}

	w.headersWritten = true
}

// WriteURLResult appends a vulnerable URL to the output
func (w *Writer) WriteURLResult(url string, param string) {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Open code block if not yet opened
	if !w.urlBlockOpened {
		w.writeString("```\n")
		w.urlBlockOpened = true
	}

	// Format: URL with <PAYLOAD> marker on the vulnerable param
	w.writeString(url + "\n")
	w.hasItems = true
}

// WriteRequestResult appends a vulnerable request block to the output
func (w *Writer) WriteRequestResult(rawRequest string, param string) {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.writeString("```http\n")
	w.writeString(rawRequest)
	if rawRequest[len(rawRequest)-1] != '\n' {
		w.writeString("\n")
	}
	w.writeString("```\n\n")
	w.hasItems = true
}

// Close flushes and closes the file
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Close URL code block if needed
	if w.isURLs {
		w.writeString("```\n")
	}

	return w.file.Close()
}

// CloseAndCleanup closes the file and deletes it if no results were written
func (w *Writer) CloseAndCleanup() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	hasItems := w.hasItems
	filePath := w.filePath
	w.mu.Unlock()

	// Close the file first
	w.Close()

	// Delete the file if no results were written
	if !hasItems && filePath != "" {
		return os.Remove(filePath)
	}
	return nil
}

// writeString writes and immediately flushes
func (w *Writer) writeString(s string) {
	w.file.WriteString(s)
	w.file.Sync() // Immediate flush
}
