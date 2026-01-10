package ui

import (
	"fmt"
	"os"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// Banner prints the tool banner
func Banner(version string) {
	banner := `
  _____ _       _   ____   ___  _     _ 
 |  ___| | __ _| |_/ ___| / _ \| |   (_)
 | |_  | |/ _` + "`" + ` | __\___ \| | | | |   | |
 |  _| | | (_| | |_ ___) | |_| | |___| |
 |_|   |_|\__,_|\__|____/ \__\_\_____|_|
                                         `
	fmt.Fprintf(os.Stderr, "%s%s%s%s\n", colorBold, colorCyan, banner, colorReset)
	fmt.Fprintf(os.Stderr, "%s         SQLi Exploitation Tool v%s%s\n", colorPurple, version, colorReset)
	fmt.Fprintf(os.Stderr, "%s                Lightweight & WAF-Friendly%s\n\n", colorWhite, colorReset)
}

// Info prints an info message
func Info(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[*]%s %s\n", colorBlue, colorReset, fmt.Sprintf(format, args...))
}

// Success prints a success message
func Success(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[+]%s %s\n", colorGreen, colorReset, fmt.Sprintf(format, args...))
}

// Error prints an error message
func Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[-]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
}

// Warning prints a warning message
func Warning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[!]%s %s\n", colorYellow, colorReset, fmt.Sprintf(format, args...))
}

// Verbose prints a message only if verbose mode is enabled
func Verbose(enabled bool, format string, args ...interface{}) {
	if enabled {
		fmt.Fprintf(os.Stderr, "%s[>]%s %s\n", colorPurple, colorReset, fmt.Sprintf(format, args...))
	}
}

// Progress prints a progress update (overwrites current line)
func Progress(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\r\033[K%s[~]%s %s", colorCyan, colorReset, fmt.Sprintf(format, args...))
}

// ProgressDone finishes a progress line
func ProgressDone() {
	fmt.Fprintf(os.Stderr, "\n")
}

// Data prints extracted data (goes to stdout for piping)
func Data(format string, args ...interface{}) {
	fmt.Printf("%s\n", fmt.Sprintf(format, args...))
}
