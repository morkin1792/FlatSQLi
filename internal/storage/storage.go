package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// HostCache stores all cached data for a host
type HostCache struct {
	Host         string                 `json:"host"`
	Database     string                 `json:"database,omitempty"`
	Version      string                 `json:"version,omitempty"`
	Tables       map[string]*TableCache `json:"tables,omitempty"`        // table_name -> columns & rows
	KnownStrings []string               `json:"known_strings,omitempty"` // cached unique strings for prediction
}

// TableCache stores columns and rows for a table
type TableCache struct {
	Columns []string            `json:"columns,omitempty"`
	Rows    []map[string]string `json:"rows,omitempty"` // array of column_name -> value
}

// Cache is the unified cache structure
type Cache struct {
	Hosts []HostCache `json:"hosts"`
}

// GetCachePath returns the path to the unified cache file
func GetCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".flatsqli.json"
	}
	return filepath.Join(home, ".flatsqli.json")
}

// loadUnifiedCache loads the unified cache with backwards compatibility
func loadUnifiedCache() (*Cache, error) {
	cachePath := GetCachePath()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Cache{Hosts: []HostCache{}}, nil
		}
		return nil, err
	}

	// Try to parse new format first
	var cache Cache
	if err := json.Unmarshal(data, &cache); err == nil {
		return &cache, nil
	}

	// Try to parse legacy format (with finder/pattern structure)
	var legacyCache struct {
		Hosts []struct {
			Host     string `json:"host"`
			Database string `json:"database,omitempty"`
			Version  string `json:"version,omitempty"`
			Finder   map[string]struct {
				Tables map[string]interface{} `json:"tables"`
			} `json:"finder,omitempty"`
			KnownStrings []string `json:"known_strings,omitempty"`
		} `json:"hosts"`
	}

	if err := json.Unmarshal(data, &legacyCache); err != nil {
		return &Cache{Hosts: []HostCache{}}, nil
	}

	// Migrate legacy format to new format
	cache = Cache{Hosts: make([]HostCache, 0, len(legacyCache.Hosts))}
	for _, legacyHost := range legacyCache.Hosts {
		hostCache := HostCache{
			Host:         legacyHost.Host,
			Database:     legacyHost.Database,
			Version:      legacyHost.Version,
			Tables:       make(map[string]*TableCache),
			KnownStrings: legacyHost.KnownStrings,
		}

		// Merge all tables from all patterns into single tables map
		for _, finderEntry := range legacyHost.Finder {
			for tableName, tableData := range finderEntry.Tables {
				if hostCache.Tables[tableName] == nil {
					hostCache.Tables[tableName] = &TableCache{}
				}

				// Handle both old format ([]string) and new format (TableCache)
				switch v := tableData.(type) {
				case []interface{}:
					// Old format: columns as array
					for _, col := range v {
						if colStr, ok := col.(string); ok {
							exists := false
							for _, c := range hostCache.Tables[tableName].Columns {
								if c == colStr {
									exists = true
									break
								}
							}
							if !exists {
								hostCache.Tables[tableName].Columns = append(hostCache.Tables[tableName].Columns, colStr)
							}
						}
					}
				case map[string]interface{}:
					// New format: TableCache with columns and rows
					if cols, ok := v["columns"].([]interface{}); ok {
						for _, col := range cols {
							if colStr, ok := col.(string); ok {
								exists := false
								for _, c := range hostCache.Tables[tableName].Columns {
									if c == colStr {
										exists = true
										break
									}
								}
								if !exists {
									hostCache.Tables[tableName].Columns = append(hostCache.Tables[tableName].Columns, colStr)
								}
							}
						}
					}
				}
			}
		}

		cache.Hosts = append(cache.Hosts, hostCache)
	}

	return &cache, nil
}

// saveUnifiedCache saves the unified cache
func saveUnifiedCache(cache *Cache) error {
	cachePath := GetCachePath()

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0644)
}

// normalizeHost extracts base host from full host string
func normalizeHost(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		if !strings.Contains(host[idx:], "]") {
			host = host[:idx]
		}
	}
	return strings.ToLower(host)
}

// findOrCreateHost finds existing host entry or creates new one
func findOrCreateHost(cache *Cache, host string) *HostCache {
	host = normalizeHost(host)
	for i := range cache.Hosts {
		if normalizeHost(cache.Hosts[i].Host) == host {
			return &cache.Hosts[i]
		}
	}
	cache.Hosts = append(cache.Hosts, HostCache{
		Host:   host,
		Tables: make(map[string]*TableCache),
	})
	return &cache.Hosts[len(cache.Hosts)-1]
}

// LoadDatabase returns the cached database type for a host
func LoadDatabase(host string) (string, string) {
	cache, err := loadUnifiedCache()
	if err != nil {
		return "", ""
	}

	host = normalizeHost(host)
	for _, entry := range cache.Hosts {
		if normalizeHost(entry.Host) == host {
			return entry.Database, entry.Version
		}
	}

	return "", ""
}

// SaveDatabase saves the database type for a host
func SaveDatabase(host, dbType, version string) error {
	cache, err := loadUnifiedCache()
	if err != nil {
		cache = &Cache{Hosts: []HostCache{}}
	}

	hostEntry := findOrCreateHost(cache, host)
	hostEntry.Database = dbType
	hostEntry.Version = version

	return saveUnifiedCache(cache)
}

// LoadTables loads all cached tables for a host
func LoadTables(host string) (map[string]*TableCache, bool) {
	cache, err := loadUnifiedCache()
	if err != nil {
		return nil, false
	}

	host = normalizeHost(host)
	for _, entry := range cache.Hosts {
		if normalizeHost(entry.Host) == host {
			if entry.Tables != nil && len(entry.Tables) > 0 {
				return entry.Tables, true
			}
			return nil, false
		}
	}

	return nil, false
}

// SaveTables saves all tables for a host
func SaveTables(host string, tables map[string]*TableCache) error {
	cache, err := loadUnifiedCache()
	if err != nil {
		cache = &Cache{Hosts: []HostCache{}}
	}

	hostEntry := findOrCreateHost(cache, host)
	hostEntry.Tables = tables

	return saveUnifiedCache(cache)
}

// ClearCache removes all cached entries
func ClearCache() error {
	cachePath := GetCachePath()
	return os.Remove(cachePath)
}

// RemoveHost removes a specific host from the cache
func RemoveHost(host string) error {
	cache, err := loadUnifiedCache()
	if err != nil {
		return err
	}

	host = normalizeHost(host)
	var newHosts []HostCache
	for _, entry := range cache.Hosts {
		if normalizeHost(entry.Host) != host {
			newHosts = append(newHosts, entry)
		}
	}
	cache.Hosts = newHosts

	return saveUnifiedCache(cache)
}

// LoadKnownStrings loads all known strings for a host
func LoadKnownStrings(host string) []string {
	cache, err := loadUnifiedCache()
	if err != nil {
		return nil
	}

	host = normalizeHost(host)
	for _, entry := range cache.Hosts {
		if normalizeHost(entry.Host) == host {
			return entry.KnownStrings
		}
	}
	return nil
}

// SaveKnownString saves a new string to the host's cache if not already present
func SaveKnownString(host, str string) error {
	if str == "" {
		return nil
	}

	cache, err := loadUnifiedCache()
	if err != nil {
		cache = &Cache{Hosts: []HostCache{}}
	}

	hostEntry := findOrCreateHost(cache, host)

	for _, s := range hostEntry.KnownStrings {
		if s == str {
			return nil
		}
	}

	hostEntry.KnownStrings = append(hostEntry.KnownStrings, str)
	return saveUnifiedCache(cache)
}

// AddTableColumn adds a column to a table in the cache
func AddTableColumn(host, tableName, columnName string) error {
	cache, err := loadUnifiedCache()
	if err != nil {
		cache = &Cache{Hosts: []HostCache{}}
	}

	hostEntry := findOrCreateHost(cache, host)
	if hostEntry.Tables == nil {
		hostEntry.Tables = make(map[string]*TableCache)
	}

	tableCache := hostEntry.Tables[tableName]
	if tableCache == nil {
		tableCache = &TableCache{}
	}

	if columnName != "" {
		exists := false
		for _, c := range tableCache.Columns {
			if c == columnName {
				exists = true
				break
			}
		}
		if !exists {
			tableCache.Columns = append(tableCache.Columns, columnName)
		}
	}
	hostEntry.Tables[tableName] = tableCache

	return saveUnifiedCache(cache)
}

// AddTableRow adds a row to a table in the cache
func AddTableRow(host, tableName string, row map[string]string) error {
	cache, err := loadUnifiedCache()
	if err != nil {
		cache = &Cache{Hosts: []HostCache{}}
	}

	hostEntry := findOrCreateHost(cache, host)
	if hostEntry.Tables == nil {
		hostEntry.Tables = make(map[string]*TableCache)
	}

	tableCache := hostEntry.Tables[tableName]
	if tableCache == nil {
		tableCache = &TableCache{}
	}

	tableCache.Rows = append(tableCache.Rows, row)
	hostEntry.Tables[tableName] = tableCache

	return saveUnifiedCache(cache)
}

// GetTableColumns returns cached columns for a table
func GetTableColumns(host, tableName string) []string {
	cache, err := loadUnifiedCache()
	if err != nil {
		return nil
	}

	host = normalizeHost(host)
	for _, entry := range cache.Hosts {
		if normalizeHost(entry.Host) == host {
			if entry.Tables == nil {
				return nil
			}
			if tc, ok := entry.Tables[tableName]; ok {
				return tc.Columns
			}
		}
	}
	return nil
}

// GetTableRows returns cached rows for a table
func GetTableRows(host, tableName string) []map[string]string {
	cache, err := loadUnifiedCache()
	if err != nil {
		return nil
	}

	host = normalizeHost(host)
	for _, entry := range cache.Hosts {
		if normalizeHost(entry.Host) == host {
			if entry.Tables == nil {
				return nil
			}
			if tc, ok := entry.Tables[tableName]; ok {
				return tc.Rows
			}
		}
	}
	return nil
}
