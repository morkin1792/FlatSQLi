package payloads

// knownVersionPrefixes contains common database version string prefixes.
// These are used to speed up version extraction by trying equality checks
// before falling back to binary search.
var knownVersionPrefixes = map[DatabaseType][]string{
	MySQL: {
		// MySQL versions
		"5.5.", "5.6.", "5.7.",
		"8.0.", "8.1.", "8.2.", "8.3.", "8.4.",
		// MariaDB versions
		"10.", "11.",
	},
	MSSQL: {
		"Microsoft SQL Server 2022",
		"Microsoft SQL Server 2019",
		"Microsoft SQL Server 2017",
		"Microsoft SQL Server 2016",
		"Microsoft SQL Server 2014",
		"Microsoft SQL Server 2012",
		"Microsoft SQL Server 2008",
	},
	PostgreSQL: {
		"PostgreSQL 17", "PostgreSQL 16", "PostgreSQL 15", "PostgreSQL 14",
		"PostgreSQL 13", "PostgreSQL 12", "PostgreSQL 11", "PostgreSQL 10",
		"PostgreSQL 9.",
	},
	Oracle: {
		"Oracle Database 23c", "Oracle Database 21c", "Oracle Database 19c",
		"Oracle Database 18c", "Oracle Database 12c", "Oracle Database 11g",
		// v$instance version format often starts with version number
		"23.", "21.", "19.", "18.", "12.", "11.",
	},
}

// GetVersionPrefixes returns known version prefixes for the given database type.
func GetVersionPrefixes(dbType DatabaseType) []string {
	if prefixes, ok := knownVersionPrefixes[dbType]; ok {
		return prefixes
	}
	return nil
}
