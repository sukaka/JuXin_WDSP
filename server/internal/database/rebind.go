package database

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/config"
)

// Rebind 将 PostgreSQL 风格的位置参数转换为指定数据库方言。
func Rebind(dialect, query string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(dialect)) {
	case "", config.DBDialectPostgres, config.DBDialectKingbase:
		return query, nil
	case config.DBDialectDameng:
	default:
		return "", fmt.Errorf("unsupported database dialect %q", dialect)
	}

	var out strings.Builder
	out.Grow(len(query))
	for i := 0; i < len(query); {
		switch {
		case query[i] == '\'':
			end := scanSingleQuoted(query, i)
			out.WriteString(query[i:end])
			i = end
		case query[i] == '"':
			end := scanDoubleQuoted(query, i)
			out.WriteString(query[i:end])
			i = end
		case strings.HasPrefix(query[i:], "--"):
			end := scanLineComment(query, i)
			out.WriteString(query[i:end])
			i = end
		case strings.HasPrefix(query[i:], "/*"):
			end := scanBlockComment(query, i)
			out.WriteString(query[i:end])
			i = end
		case query[i] == '$':
			if delimiter, ok := dollarQuoteDelimiter(query, i); ok {
				end := len(query)
				if closing := strings.Index(query[i+len(delimiter):], delimiter); closing >= 0 {
					end = i + len(delimiter) + closing + len(delimiter)
				}
				out.WriteString(query[i:end])
				i = end
				continue
			}
			if i+1 >= len(query) || query[i+1] < '0' || query[i+1] > '9' {
				out.WriteByte(query[i])
				i++
				continue
			}
			end := i + 1
			for end < len(query) && query[end] >= '0' && query[end] <= '9' {
				end++
			}
			number := query[i+1 : end]
			value, err := strconv.ParseUint(number, 10, 31)
			if err != nil || value == 0 {
				return "", fmt.Errorf("invalid positional parameter $%s", number)
			}
			out.WriteByte(':')
			out.WriteString(number)
			i = end
		default:
			out.WriteByte(query[i])
			i++
		}
	}
	return out.String(), nil
}

func scanSingleQuoted(query string, start int) int {
	escaped := start > 0 && (query[start-1] == 'E' || query[start-1] == 'e') &&
		(start == 1 || !isIdentifierChar(query[start-2]))
	for i := start + 1; i < len(query); i++ {
		if escaped && query[i] == '\\' {
			if i+1 < len(query) {
				i++
			}
			continue
		}
		if query[i] == '\'' {
			if i+1 < len(query) && query[i+1] == '\'' {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(query)
}

func scanDoubleQuoted(query string, start int) int {
	for i := start + 1; i < len(query); i++ {
		if query[i] == '"' {
			if i+1 < len(query) && query[i+1] == '"' {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(query)
}

func scanLineComment(query string, start int) int {
	if end := strings.IndexByte(query[start:], '\n'); end >= 0 {
		return start + end + 1
	}
	return len(query)
}

func scanBlockComment(query string, start int) int {
	depth := 1
	for i := start + 2; i < len(query); {
		switch {
		case strings.HasPrefix(query[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(query[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(query)
}

func dollarQuoteDelimiter(query string, start int) (string, bool) {
	if start+1 >= len(query) {
		return "", false
	}
	if query[start+1] == '$' {
		return "$$", true
	}
	if !isIdentifierStart(query[start+1]) {
		return "", false
	}
	for i := start + 2; i < len(query); i++ {
		if query[i] == '$' {
			return query[start : i+1], true
		}
		if !isIdentifierChar(query[i]) {
			return "", false
		}
	}
	return "", false
}

func isIdentifierStart(ch byte) bool {
	return ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func isIdentifierChar(ch byte) bool {
	return isIdentifierStart(ch) || ch >= '0' && ch <= '9'
}
