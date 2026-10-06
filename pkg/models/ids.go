package models

import (
	"encoding/json"
	"strconv"
	"strings"
)

// IDString renders a CyberArk object ID, which PVWA returns as a JSON number
// or a string. Numbers are printed in full (1234567, not 1.234567e+06); a
// missing ID, or one of any other type, yields "".
func IDString(id interface{}) string {
	switch v := id.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}
