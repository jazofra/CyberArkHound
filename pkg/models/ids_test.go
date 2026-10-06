package models

import (
	"encoding/json"
	"testing"
)

func TestIDString(t *testing.T) {
	tests := []struct {
		id   interface{}
		want string
	}{
		{nil, ""},
		{" 42 ", "42"},
		{float64(1234567), "1234567"},
		{float64(12.5), "12.5"},
		{7, "7"},
		{int64(8), "8"},
		{json.Number("99"), "99"},
		{true, ""},
	}
	for _, tt := range tests {
		if got := IDString(tt.id); got != tt.want {
			t.Errorf("IDString(%#v) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
