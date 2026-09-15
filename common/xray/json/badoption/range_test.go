package badoption

import (
	"encoding/json"
	"testing"
)

// Reference: Xray v26.9.9 infra/conf/common.go — Int32Range.UnmarshalJSON,
// ParseRangeString, splitFromSecondDash, ensureOrder. Every accepted case below
// is a string Xray loads; a config that loads in Xray must load here too.
func TestRangeUnmarshalJSONParity(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		input string
		from  int32
		to    int32
	}{
		{`"114-514"`, 114, 514},
		{`"1000-100"`, 100, 1000},     // ensureOrder swaps, does not error
		{`"-1"`, -1, -1},              // negative sentinel
		{`"-1919--810"`, -1919, -810}, // sign-aware split from the second dash
		{`"-114-514"`, -114, 514},
		{`""`, 0, 0},
		{`"114"`, 114, 114},
		{`100`, 100, 100},
		{`-1`, -1, -1},
		{`{"from":500,"to":100}`, 100, 500}, // object form is ours; order still normalized
	} {
		var value Range
		if err := json.Unmarshal([]byte(testCase.input), &value); err != nil {
			t.Fatalf("Unmarshal(%s): unexpected error %v", testCase.input, err)
		}
		if value.From != testCase.from || value.To != testCase.to {
			t.Fatalf("Unmarshal(%s) = {%d,%d}, want {%d,%d}", testCase.input, value.From, value.To, testCase.from, testCase.to)
		}
	}
}

func TestRangeUnmarshalJSONRejects(t *testing.T) {
	t.Parallel()
	// Xray's ParseRangeString errors on these; the old implementation split on
	// every dash and silently parsed "1-2-3" as 1..1.
	for _, input := range []string{`"1-2-3"`, `"a-b"`, `"1-"`, `"1-x"`, `true`} {
		var value Range
		if err := json.Unmarshal([]byte(input), &value); err == nil {
			t.Fatalf("Unmarshal(%s): expected an error, got {%d,%d}", input, value.From, value.To)
		}
	}
}
