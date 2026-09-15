package badoption

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/xray/crypto"
	E "github.com/sagernet/sing/common/exceptions"
)

type Range struct {
	From int32 `json:"from"`
	To   int32 `json:"to"`
}

func (c *Range) Build() *Range {
	return (*Range)(c)
}

func (c *Range) MarshalJSON() ([]byte, error) {
	if c.From == 0 && c.To == 0 {
		return json.Marshal("")
	}
	return json.Marshal(fmt.Sprintf("%d-%d", c.From, c.To))
}

// splitFromSecondDash mirrors Xray infra/conf/common.go:splitFromSecondDash.
//
//	"-114-514"   ->  ["-114", "514"]
//	"-1919--810" ->  ["-1919", "-810"]
func splitFromSecondDash(s string) []string {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) < 3 {
		return []string{s}
	}
	return []string{parts[0] + "-" + parts[1], parts[2]}
}

// parseRangeString is a port of Xray infra/conf/common.go:ParseRangeString
// (v26.9.9, unchanged since v26.7.11). Accepted forms — exactly Xray's:
// "114-514", "-114-514", "-1919--810", plain "114", plain "-1" (negative
// sentinel), and "" (treated as 0). Anything else is an error, including
// "1-2-3": the old local implementation split on EVERY dash and silently took
// the first part, so a config Xray rejects loaded here with a wrong value.
//
// strconv.Atoi + an int32 cast (rather than ParseInt(_, 10, 32)) is deliberate:
// it reproduces Xray's out-of-int32 truncation instead of failing the whole
// config load. The acceptance bar for this type is "any subscription Xray eats,
// we eat", not "our parser is stricter".
func parseRangeString(str string) (int32, int32, error) {
	// number in string form, e.g. "114" or the "-1" sentinel
	if value, err := strconv.Atoi(str); err == nil {
		return int32(value), int32(value), nil
	}
	// empty string is 0
	if str == "" {
		return 0, 0, nil
	}
	var pair []string
	if strings.HasPrefix(str, "-") {
		// "-114-514" / "-1919--810": the leading dash is a sign, not a separator
		pair = splitFromSecondDash(str)
	} else {
		pair = strings.SplitN(str, "-", 2)
	}
	if len(pair) == 2 {
		left, err := strconv.Atoi(pair[0])
		right, err2 := strconv.Atoi(pair[1])
		if err == nil && err2 == nil {
			return int32(left), int32(right), nil
		}
	}
	return 0, 0, E.New("invalid range string: ", str)
}

func (c *Range) UnmarshalJSON(content []byte) error {
	var rangeValue struct {
		From int32 `json:"from"`
		To   int32 `json:"to"`
	}
	var stringValue string

	if err := json.Unmarshal(content, &stringValue); err == nil {
		from, to, err := parseRangeString(stringValue)
		if err != nil {
			return err
		}
		rangeValue.From, rangeValue.To = from, to
	} else {
		var intValue int32
		if err := json.Unmarshal(content, &intValue); err == nil {
			rangeValue.From, rangeValue.To = intValue, intValue
		} else if err := json.Unmarshal(content, &rangeValue); err != nil {
			// object form {"from":..,"to":..} is ours, not Xray's; keep it.
			return err
		}
	}

	// Xray's Int32Range.ensureOrder(): a reversed range is SWAPPED, never an
	// error ("Value will be exchanged if From > To" — its own doc comment).
	// We used to return E.New("invalid range") here, which made a config that
	// loads in Xray fail to load at all.
	if rangeValue.From > rangeValue.To {
		rangeValue.From, rangeValue.To = rangeValue.To, rangeValue.From
	}
	*c = Range{rangeValue.From, rangeValue.To}
	return nil
}

func (c Range) Rand() int32 {
	return int32(crypto.RandBetween(int64(c.From), int64(c.To)))
}
