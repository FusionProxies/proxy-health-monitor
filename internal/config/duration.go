package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that reads "90s", "5m", "1h30m" and also days
// ("7d", "30d"), which Go's own parser does not know.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return FormatDuration(time.Duration(d)) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected a duration such as 60s, 5m or 7d", n.Line)
	}
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON renders the duration as text, for the settings API.
func (d Duration) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(d.String())), nil }

// ParseDuration parses Go durations plus a "d" suffix for days. A bare 0 is
// accepted and means zero.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") && !strings.HasSuffix(s, "ns") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use 30s, 5m, 2h or 7d)", s)
	}
	if v < 0 {
		return 0, fmt.Errorf("negative duration %q", s)
	}
	return v, nil
}

// FormatDuration prints whole days as "7d" and everything else the Go way,
// without the trailing zero units Go adds ("5m" instead of "5m0s").
func FormatDuration(v time.Duration) string {
	if v == 0 {
		return "0s"
	}
	day := 24 * time.Hour
	if v%day == 0 {
		return strconv.FormatInt(int64(v/day), 10) + "d"
	}
	s := v.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
