package configfsi

import (
	"strings"
	"testing"
)

func TestTsmPathString(t *testing.T) {
	tcs := []struct {
		input *TsmPath
		want  string
	}{
		{input: &TsmPath{}, want: "/sys/kernel/config/tsm"},
		{input: &TsmPath{Subsystem: "rebort"}, want: "/sys/kernel/config/tsm/rebort"},
		{
			input: &TsmPath{Subsystem: "repart", Entry: "j"},
			want:  "/sys/kernel/config/tsm/repart/j",
		},
		{
			input: &TsmPath{Subsystem: "report", Entry: "r", Attribute: "inblob"},
			want:  "/sys/kernel/config/tsm/report/r/inblob",
		},
	}
	for _, tc := range tcs {
		got := tc.input.String()
		if got != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func match(err error, want string) bool {
	if err == nil && want == "" {
		return true
	}
	return (err != nil && want != "" && strings.Contains(err.Error(), want))
}

func TestParseTsmPath(t *testing.T) {
	tcs := []struct {
		input   string
		want    *TsmPath
		wantErr string
	}{
		{
			input:   "not/to/configfs",
			wantErr: `"not/to/configfs" does not begin with "/sys/kernel/config/tsm"`,
		},
		{
			input:   "///sys/kernel/config/tsm",
			wantErr: `"/sys/kernel/config/tsm" does not contain a subsystem`,
		},
		{
			input:   "/sys/kernel/config/tsm/report/is/way/too/long",
			wantErr: `"report/is/way/too/long" suffix expected to be of form`,
		},
		{
			input: "/sys/kernel/config/tsm/a",
			want:  &TsmPath{Subsystem: "a"},
		},
		{
			input: "/sys/kernel/config/tsm/a/b",
			want:  &TsmPath{Subsystem: "a", Entry: "b"},
		},
		{
			input: "/sys/kernel/config/tsm/a/b/c",
			want:  &TsmPath{Subsystem: "a", Entry: "b", Attribute: "c"},
		},
	}
	for _, tc := range tcs {
		got, err := ParseTsmPath(tc.input)
		if !match(err, tc.wantErr) {
			t.Errorf("ParseTsmPath(%q) = %v, %v errored unexpectedly. Want %s",
				tc.input, got, err, tc.wantErr)
		}
		if tc.wantErr == "" && *got != *tc.want {
			t.Errorf("ParseTsmPath(%q) = %v, nil. Want %v", tc.input, *got, *tc.want)
		}
	}
}
