package configfsi

import (
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	// TsmPrefix is the path to the configfs tsm system.
	TsmPrefix = "/sys/kernel/config/tsm"

	// How many random characters to use when replacing * in a temporary path pattern.
	randomPathSize = 6
)

// TsmPath represents a configfs file path decomposed into the components
// that are expected for TSM.
type TsmPath struct {
	// Subsystem is the TSM subsystem the path is targeting, e.g., "report"
	Subsystem string
	// Entry is the directory under the subsystem that represents a single
	// user's interface with the subsystem.
	Entry string
	// Attribute is a file under Entry that may be readable or writable depending
	// on its name.
	Attribute string
}

// String returns the configfs path that the TsmPath stands for.
func (p *TsmPath) String() string {
	return path.Join(TsmPrefix, p.Subsystem, p.Entry, p.Attribute)
}

// ParseTsmPath decomposes a configfs path to TSM into its expected format, or returns
// an error.
func ParseTsmPath(filepath string) (*TsmPath, error) {
	p := path.Clean(filepath)
	rest := strings.TrimPrefix(p, TsmPrefix)
	if rest == filepath {
		return nil, fmt.Errorf("%q does not begin with %q", p, TsmPrefix)
	}
	// If just the tsm folder is given, there won't be a "/", but if there is a subpath,
	// then it will have the leading "/".
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return nil, fmt.Errorf("%q does not contain a subsystem", p)
	}

	dir := path.Dir(rest)
	file := path.Base(rest)
	if dir == "." {
		return &TsmPath{Subsystem: file}, nil
	}
	gdir := path.Dir(dir)
	mfile := path.Base(dir)
	if gdir == "." {
		return &TsmPath{Subsystem: mfile, Entry: file}, nil
	}
	ggdir := path.Dir(gdir)
	subsystem := path.Base(gdir)
	if ggdir != "." {
		return nil, fmt.Errorf("%q suffix expected to be of form subsystem[/entry[/attribute]] (debug %q)", rest, ggdir)
	}
	return &TsmPath{Subsystem: subsystem, Entry: mfile, Attribute: file}, nil
}

func readableString(data []byte) string {
	b2r := func(b byte) rune {
		wrap := b % 62
		if wrap < 10 {
			return rune('0' + wrap)
		}
		wrap2 := (wrap - 10)
		if wrap2 < 26 {
			return rune('A' + wrap2)
		}
		wrap3 := wrap2 - 26
		return rune('a' + wrap3)
	}
	var sb strings.Builder
	for _, b := range data {
		sb.WriteRune(b2r(b))
	}
	return sb.String()
}

// TempName returns a random filename following the pattern semantics
// of os.MkdirTemp. Does not have a root directory.
func TempName(rand io.Reader, dir, pattern string) string {
	var randString string // [a-zA-Z0-9]
	data := make([]byte, randomPathSize)
	if n, err := rand.Read(data); err != nil || n != len(data) {
		return "rdfail"
	}
	lastAsterisk := strings.LastIndex(pattern, "*")
	if lastAsterisk == -1 {
		return pattern + randString
	}
	return pattern[0:lastAsterisk] + randString + pattern[lastAsterisk+1:]
}
