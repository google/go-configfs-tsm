// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fakertmr defines a configfsi.Client for faking TSM behavior.
// The current implementation only supports TDX.
package fakertmr

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
)

const (
	tsmRtmrDigest = "digest"
	tsmPathIndex  = "index"
	tsmPathTcgMap = "tcg_map"
)

// rtmrValue represents the value of a rtmr index.
type rtmrValue struct {
	rtmrIndex int
	digest    []byte
	tcgMap    []byte
}

// rtmrEntry represents a rtmr entry in the configfs.
type rtmrEntry struct {
	rtmrIndex   int
	initialized bool
	// rtmrMaps is a map of rtmr index to rtmr value.
	// All RrmrMaps must be initialized with the value from RtmrSubsystem.
	rtmrMaps map[int]*rtmrValue
}

// RtmrSubsystem represents a fake configfs-tsm rtmr subsystem.
type RtmrSubsystem struct {
	// WriteAttr called on any WriteFile to an attribute.
	WriteAttr func(e *rtmrEntry, attr string, contents []byte) error
	// ReadAttr is called on any non-InAddr key.
	ReadAttr func(e *rtmrEntry, attr string) ([]byte, error)
	// Random is the source of randomness to use for MkdirTemp
	Random io.Reader
	// RtmrMaps is a map of rtmr index to rtmr value.
	RtmrMaps map[int]*rtmrValue
	// Entries is a map of rtmr entry name to rtmr entry.
	Entries map[string]*rtmrEntry
	// If set true, ReadDir will returns a list of directory entries.
	SetEntries bool
}

// RemoveAll implements configfsi.Client.
func (r *RtmrSubsystem) RemoveAll(path string) error {
	return errors.New("rtmr subsystem does not support RemoveAll")
}

func readTdx(entry *rtmrEntry, attr string) ([]byte, error) {
	if !entry.initialized {
		return nil, os.ErrNotExist
	}
	switch attr {
	case tsmRtmrDigest:
		return entry.rtmrMaps[entry.rtmrIndex].digest, nil
	case tsmPathIndex:
		return []byte(strconv.Itoa(entry.rtmrIndex)), nil
	case tsmPathTcgMap:
		return entry.rtmrMaps[entry.rtmrIndex].tcgMap, nil
	}
	return nil, os.ErrNotExist
}

func writeTdx(entry *rtmrEntry, attr string, content []byte) error {
	switch attr {
	case tsmRtmrDigest:
		if len(content) != crypto.SHA384.Size() {
			return syscall.EINVAL
		}
		if !entry.initialized {
			return os.ErrNotExist
		}
		// According to the TDX module spec, userspace can only extend rtmr2 or rtmr3
		if entry.rtmrIndex != 2 && entry.rtmrIndex != 3 {
			return os.ErrPermission
		}
		oldDigest := entry.rtmrMaps[entry.rtmrIndex].digest
		newDigest := sha512.Sum384(append(oldDigest[:], content...))
		entry.rtmrMaps[entry.rtmrIndex].digest = newDigest[:]
	case tsmPathIndex:
		index, e := strconv.Atoi(string(content))
		if e != nil {
			return fmt.Errorf("WriteTdx: %v", e)
		}
		entry.rtmrIndex = index
		entry.initialized = true
		value := entry.rtmrMaps[index]
		var rtmrPcrMaps = map[int]string{
			0: "1,7\n",
			1: "2-6\n",
			2: "8-15\n",
			3: "\n",
		}
		if value == nil {
			value = &rtmrValue{
				rtmrIndex: index,
				digest:    make([]byte, crypto.SHA384.Size()),
				tcgMap:    []byte(rtmrPcrMaps[index]),
			}
			entry.rtmrMaps[index] = value
		}
	default:
		return fmt.Errorf("WriteTdx: unknown attribute %q", attr)
	}
	return nil
}

// ReadDir reads the directory named by dirname
// and returns a list of directory entries sorted by filename.
func (r *RtmrSubsystem) ReadDir(dirname string) ([]os.DirEntry, error) {
	if r.SetEntries == false {
		return nil, os.ErrNotExist
	}
	rtmrDirs, err := os.MkdirTemp(os.TempDir(), "rtmr")
	if err != nil {
		return nil, fmt.Errorf("ReadDir: %v", err)
	}
	rtmr := [4]int{0, 1, 2, 3}
	for _, index := range rtmr {
		entryPath, err := os.MkdirTemp(rtmrDirs, fmt.Sprintf("rtmr%d-", index))
		if err != nil {
			log.Fatalf("MkdirTemp: %v", err)
		}
		index_file := filepath.Join(entryPath, tsmPathIndex)
		if err := os.WriteFile(index_file, []byte(fmt.Sprintf("%v", index)), 0666); err != nil {
			log.Fatalf("WriteFile: %v", err)
		}
	}
	return os.ReadDir(rtmrDirs)
}

// MkdirTemp creates a new temporary directory in the rtmr subsystem.
func (r *RtmrSubsystem) MkdirTemp(dir, pattern string) (string, error) {
	p, err := configfsi.ParseTsmPath(dir)
	if err != nil {
		return "", fmt.Errorf("MkdirTemp: Error %v", err)
	}
	if p.Entry != "" {
		return "", fmt.Errorf("MkdirTemp: rtmr entry %q cannot have subdirectories", dir)
	}

	if r.Entries == nil {
		r.Entries = make(map[string]*rtmrEntry)
	}
	name := configfsi.TempName(r.Random, pattern)
	if _, ok := r.Entries[name]; ok {
		return "", os.ErrExist
	}
	r.Entries[name] = &rtmrEntry{initialized: false, rtmrMaps: r.RtmrMaps}
	return path.Join(dir, name), nil
}

// ReadFile reads the contents of a file in the rtmr subsystem.
func (r *RtmrSubsystem) ReadFile(name string) ([]byte, error) {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: Error %v", err)
	}
	if r.Entries == nil {
		return nil, os.ErrNotExist
	}
	entry, ok := r.Entries[p.Entry]
	if !ok || entry == nil {
		return nil, os.ErrNotExist
	}
	return r.ReadAttr(entry, p.Attribute)
}

// WriteFile writes the contents to a file in the rtmr subsystem.
func (r *RtmrSubsystem) WriteFile(name string, content []byte) error {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}
	if p.Attribute == "" {
		return fmt.Errorf("WriteFile: no attribute specified to %q", name)
	}
	entry, ok := r.Entries[p.Entry]
	if !ok || entry == nil {
		return os.ErrNotExist
	}
	return r.WriteAttr(entry, p.Attribute, content)
}

// CreateRtmrSubsystem creates a new rtmr subsystem.
// The current subsystem only supports TDX.
func CreateRtmrSubsystem() *RtmrSubsystem {
	return &RtmrSubsystem{
		Random:     rand.Reader,
		WriteAttr:  writeTdx,
		ReadAttr:   readTdx,
		RtmrMaps:   make(map[int]*rtmrValue),
		Entries:    make(map[string]*rtmrEntry),
		SetEntries: false,
	}
}

// CreateRtmrSubsystemEntry creates a new rtmr subsystem.
// The fake susbsystem has set the interface.
// The current subsystem only supports TDX.
func CreateRtmrSubsystemWithEntries() *RtmrSubsystem {
	return &RtmrSubsystem{
		Random:     rand.Reader,
		WriteAttr:  writeTdx,
		ReadAttr:   readTdx,
		RtmrMaps:   make(map[int]*rtmrValue),
		Entries:    make(map[string]*rtmrEntry),
		SetEntries: true,
	}
}
