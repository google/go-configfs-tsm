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

// RtmrSubsystem represents a fake configfs-tsm rtmr subsystem.
type RtmrSubsystem struct {
	// WriteAttr called on any WriteFile to an attribute.
	WriteAttr func(dirname string, attr string, contents []byte) error
	// ReadAttr is called on any non-InAddr key.
	ReadAttr func(dirname string, attr string) ([]byte, error)
	// Random is the source of randomness to use for MkdirTemp
	Random io.Reader
	// We use a temp folder to store the rtmr entries.
	// The path to the fake rtmr subsystem.
	Path string
}

// RemoveAll implements configfsi.Client.
func (r *RtmrSubsystem) RemoveAll(path string) error {
	return errors.New("rtmr subsystem does not support RemoveAll")
}

func readTdx(entry string, attr string) ([]byte, error) {
	return os.ReadFile(path.Join(entry, attr))
}

func writeTdx(entry string, attr string, content []byte) error {
	switch attr {
	case tsmRtmrDigest:
		// Check if the content is a valid SHA384 hash.
		if len(content) != crypto.SHA384.Size() {
			return syscall.EINVAL
		}
		// Check if the entry is initialized.
		content, err := os.ReadFile(filepath.Join(entry, tsmPathIndex))
		if err != nil {
			return err
		}
		rtmrIndex, err := strconv.Atoi(string(content))
		if err != nil {
			return err
		}
		if rtmrIndex != 2 && rtmrIndex != 3 {
			return os.ErrPermission
		}
		oldDigest, err := os.ReadFile(filepath.Join(entry, tsmRtmrDigest))
		if err != nil {
			return err
		}
		newDigest := sha512.Sum384(append(oldDigest[:], content...))
		if err := os.WriteFile(filepath.Join(entry, tsmRtmrDigest), newDigest[:], 0666); err != nil {
			return err
		}
	case tsmPathIndex:
		rtmrIndex, e := strconv.Atoi(string(content))
		if e != nil {
			return fmt.Errorf("WriteTdx: %v", e)
		}
		if rtmrIndex < 0 || rtmrIndex > 3 {
			return fmt.Errorf("WriteTdx: invalid rtmr index %d. Index can only be a non-negative number", rtmrIndex)
		}
		if err := os.WriteFile(filepath.Join(entry, tsmPathIndex), content, 0666); err != nil {
			return err
		}
		var rtmrPcrMaps = map[int]string{
			0: "1,7\n",
			1: "2-6\n",
			2: "8-15\n",
			3: "\n",
		}
		if err := os.WriteFile(filepath.Join(entry, tsmPathTcgMap), []byte(rtmrPcrMaps[rtmrIndex]), 0666); err != nil {
			return err
		}
	case tsmPathTcgMap:
		return os.ErrPermission
	default:
		return fmt.Errorf("WriteTdx: unknown attribute %q", attr)
	}
	return nil
}

// ReadDir reads the directory named by dirname
// and returns a list of directory entries sorted by filename.
func (r *RtmrSubsystem) ReadDir(dirname string) ([]os.DirEntry, error) {
	p, err := configfsi.ParseTsmPath(dirname)
	if err != nil {
		return nil, fmt.Errorf("ReadDir: %v", err)
	}
	if p.Entry != "" {
		return nil, fmt.Errorf("ReadDir: rtmr tsm %q cannot have subdirectories", dirname)
	}
	return os.ReadDir(r.Path)
}

func createEmptyFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
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
	if _, err := os.Stat(r.Path); os.IsNotExist(err) {
		if err = os.Mkdir(r.Path, 0755); err != nil {
			return "", fmt.Errorf("MkdirTemp: %v", err)
		}
	}
	name := configfsi.TempName(r.Random, pattern)
	fakeRtmrPath := path.Join(r.Path, name)
	if err = os.Mkdir(fakeRtmrPath, 0755); err != nil {
		return "", fmt.Errorf("MkdirTemp: %v", err)
	}
	// Create empty index, digest and tcg_map files.
	if err = createEmptyFile(filepath.Join(fakeRtmrPath, tsmPathIndex)); err != nil {
		return "", fmt.Errorf("MkdirTemp: %v", err)
	}

	if err = createEmptyFile(filepath.Join(fakeRtmrPath, tsmRtmrDigest)); err != nil {
		return "", fmt.Errorf("MkdirTemp: %v", err)
	}

	if err = createEmptyFile(filepath.Join(fakeRtmrPath, tsmPathTcgMap)); err != nil {
		return "", fmt.Errorf("MkdirTemp: %v", err)
	}

	return path.Join(dir, name), nil
}

// ReadFile reads the contents of a file in the rtmr subsystem.
func (r *RtmrSubsystem) ReadFile(name string) ([]byte, error) {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: Error %v", err)
	}
	return r.ReadAttr(path.Join(r.Path, p.Entry), p.Attribute)
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
	return r.WriteAttr(path.Join(r.Path, p.Entry), p.Attribute, content)
}

// CreateRtmrSubsystem creates a new rtmr subsystem.
// The current subsystem only supports TDX.
func CreateRtmrSubsystem() *RtmrSubsystem {
	return &RtmrSubsystem{
		Random:    rand.Reader,
		WriteAttr: writeTdx,
		ReadAttr:  readTdx,
		Path:      path.Join(os.TempDir(), "rtmr"),
	}
}
