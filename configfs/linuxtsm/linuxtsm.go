// Copyright 2023 Google LLC
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

// Package linuxtsm defines a configfsi.Client for Linux OS operations on configfs.
package linuxtsm

import "os"

// Client provides configfsi.Client for /sys/kernel/config/tsm file operations in Linux.
type Client struct{}

// MkdirTemp creates a new temporary directory in the directory dir and returns the pathname
// of the new directory. Pattern semantics follow os.MkdirTemp.
func (*Client) MkdirTemp(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern)
}

// ReadFile reads the named file and returns the contents.
func (*Client) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// WriteFile writes data to the named file, creating it if necessary. The permissions
// are implementation-defined.
func (*Client) WriteFile(name string, contents []byte) error {
	return os.WriteFile(name, contents, 0220)
}

// RemoveAll removes path and any children it contains.
func (*Client) RemoveAll(path string) error {
	return os.Remove(path)
}
