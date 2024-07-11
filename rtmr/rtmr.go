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

// Package rtmr provides an API to the configfs/tsm/rtmr subsystem for
// extending runtime measurements to RTMR registers.
package rtmr

import (
	"crypto"
	"fmt"
	"strconv"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
)

const (
	rtmrSubsystem = "rtmrs"
	tsmRtmrPrefix = configfsi.TsmPrefix + "/" + rtmrSubsystem
	// The digest of the rtmr register.
	tsmRtmrDigest = "digest"
	// A Runtime Measurement Register (RTMR) hardware index.
	tsmPathIndex = "index"
	// A representation of the architecturally defined mapping between this RTMR and one or more TCG TPM PCRs
	tsmPathTcgMap = "tcg_map"
)

// Extend is a struct that represents a rtmr entry in the configfs.
type Extend struct {
	RtmrIndex int
	entry     *configfsi.TsmPath
	client    configfsi.Client
}

// Response is a struct that represents the response of reading a rtmr entry in the configfs.
type Response struct {
	RtmrIndex int
	digest    []byte
	tcgMap    []byte
}

func (r *Extend) attribute(subtree string) string {
	a := *r.entry
	a.Attribute = subtree
	return a.String()
}

// extendDigest extends the measurement to the rtmr with the given hash.
func (r *Extend) extendDigest(hash []byte) error {
	if err := r.client.WriteFile(r.attribute(tsmRtmrDigest), hash); err != nil {
		return fmt.Errorf("could not write digest to rmtr%d: %v", r.RtmrIndex, err)
	}
	return nil
}

// getDigest returns the digest of the rtmr.
func (r *Extend) getDigest() ([]byte, error) {
	return r.client.ReadFile(r.attribute(tsmRtmrDigest))
}

// getTcgMap returns the tcg map of the rtmr.
func (r *Extend) getTcgMap() ([]byte, error) {
	return r.client.ReadFile(r.attribute(tsmPathTcgMap))
}

// validateIndex checks if the rtmr index matches the expected value.
func (r *Extend) validateIndex() bool {
	if r == nil {
		return false
	}
	indexBytes, err := r.client.ReadFile(r.attribute(tsmPathIndex))
	if err != nil {
		return false
	}
	index, err := configfsi.Kstrtouint(indexBytes, 10, 64)
	if err != nil {
		return false
	}
	if int(index) != r.RtmrIndex {
		return false
	}
	return true
}

// setRtmrIndex sets a configfs rtmr entry to the given index.
// It reports an error if the index cannot be written.
func (r *Extend) setRtmrIndex() error {
	indexBytes := []byte(strconv.Itoa(r.RtmrIndex)) // Convert index to []byte
	indexPath := r.attribute(tsmPathIndex)
	if err := r.client.WriteFile(indexPath, indexBytes); err != nil {
		return fmt.Errorf("could not write index %s: %v", indexPath, err)
	}
	return nil
}

// searchRtmrInterface searches for an rtmr entry in the configfs.
func searchRtmrInterface(client configfsi.Client, index int) *Extend {
	root := tsmRtmrPrefix
	entries, err := client.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, d := range entries {
		if d.IsDir() {
			r := &Extend{
				RtmrIndex: index,
				entry:     &configfsi.TsmPath{Subsystem: rtmrSubsystem, Entry: d.Name()},
				client:    client,
			}
			if r.validateIndex() {
				return r
			}
		}
	}
	return nil
}

// createRtmrInterface creates a new rtmr entry in the configfs.
func createRtmrInterface(client configfsi.Client, index int) (*Extend, error) {
	entryPath, err := client.MkdirTemp(tsmRtmrPrefix, fmt.Sprintf("rtmr%d-", index))
	if err != nil {
		return nil, err
	}
	p, _ := configfsi.ParseTsmPath(entryPath)

	r := &Extend{
		RtmrIndex: index,
		entry:     &configfsi.TsmPath{Subsystem: rtmrSubsystem, Entry: p.Entry},
		client:    client,
	}

	if err := r.setRtmrIndex(); err != nil {
		return nil, fmt.Errorf("could not set rtmr index %d: %v", index, err)
	}
	return r, nil
}

// getRtmrInterface returns the rtmr entry in the configfs.
func getRtmrInterface(client configfsi.Client, index int) (*Extend, error) {
	// The configfs-tsm interface only allows one rtmr entry for a given index.
	// If the rtmr entry already exists, we should extend the digest to it.
	var err error
	r := searchRtmrInterface(client, index)
	if r == nil {
		r, err = createRtmrInterface(client, index)
	}
	return r, err
}

// ExtendDigest extends the measurement to the rtmr with the given digest.
func ExtendDigest(client configfsi.Client, rtmr int, digest []byte) error {
	if len(digest) != crypto.SHA384.Size() {
		return fmt.Errorf("the length of the digest must be %d bytes, the input is %d bytes", crypto.SHA384.Size(), len(digest))
	}
	if rtmr < 0 {
		return fmt.Errorf("invalid rtmr index %d. Index can only be a non-negative number", rtmr)
	}
	r, err := getRtmrInterface(client, rtmr)
	if err != nil {
		return err
	}
	return r.extendDigest(digest)
}

// GetDigest returns the digest and the tcg map of a given rtmr index.
func GetDigest(client configfsi.Client, rtmr int) (*Response, error) {
	if rtmr < 0 {
		return nil, fmt.Errorf("invalid rtmr index %d. Index can only be a non-negative number", rtmr)
	}
	r, err := getRtmrInterface(client, rtmr)
	if err != nil {
		return nil, err
	}
	digest, err := r.getDigest()
	if err != nil {
		return nil, err
	}
	tcgmap, err := r.getTcgMap()
	if err != nil {
		return nil, err
	}

	return &Response{
		RtmrIndex: rtmr,
		digest:    digest,
		tcgMap:    tcgmap,
	}, nil
}
