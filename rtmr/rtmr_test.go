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

package rtmr

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/fakertmr"
)

func TestExtendDigestErr(t *testing.T) {
	var sha384Hash [48]byte

	tcsErr := []struct {
		rtmr    int
		digest  []byte
		wantErr string
	}{
		{rtmr: 1, digest: sha384Hash[:], wantErr: "could not write digest to rmtr1"},
		{rtmr: 3, digest: []byte("aaaaaaaa"), wantErr: "the length of the digest must be 48 bytes"},
		{rtmr: -1, digest: sha384Hash[:], wantErr: "invalid rtmr index -1. Index can only be a non-negative number"},
	}
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	for _, tc := range tcsErr {
		err := ExtendDigest(client, tc.rtmr, tc.digest)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("ExtendtoRtmrClient(%d, %q) failed: %v, want %q", tc.rtmr, tc.digest, err, tc.wantErr)
		}
	}
}

func TestExtendDigestRtmrOk(t *testing.T) {
	var sha384Hash [48]byte

	tcsOk := []struct {
		rtmr   int
		digest []byte
	}{
		{rtmr: 2, digest: sha384Hash[:]},
		{rtmr: 3, digest: sha384Hash[:]},
		// Test the same rtmr index with an existing entry.
		{rtmr: 3, digest: sha384Hash[:]},
	}
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	for _, tc := range tcsOk {
		err := ExtendDigest(client, tc.rtmr, tc.digest)
		if err != nil {
			t.Fatalf("ExtendtoRtmrClient (%d, %q) failed: %v", tc.rtmr, tc.digest, err)
		}
	}
}

func TestGetDigestErr(t *testing.T) {
	tcsErr := []struct {
		rtmr    int
		wantErr string
	}{
		{rtmr: -1, wantErr: "invalid rtmr index -1. Index can only be a non-negative number"},
	}
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	for _, tc := range tcsErr {
		_, err := GetDigest(client, tc.rtmr)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("GetDigestRtmr(%d) failed: %v, want %q", tc.rtmr, err, tc.wantErr)
		}
	}
}

func TestGetDigestOk(t *testing.T) {
	var sha384Hash [48]byte
	tcsOk := []struct {
		rtmr   int
		digest []byte
		tcgMap []byte
	}{
		{rtmr: 0, digest: sha384Hash[:], tcgMap: []byte("1,7\n")},
		{rtmr: 1, digest: sha384Hash[:], tcgMap: []byte("2-6\n")},
		{rtmr: 2, digest: sha384Hash[:], tcgMap: []byte("8-15\n")},
		{rtmr: 3, digest: sha384Hash[:], tcgMap: []byte("\n")},
		// Test the same rtmr index with an existing entry.
		{rtmr: 2, digest: sha384Hash[:], tcgMap: []byte("8-15\n")},
	}
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	for _, tc := range tcsOk {
		r, err := GetDigest(client, tc.rtmr)
		if err != nil {
			t.Fatalf("GetDigestRtmr(%d) failed: %v", tc.rtmr, err)
		}
		if r.RtmrIndex != tc.rtmr {
			t.Fatalf("GetDigestRtmr(%d) failed: got %d, want %d", tc.rtmr, r.RtmrIndex, tc.rtmr)
		}
		if !bytes.Equal(r.TcgMap, tc.tcgMap) {
			t.Fatalf("GetDigestRtmr(%d) failed: got %q, want %q", tc.rtmr, r.TcgMap, tc.tcgMap)
		}
	}
}

func TestGetRtmrDigestAndExtendDigest(t *testing.T) {
	var sha384Hash [48]byte
	sha384Hash[0] = 0x01
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	rtmrIndex := 3
	initRtmrValue := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	extendRtmrValue := []byte("ܮ\x87\xd5n\xa6\x12\x15\xf3#\xa6&0`\xb6\x96(\x02\xb2Po\x80\xbe*\x92\xcb\fJ\x1f\x06\x80\xf0\x9c\x14\xee\xaan\x82\xc9\xfa\x9a\xec\xf9ROeś")
	// GetDigest
	digest1, err := GetDigest(client, rtmrIndex)
	if err != nil {
		t.Fatalf("GetDigest(%d) failed: %v", rtmrIndex, err)
	}
	if !bytes.Equal(digest1.Digest, initRtmrValue) {
		t.Fatalf("rtmr%q does not have the all-zero initial value %q", rtmrIndex, digest1.Digest)
	}
	// ExtendDigest
	err = ExtendDigest(client, rtmrIndex, sha384Hash[:])
	if err != nil {
		t.Fatalf("ExtendDigest(%d) failed: %v", rtmrIndex, err)
	}
	// GetDigest
	digest2, err := GetDigest(client, rtmrIndex)
	if err != nil {
		t.Fatalf("GetDigest(%d) failed: %v", rtmrIndex, err)
	}
	if !bytes.Equal(digest2.Digest, extendRtmrValue) {
		t.Fatalf("rtmr%q does not match the expected value: got %q, want %q", rtmrIndex, digest2.Digest, extendRtmrValue)
	}
}
