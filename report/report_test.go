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

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/faketsm"
)

func TestGetReport(t *testing.T) {
	c := &faketsm.Client{Subsystems: map[string]configfsi.Client{"report": faketsm.ReportV7(0)}}
	req := &ReportRequest{
		InBlob:     []byte("lessthan64bytesok"),
		GetAuxBlob: true,
	}
	resp, err := GetReport(c, req)
	if err != nil {
		t.Fatalf("GetReport(%+v) = %+v, %v, want nil", req, resp, err)
	}
	wantOut := "privlevel: 0\ninblob: 6c6573737468616e363462797465736f6b"
	if !bytes.Equal(resp.OutBlob, []byte(wantOut)) {
		t.Errorf("OutBlob %v is not %v", string(resp.OutBlob), wantOut)
	}
	if resp.Provider != "fake" {
		t.Errorf("provider = %q, want \"fake\"", resp.Provider)
	}
	if !bytes.Equal(resp.AuxBlob, []byte(`auxblob`)) {
		t.Errorf("auxblob = %v, want %v", resp.AuxBlob, []byte(`auxblob`))
	}
}

func TestGetReportErr(t *testing.T) {
	tcs := []struct {
		name    string
		req     *ReportRequest
		floor   uint
		wantErr string
	}{
		{
			name: "inblob too big",
			req: &ReportRequest{
				InBlob: make([]byte, 4096),
			},
			wantErr: "invalid argument",
		},
		{
			name: "privlevel too high",
			req: &ReportRequest{
				Privilege: &ReportPrivilege{Level: 300},
			},
			wantErr: "privlevel must be 0-3",
		},
		{
			name: "privlevel too low",
			req: &ReportRequest{
				Privilege: &ReportPrivilege{Level: 0},
			},
			floor:   1,
			wantErr: "privlevel 0 cannot be less than 1",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := &faketsm.Client{Subsystems: map[string]configfsi.Client{"report": faketsm.ReportV7(tc.floor)}}
			resp, err := GetReport(c, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("GetReport(%+v) = %+v, %v, want %q", tc.req, resp, err, tc.wantErr)
			}
		})
	}
}
