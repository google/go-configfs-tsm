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

// Package report provides an API to the configfs/tsm/report subsystem for collecting
// attestation reports and associated certificates.
package report

import (
	"fmt"
	"strconv"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/uuid"
	"go.uber.org/multierr"
)

const (
	subsystem     = "report"
	subsystemPath = configfsi.TsmPrefix + "/" + subsystem
)

// Privilege represents the requested privilege information at which a report should
// be created.
type Privilege struct {
	Level int
}

// Request represents an open request for an attestation report.
type Request struct {
	InBlob     []byte
	Privilege  *Privilege
	GetAuxBlob bool
}

// OpenReport represents a created tsm report subtree with internal expectations for the generation.
type OpenReport struct {
	InBlob             []byte
	Privilege          *Privilege
	GetAuxBlob         bool
	entry              *configfsi.TsmPath
	expectedGeneration uint64
	client             configfsi.Client
}

// Response represents a common case response for getting at attestation report to avoid
// multiple attribute access calls.
type Response struct {
	Provider string
	OutBlob  []byte
	AuxBlob  []byte
}

func (r *OpenReport) attribute(subtree string) string {
	a := *r.entry
	a.Attribute = subtree
	return a.String()
}

func readUint64File(client configfsi.Client, p string) (uint64, error) {
	data, err := client.ReadFile(p)
	if err != nil {
		return 0, fmt.Errorf("could not read %q: %v", p, err)
	}
	return strconv.ParseUint(string(data), 10, 64)
}

// CreateOpenReport returns a newly-created entry in the configfs-tsm report subtree with an initial
// expected generation value.
func CreateOpenReport(client configfsi.Client) (*OpenReport, error) {
	r := &OpenReport{client: client}
	entry, err := client.MkdirTemp(subsystemPath, uuid.New().String())
	if err != nil {
		return nil, fmt.Errorf("could not create report entry in configfs: %v", err)
	}
	p, _ := configfsi.ParseTsmPath(entry)
	r.entry = &configfsi.TsmPath{Subsystem: subsystem, Entry: p.Entry}
	r.expectedGeneration, err = readUint64File(client, r.attribute("generation"))
	if err != nil {
		// The report was created but couldn't be properly initialized.
		return nil, multierr.Combine(r.Destroy(), err)
	}
	return r, nil
}

// Create returns a newly-created entry in the configfs-tsm report subtree with common inputs
// for the Get() method initialized from the request.
func Create(client configfsi.Client, req *Request) (*OpenReport, error) {
	r, err := CreateOpenReport(client)
	if err != nil {
		return nil, err
	}
	r.InBlob = req.InBlob // InBlob is not a copy!
	r.Privilege = req.Privilege
	r.GetAuxBlob = req.GetAuxBlob
	return r, nil
}

// Destroy returns an error if the configfs report subtree cannot be removed. Will not error for
// partially initialized or already-destroyed reports.
func (r *OpenReport) Destroy() error {
	if r.entry != nil {
		if err := r.client.RemoveAll(r.entry.String()); err != nil {
			return err
		}
		r.entry = nil
	}
	return nil
}

// PrivilegeLevelFloor returns the privlevel_floor attribute interpreted as the int type it is.
func (r *OpenReport) PrivilegeLevelFloor() (int, error) {
	data, err := r.ReadOption("privlevel_floor")
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseInt(string(data), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("could not parse privlevel_floor data %v as int: %v", data, err)
	}
	return int(i), nil
}

// WriteOption sets a configfs report option to the provided data and internally tracks
// the generation that should be expected on the next ReadOption.
func (r *OpenReport) WriteOption(subtree string, data []byte) error {
	if err := r.client.WriteFile(r.attribute(subtree), data); err != nil {
		return fmt.Errorf("could not write report %s: %v", subtree, err)
	}
	r.expectedGeneration += 1
	return nil
}

// ReadOption is a safe accessor to a readable attribute of a report. Returns an error if there is
// any detected tampering to the ongoing request.
func (r *OpenReport) ReadOption(subtree string) ([]byte, error) {
	data, err := r.client.ReadFile(r.attribute(subtree))
	if err != nil {
		return nil, fmt.Errorf("could not read report property %q: %v", subtree, err)
	}
	gotGeneration, err := readUint64File(r.client, r.attribute("generation"))
	if err != nil {
		return nil, err
	}
	if gotGeneration != r.expectedGeneration {
		return nil, fmt.Errorf("report generation was %d when expecting %d while reading property %q",
			gotGeneration, r.expectedGeneration, subtree)
	}
	return data, nil
}

// Get returns the requested report data after initializing the context to the expected
// parameters. Returns an error if the kernel reports an error or there is a difference in expected
// generation value.
func (r *OpenReport) Get() (*Response, error) {
	var err error
	if err := r.WriteOption("inblob", r.InBlob); err != nil {
		return nil, err
	}
	if r.Privilege != nil {
		if err := r.WriteOption("privlevel", []byte(fmt.Sprintf("%d", r.Privilege.Level))); err != nil {
			return nil, err
		}
	}
	resp := &Response{}
	if r.GetAuxBlob {
		resp.AuxBlob, err = r.ReadOption("auxblob")
		if err != nil {
			return nil, fmt.Errorf("could not read report auxblob: %v", err)
		}
	}
	resp.OutBlob, err = r.ReadOption("outblob")
	if err != nil {
		return nil, fmt.Errorf("could not read report outblob: %v", err)
	}
	providerData, err := r.ReadOption("provider")
	if err != nil {
		return nil, err
	}
	resp.Provider = string(providerData)
	return resp, nil
}

// Get returns a one-shot configfs-tsm report given a report request.
func Get(client configfsi.Client, req *Request) (*Response, error) {
	var err error
	r, err := Create(client, req)
	if err != nil {
		return nil, err
	}
	response, err := r.Get()
	return response, multierr.Combine(r.Destroy(), err)
}
