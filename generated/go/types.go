// This file was auto-generated by Fern from our API Definition.

package osintscan

import (
	json "encoding/json"
	fmt "fmt"
	core "github.com/Method-Security/osintscan/generated/go/core"
)

type DomainTakeover struct {
	Target       string     `json:"target" url:"target"`
	StatusCode   *int       `json:"statusCode,omitempty" url:"statusCode,omitempty"`
	ResponseBody *string    `json:"responseBody,omitempty" url:"responseBody,omitempty"`
	Services     []*Service `json:"services,omitempty" url:"services,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (d *DomainTakeover) GetExtraProperties() map[string]interface{} {
	return d.extraProperties
}

func (d *DomainTakeover) UnmarshalJSON(data []byte) error {
	type unmarshaler DomainTakeover
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*d = DomainTakeover(value)

	extraProperties, err := core.ExtractExtraProperties(data, *d)
	if err != nil {
		return err
	}
	d.extraProperties = extraProperties

	d._rawJSON = json.RawMessage(data)
	return nil
}

func (d *DomainTakeover) String() string {
	if len(d._rawJSON) > 0 {
		if value, err := core.StringifyJSON(d._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(d); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", d)
}

type DomainTakeoverReport struct {
	DomainTakeovers []*DomainTakeover `json:"domainTakeovers,omitempty" url:"domainTakeovers,omitempty"`
	Errors          []string          `json:"errors,omitempty" url:"errors,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (d *DomainTakeoverReport) GetExtraProperties() map[string]interface{} {
	return d.extraProperties
}

func (d *DomainTakeoverReport) UnmarshalJSON(data []byte) error {
	type unmarshaler DomainTakeoverReport
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*d = DomainTakeoverReport(value)

	extraProperties, err := core.ExtractExtraProperties(data, *d)
	if err != nil {
		return err
	}
	d.extraProperties = extraProperties

	d._rawJSON = json.RawMessage(data)
	return nil
}

func (d *DomainTakeoverReport) String() string {
	if len(d._rawJSON) > 0 {
		if value, err := core.StringifyJSON(d._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(d); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", d)
}

type Fingerprint struct {
	CicdPass      bool     `json:"cicdPass" url:"cicdPass"`
	Cname         []string `json:"cname,omitempty" url:"cname,omitempty"`
	Discussion    string   `json:"discussion" url:"discussion"`
	Documentation string   `json:"documentation" url:"documentation"`
	Fingerprint   string   `json:"fingerprint" url:"fingerprint"`
	HttpStatus    *int     `json:"httpStatus,omitempty" url:"httpStatus,omitempty"`
	NxDomain      bool     `json:"nxDomain" url:"nxDomain"`
	Service       string   `json:"service" url:"service"`
	Status        string   `json:"status" url:"status"`
	Vulnerable    bool     `json:"vulnerable" url:"vulnerable"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (f *Fingerprint) GetExtraProperties() map[string]interface{} {
	return f.extraProperties
}

func (f *Fingerprint) UnmarshalJSON(data []byte) error {
	type unmarshaler Fingerprint
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*f = Fingerprint(value)

	extraProperties, err := core.ExtractExtraProperties(data, *f)
	if err != nil {
		return err
	}
	f.extraProperties = extraProperties

	f._rawJSON = json.RawMessage(data)
	return nil
}

func (f *Fingerprint) String() string {
	if len(f._rawJSON) > 0 {
		if value, err := core.StringifyJSON(f._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(f); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", f)
}

type Service struct {
	Name        string `json:"name" url:"name"`
	Fingerprint string `json:"fingerprint" url:"fingerprint"`
	Vulnerable  bool   `json:"vulnerable" url:"vulnerable"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (s *Service) GetExtraProperties() map[string]interface{} {
	return s.extraProperties
}

func (s *Service) UnmarshalJSON(data []byte) error {
	type unmarshaler Service
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*s = Service(value)

	extraProperties, err := core.ExtractExtraProperties(data, *s)
	if err != nil {
		return err
	}
	s.extraProperties = extraProperties

	s._rawJSON = json.RawMessage(data)
	return nil
}

func (s *Service) String() string {
	if len(s._rawJSON) > 0 {
		if value, err := core.StringifyJSON(s._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(s); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", s)
}