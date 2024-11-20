// This file was auto-generated by Fern from our API Definition.

package osintscan

import (
	json "encoding/json"
	fmt "fmt"
	core "github.com/Method-Security/osintscan/generated/go/core"
)

type DnsRecord struct {
	Name  string `json:"name" url:"name"`
	Ttl   int    `json:"ttl" url:"ttl"`
	Type  string `json:"type" url:"type"`
	Value string `json:"value" url:"value"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (d *DnsRecord) GetExtraProperties() map[string]interface{} {
	return d.extraProperties
}

func (d *DnsRecord) UnmarshalJSON(data []byte) error {
	type unmarshaler DnsRecord
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*d = DnsRecord(value)

	extraProperties, err := core.ExtractExtraProperties(data, *d)
	if err != nil {
		return err
	}
	d.extraProperties = extraProperties

	d._rawJSON = json.RawMessage(data)
	return nil
}

func (d *DnsRecord) String() string {
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

type DnsRecords struct {
	A     []*DnsRecord `json:"a,omitempty" url:"a,omitempty"`
	Aaaa  []*DnsRecord `json:"aaaa,omitempty" url:"aaaa,omitempty"`
	Mx    []*DnsRecord `json:"mx,omitempty" url:"mx,omitempty"`
	Txt   []*DnsRecord `json:"txt,omitempty" url:"txt,omitempty"`
	Ns    []*DnsRecord `json:"ns,omitempty" url:"ns,omitempty"`
	Cname []*DnsRecord `json:"cname,omitempty" url:"cname,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (d *DnsRecords) GetExtraProperties() map[string]interface{} {
	return d.extraProperties
}

func (d *DnsRecords) UnmarshalJSON(data []byte) error {
	type unmarshaler DnsRecords
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*d = DnsRecords(value)

	extraProperties, err := core.ExtractExtraProperties(data, *d)
	if err != nil {
		return err
	}
	d.extraProperties = extraProperties

	d._rawJSON = json.RawMessage(data)
	return nil
}

func (d *DnsRecords) String() string {
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

type DnsRecordsReport struct {
	Domain          string      `json:"domain" url:"domain"`
	DnsRecords      *DnsRecords `json:"dnsRecords,omitempty" url:"dnsRecords,omitempty"`
	DmarcDomain     *string     `json:"dmarcDomain,omitempty" url:"dmarcDomain,omitempty"`
	DmarcDnsRecords *DnsRecords `json:"dmarcDnsRecords,omitempty" url:"dmarcDnsRecords,omitempty"`
	DkimDomain      *string     `json:"dkimDomain,omitempty" url:"dkimDomain,omitempty"`
	DkimDnsRecords  *DnsRecords `json:"dkimDnsRecords,omitempty" url:"dkimDnsRecords,omitempty"`
	Errors          []string    `json:"errors,omitempty" url:"errors,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (d *DnsRecordsReport) GetExtraProperties() map[string]interface{} {
	return d.extraProperties
}

func (d *DnsRecordsReport) UnmarshalJSON(data []byte) error {
	type unmarshaler DnsRecordsReport
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*d = DnsRecordsReport(value)

	extraProperties, err := core.ExtractExtraProperties(data, *d)
	if err != nil {
		return err
	}
	d.extraProperties = extraProperties

	d._rawJSON = json.RawMessage(data)
	return nil
}

func (d *DnsRecordsReport) String() string {
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

type DomainTakeover struct {
	Target       string     `json:"target" url:"target"`
	StatusCode   int        `json:"statusCode" url:"statusCode"`
	ResponseBody string     `json:"responseBody" url:"responseBody"`
	Domain       string     `json:"domain" url:"domain"`
	Cname        string     `json:"cname" url:"cname"`
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
