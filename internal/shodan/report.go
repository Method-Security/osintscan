package shodan

import (
	"encoding/json"
	"time"
)

// shodanTime is a custom type to handle custom time formats
type shodanTime struct {
	time.Time
}

type Record struct {
	ASN        string                    `json:"asn" yaml:"asn"`
	CPE        []string                  `json:"cpe" yaml:"cpe"`
	CPE23      []string                  `json:"cpe23" yaml:"cpe23"`
	Data       string                    `json:"data" required:"true" yaml:"data"`
	Device     string                    `json:"device" yaml:"device"`
	DeviceType string                    `json:"devicetype" yaml:"devicetype"`
	Domains    []string                  `json:"domains" required:"true" yaml:"domains"`
	Hash       int                       `json:"hash" required:"true" yaml:"hash"`
	Hostnames  []string                  `json:"hostnames" yaml:"hostnames"`
	HTTP       HTTP                      `json:"http" yaml:"http"`
	IPStr      string                    `json:"ip_str" yaml:"ip_str"`
	Info       string                    `json:"info" yaml:"info"`
	IPv6       string                    `json:"ipv6" yaml:"ipv6"`
	ISP        string                    `json:"isp" yaml:"isp"`
	Link       string                    `json:"link" yaml:"link"`
	MAC        map[string]MacAddressInfo `json:"mac" yaml:"mac"`
	Opts       map[string]interface{}    `json:"opts" yaml:"opts"`
	Org        string                    `json:"org" yaml:"org"`
	OS         string                    `json:"os" yaml:"os"`
	Platform   string                    `json:"platform" yaml:"platform"`
	Port       int                       `json:"port" yaml:"port"`
	Product    string                    `json:"product" yaml:"product"`
	Tags       []Tag                     `json:"tags" yaml:"tags"`
	Timestamp  shodanTime                `json:"timestamp" required:"true" yaml:"timestamp"`
	Title      string                    `json:"title" yaml:"title"`
	Transport  string                    `json:"transport" required:"true" yaml:"transport"`
	Uptime     int                       `json:"uptime" yaml:"uptime"`
	Vendor     string                    `json:"vendor" yaml:"vendor"`
	Version    string                    `json:"version" yaml:"version"`
	Vulns      map[string]Vulnerability  `json:"vulns" yaml:"vulns"`
}

type HTTP struct {
	Status      int     `json:"status" yaml:"status"`
	RobotsHash  *int    `json:"robots_hash" yaml:"robots_hash"`
	SecurityTxt *string `json:"securitytxt" yaml:"securitytxt"`
	Title       string  `json:"title" yaml:"title"`
	SitemapHash *int    `json:"sitemap_hash" yaml:"sitemap_hash"`
	Robots      *string `json:"robots" yaml:"robots"`
}

type MacAddressInfo struct {
	Assignment string `json:"assignment" required:"true" yaml:"assignment"`
	Date       string `json:"date" yaml:"date"`
	Org        string `json:"org" required:"true" yaml:"org"`
}

type Tag string

const (
	C2             Tag = "c2"
	CDN            Tag = "cdn"
	Cloud          Tag = "cloud"
	Compromised    Tag = "compromised"
	Cryptocurrency Tag = "cryptocurrency"
	Database       Tag = "database"
	DevOps         Tag = "devops"
	DoublePulsar   Tag = "doublepulsar"
	EOLOS          Tag = "eol-os"
	EOLProduct     Tag = "eol-product"
	Honeypot       Tag = "honeypot"
	ICS            Tag = "ics"
	IOT            Tag = "iot"
	Malware        Tag = "malware"
	Medical        Tag = "medical"
	Onion          Tag = "onion"
	Proxy          Tag = "proxy"
	SelfSigned     Tag = "self-signed"
	Scanner        Tag = "scanner"
	SSHBadKey      Tag = "ssh-bad-key"
	StartTLS       Tag = "starttls"
	Tor            Tag = "tor"
	Videogame      Tag = "videogame"
	VPN            Tag = "vpn"
)

type Vulnerability struct {
	CVSS       float64  `json:"cvss" yaml:"cvss"`
	References []string `json:"references" required:"true" yaml:"references"`
	Summary    string   `json:"summary" required:"true" yaml:"summary"`
	Verified   bool     `json:"verified" yaml:"verified"`
}

type Response struct {
	Matches []json.RawMessage `json:"matches" yaml:"matches"`
}

type Report struct {
	Query         string   `json:"query" yaml:"query"`
	QueryType     string   `json:"query_type" yaml:"query_type"`
	ShodanRecords []Record `json:"shodan_records" yaml:"shodan_records"`
	Errors        []string `json:"errors" yaml:"errors"`
}
