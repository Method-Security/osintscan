// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/caffix/stringset"
	"gopkg.in/yaml.v3"
)

const (
	outputDirName  = "amass"
	defaultCfgFile = "config.yaml"
	cfgEnvironVar  = "AMASS_CONFIG"
	systemCfgDir   = "/etc"
)

// Updater allows an object to implement a method that updates a configuration.
type Updater interface {
	OverrideConfig(*Config) error
}

// Config passes along Amass configuration settings and options.
type Config struct {
	sync.Mutex `yaml:"-"`

	// The pseudo-random number generator
	Rand *rand.Rand `yaml:"-"`

	// Logger for error messages
	Log *log.Logger `yaml:"-"`

	// The date/time that discoveries must be active since to be included in the findings
	CollectionStartTime time.Time `yaml:"-"`

	// Scope struct that contains ASN, CIDR, Domain, IP, and ports in scope
	Scope *Scope `yaml:"scope,omitempty"`

	// Defines options like datasources config path and stuff like that
	Options map[string]interface{} `yaml:"options,omitempty"`

	// Filepath of the configuration file. It is needed as a seed incase of relative paths in the config.
	Filepath string `yaml:"-"`

	// Alternative directory for scripts provided by the user
	ScriptsDirectory string `yaml:"-"`

	// The directory that stores the bolt db and other files created
	Dir string `yaml:"-"`

	// The graph databases used by the system / enumerations
	GraphDBs []*Database `yaml:"-"`

	// The maximum number of concurrent DNS queries
	MaxDNSQueries int `yaml:"-"`

	// The list of words to use when generating names
	Wordlist []string `yaml:"-"`

	// Will the enumeration including brute forcing techniques
	BruteForcing bool `yaml:"-"`

	// Will recursive brute forcing be performed?
	Recursive bool `yaml:"-"`

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int `yaml:"-"`

	// Maximum depth for bruteforcing
	MaxDepth int `yaml:"-"`

	// Will discovered subdomain name alterations be generated?
	Alterations    bool     `yaml:"-"`
	FlipWords      bool     `yaml:"-"`
	FlipNumbers    bool     `yaml:"-"`
	AddWords       bool     `yaml:"-"`
	AddNumbers     bool     `yaml:"-"`
	MinForWordFlip int      `yaml:"-"`
	EditDistance   int      `yaml:"-"`
	AltWordlist    []string `yaml:"-"`

	// Only access the data sources for names and return results?
	Passive bool `yaml:"-"`

	// Determines if zone transfers will be attempted
	Active bool `yaml:"-"`

	blacklistLock sync.Mutex `yaml:"-"`

	// A list of data sources that should not be utilized
	SourceFilter struct {
		Include bool     `yaml:"-"` // true = include, false = exclude
		Sources []string `yaml:"-"`
	} `yaml:"-"`

	// The minimum number of minutes that data source responses will be reused
	MinimumTTL int `yaml:"-"`

	// Type of DNS records to query for
	RecordTypes []string `yaml:"-"`

	// Resolver settings
	Resolvers        []string `yaml:"-"`
	ResolversQPS     int      `yaml:"-"`
	TrustedResolvers []string `yaml:"-"`
	TrustedQPS       int      `yaml:"-"`

	// Option for verbose logging and output
	Verbose bool `yaml:"-"`

	// Names provided to seed the enumeration
	ProvidedNames []string `yaml:"-"`

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp `yaml:"-"`

	// Mode should be determined based on scripts utilized
	Mode string `yaml:"-"`

	// The data source configurations
	DataSrcConfigs *DataSourceConfig `yaml:"-"`
}

type Scope struct {
	// The root domain names that the enumeration will target
	Domains []string `yaml:"domains,omitempty"`

	// IP Net.IP
	Addresses []net.IP `yaml:"-"`

	// The IP addresses specified as in scope
	IP []string `yaml:"ips,omitempty"`

	// ASNs specified as in scope
	ASNs []int `yaml:"asns,omitempty"`

	// CIDR IPNET
	CIDRs []*net.IPNet `yaml:"-"`

	// CIDR in scope
	CIDRStrings []string `yaml:"cidrs,omitempty"`

	// The ports checked for certificates
	Ports []int `yaml:"ports,omitempty"`

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string `yaml:"blacklist,omitempty"`
}

// NewConfig returns a default configuration object.
func NewConfig() *Config {
	return &Config{
		Rand:                rand.New(rand.NewSource(time.Now().UTC().UnixNano())),
		Log:                 log.New(io.Discard, "", 0),
		CollectionStartTime: time.Now(),
		Scope:               &Scope{Ports: []int{80, 443}},
		Options:             make(map[string]interface{}),
		MinForRecursive:     1,
		FlipWords:           true,
		FlipNumbers:         true,
		AddWords:            true,
		AddNumbers:          true,
		MinForWordFlip:      2,
		EditDistance:        1,
		Recursive:           true,
		MinimumTTL:          1440,
		ResolversQPS:        DefaultQueriesPerPublicResolver,
		TrustedQPS:          DefaultQueriesPerBaselineResolver,
		DataSrcConfigs: &DataSourceConfig{
			GlobalOptions: make(map[string]int),
		},
	}
}

// UpdateConfig allows the provided Updater to update the current configuration.
func (c *Config) UpdateConfig(update Updater) error {
	return update.OverrideConfig(c)
}

// CheckSettings runs some sanity checks on the configuration options selected.
func (c *Config) CheckSettings() error {
	var err error

	if c.BruteForcing {
		if c.Passive {
			return errors.New("brute forcing cannot be performed without DNS resolution")
		}
	}
	if c.Passive && c.Active {
		return errors.New("active enumeration cannot be performed without DNS resolution")
	}

	c.Wordlist, err = ExpandMaskWordlist(c.Wordlist)
	if err != nil {
		return err
	}

	c.AltWordlist, err = ExpandMaskWordlist(c.AltWordlist)
	if err != nil {
		return err
	}
	return err
}

// LoadSettings parses settings from an .yaml file and assigns them to the Config.
func (c *Config) LoadSettings(path string) error {
	// Determine and store the absolute path of the config file
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of the configuration file: %v", err)
	}
	c.Filepath = absolutePath

	// Open the configuration file
	data, err := os.ReadFile(c.Filepath)
	if err != nil {
		return fmt.Errorf("failed to load the main configuration file: %v", err)
	}

	err = yaml.Unmarshal(data, c)
	if err != nil {
		return fmt.Errorf("error mapping configuration settings to internal values: %v", err)
	}

	// Convert string CIDRs to net.IP and net.IPNet
	c.Scope.CIDRs = c.Scope.toCIDRs(c.Scope.CIDRStrings)

	parseIPs := ParseIPs{} // Create a new ParseIPs, which is a []net.IP under the hood
	// Validate IP ranges in c.Scope.IP
	for _, ipRange := range c.Scope.IP {
		if err := parseIPs.parseRange(ipRange); err != nil {
			return err
		}
	}

	// append parseIPs (which is a []net.IP) to c.Scope.IP
	c.Scope.Addresses = append(c.Scope.Addresses, parseIPs...)

	loads := []func(cfg *Config) error{
		c.loadAlterationSettings,
		c.loadBruteForceSettings,
		c.loadDatabaseSettings,
		c.loadDataSourceSettings,
		c.loadResolverSettings,
	}
	for _, load := range loads {
		if err := load(c); err != nil {
			return err
		}
	}

	return nil
}

// Creates a file path that is relative the the configuration file location.
// If the path is already absolute, return it as is.
func (c *Config) AbsPathFromConfigDir(path string) (string, error) {
	// If the path is already absolute, return it as is
	if filepath.IsAbs(path) {
		// Check if the file exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %v", err)
		}

		return path, nil
	}

	// Get the directory of the current config file
	cfgDir := filepath.Dir(c.Filepath)

	// Clean the incoming path to ensure it doesn't have any problematic elements
	cleanPath := filepath.Clean(path)

	// Construct the absolute path by joining the config directory and the relative path
	absPath := filepath.Join(cfgDir, cleanPath)

	// Check if the file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %v", err)
	}

	return absPath, nil
}
func (s *Scope) toCIDRs(strings []string) []*net.IPNet {
	cidrs := make([]*net.IPNet, len(strings))
	for i, str := range strings {
		_, cidr, _ := net.ParseCIDR(str)
		cidrs[i] = cidr
	}
	return cidrs
}

// AcquireConfig populates the Config struct provided by the Config argument.
func AcquireConfig(dir, file string, cfg *Config) error {
	var path, dircfg, syscfg string

	cfg.Filepath = OutputDirectory(dir)
	if finfo, err := os.Stat(cfg.Filepath); cfg.Filepath != "" && !os.IsNotExist(err) && finfo.IsDir() {
		dircfg = filepath.Join(cfg.Filepath, defaultCfgFile)
	}

	if runtime.GOOS != "windows" {
		syscfg = filepath.Join(filepath.Join(systemCfgDir, outputDirName), defaultCfgFile)
	}

	if file != "" {
		path = file
	} else if f, set := os.LookupEnv(cfgEnvironVar); set {
		path = f
	} else if _, err := os.Stat(dircfg); err == nil {
		path = dircfg
	} else if _, err := os.Stat(syscfg); err == nil {
		path = syscfg
	}

	return cfg.LoadSettings(path)
}

// OutputDirectory returns the file path of the Amass output directory. A suitable
// path provided will be used as the output directory instead.
func OutputDirectory(dir ...string) string {
	if len(dir) > 0 && dir[0] != "" {
		return dir[0]
	}

	if path, err := os.UserConfigDir(); err == nil {
		return filepath.Join(path, outputDirName)
	}

	return ""
}

// GetListFromFile reads a wordlist text or gzip file and returns the slice of words.
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("error opening the file %s: %v", absPath, err)
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("error reading the first 512 bytes from %s: %s", absPath, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("error rewinding the file %s: %s", absPath, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("error gz-reading the file %s: %v", absPath, err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	s, err := getWordList(reader)
	return s, err
}

func getWordList(reader io.Reader) ([]string, error) {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" {
			words = append(words, w)
		}
	}
	return stringset.Deduplicate(words), nil
}
