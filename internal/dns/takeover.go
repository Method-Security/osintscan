package dns

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	dnsfern "github.com/Method-Security/osintscan/generated/go/dns"
)

func DetectDomainTakeover(targets []string, fingerprintsPath string, onlySuccessful bool, setHTTPS bool, timeout int) (*dnsfern.DomainTakeoverReport, error) {
	resources := dnsfern.DomainTakeoverReport{}
	errs := []string{}

	httpClient := createHTTPClient(setHTTPS, timeout)

	fingerprints, err := retrieveFingerprints(fingerprintsPath)
	if err != nil {
		return &resources, err
	}

	var takeoverResults []*dnsfern.DomainTakeover
	for _, target := range targets {
		var urlTargets []string

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			if setHTTPS {
				urlTargets = append(urlTargets, "https://"+target)
			} else {
				urlTargets = append(urlTargets, "http://"+target, "https://"+target)
			}
		} else {
			urlTargets = append(urlTargets, target)
		}

		for _, url := range urlTargets {
			domain, cname, err := retrieveCNAMERecord(url)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}

			responseBody, statusCode, serviceResults, successful, err := assessTarget(url, httpClient, fingerprints)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			if !onlySuccessful || successful {
				takeoverResult := dnsfern.DomainTakeover{
					Target:       url,
					ResponseBody: responseBody,
					StatusCode:   statusCode,
					Domain:       domain,
					Cname:        cname,
					Services:     serviceResults,
				}
				takeoverResults = append(takeoverResults, &takeoverResult)
			}
		}
	}

	resources.DomainTakeovers = takeoverResults
	resources.Errors = errs
	return &resources, nil
}

func createHTTPClient(setHTTPS bool, timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: setHTTPS},
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}
}

func retrieveFingerprints(fingerprintsPath string) ([]dnsfern.Fingerprint, error) {
	var fingerprints []dnsfern.Fingerprint

	absPath, err := filepath.Abs(fingerprintsPath)
	if err != nil {
		return nil, err
	}

	file, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(file, &fingerprints)
	if err != nil {
		return nil, errors.New("could not unmarshal fingerprint file")
	}

	return fingerprints, nil
}

func assessTarget(url string, client *http.Client, fingerprints []dnsfern.Fingerprint) (string, int, []*dnsfern.Service, bool, error) {

	resp, err := client.Get(url)
	if err != nil {
		return "", 0, nil, false, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, nil, false, err
	}

	err = resp.Body.Close()
	if err != nil {
		return "", 0, nil, false, err
	}

	statusCode := resp.StatusCode
	body := string(bodyBytes)
	serviceInfo, successful := analyzeResponse(body, fingerprints)
	return body, statusCode, serviceInfo, successful, nil
}

func analyzeResponse(body string, fingerprints []dnsfern.Fingerprint) ([]*dnsfern.Service, bool) {
	var serviceResults []*dnsfern.Service
	successful := false
	for _, fp := range fingerprints {
		isVulnerability := isVulnerability(body, fp)
		serviceResult := dnsfern.Service{
			Name:        fp.Service,
			Fingerprint: fp.Fingerprint,
			Vulnerable:  isVulnerability,
		}
		serviceResults = append(serviceResults, &serviceResult)
		successful = successful || isVulnerability
	}
	return serviceResults, successful
}

func isVulnerability(body string, fp dnsfern.Fingerprint) bool {
	if fp.Fingerprint != "" {
		re, err := regexp.Compile(fp.Fingerprint)
		if err != nil {
			return false
		}
		if re.MatchString(body) && !fp.NxDomain {
			return fp.Vulnerable
		}
	}
	return false
}

func retrieveCNAMERecord(url string) (string, string, error) {
	domain, err := getDomainFromURL(url)
	if err != nil {
		return "", "", err
	}

	cnameRecord, err := net.LookupCNAME(domain)
	if err != nil {
		return "", "", err
	}
	return domain, cnameRecord, nil
}

func getDomainFromURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	host := parsedURL.Host
	if strings.Contains(host, ":") {
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	}
	return host, nil
}
