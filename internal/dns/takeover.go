package dns

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	osintscan "github.com/Method-Security/osintscan/generated/go"
)

func DetectDomainTakeover(targets []string, setHTTP bool, timeout int) (*osintscan.DomainTakeoverReport, error) {
	resources := osintscan.DomainTakeoverReport{}
	errs := []string{}

	httpClient := createHTTPClient(setHTTP, timeout)

	fingerprints, err := retrieveFingerprints()
	if err != nil {
		return &resources, err
	}

	var takeoverResults []*osintscan.DomainTakeover
	for _, target := range targets {

		responseBody, statusCode, serviceResults, err := assessTarget(target, httpClient, fingerprints)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		takeoverResult := osintscan.DomainTakeover{
			Target:       target,
			Services:     serviceResults,
			ResponseBody: &responseBody,
			StatusCode:   &statusCode,
		}
		takeoverResults = append(takeoverResults, &takeoverResult)
	}

	resources.DomainTakeovers = takeoverResults
	resources.Errors = errs
	return &resources, nil
}

func isURLValid(URL string) bool {
	_, err := url.ParseRequestURI(URL)
	return err == nil
}

func createHTTPClient(setHTTP bool, timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !setHTTP},
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}
}

func retrieveFingerprints() ([]osintscan.Fingerprint, error) {
	var fingerprints []osintscan.Fingerprint

	absPath, err := filepath.Abs("configs/fingerprints.json")
	if err != nil {
		return nil, err
	}

	file, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(file, &fingerprints)
	if err != nil {
		return nil, err
	}

	return fingerprints, nil
}

func assessTarget(target string, client *http.Client, fingerprints []osintscan.Fingerprint) (string, int, []*osintscan.Service, error) {
	url := target
	if !isURLValid(url) {
		url = fmt.Sprintf("https://%s", target)
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", 0, nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, nil, err
	}

	err = resp.Body.Close()
	if err != nil {
		return "", 0, nil, err
	}

	statusCode := resp.StatusCode
	body := string(bodyBytes)

	return body, statusCode, analyzeResponse(body, fingerprints), nil
}

func analyzeResponse(body string, fingerprints []osintscan.Fingerprint) []*osintscan.Service {
	var serviceResults []*osintscan.Service
	for _, fp := range fingerprints {
		serviceResult := osintscan.Service{
			Name:        fp.Service,
			Fingerprint: fp.Fingerprint,
			Vulnerable:  isVulnerability(body, fp),
		}
		serviceResults = append(serviceResults, &serviceResult)
	}
	return serviceResults
}

func isVulnerability(body string, fp osintscan.Fingerprint) bool {
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
