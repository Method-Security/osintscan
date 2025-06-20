package utils

import (
	"bufio"
	"os"
	"path/filepath"
)

func GetEntriesFromFiles(paths []string) ([]string, error) {
	entries := []string{}
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		entries = append(entries, lines...)
	}
	return entries, nil
}

// GetDiscoverDNSSubdomainActiveWordlistPath returns the file path for a given wordlist size
func GetDiscoverDNSSubdomainActiveWordlistPath(wordlistSize string) string {
	wordlistPaths := map[string]string{
		"TINY":   "conf/discover/dns/subdomain/wordlist-100.txt",
		"SMALL":  "conf/discover/dns/subdomain/wordlist-5000.txt",
		"MEDIUM": "conf/discover/dns/subdomain/wordlist-20000.txt",
		"LARGE":  "conf/discover/dns/subdomain/wordlist-110000.txt",
	}

	return wordlistPaths[wordlistSize]
}
