package util

import (
	"bufio"
	"fmt"
	"os"
)

func LoadWordlist(wordlistPath string) ([]string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("could not open wordlist: %w", err)
	}
	defer file.Close()

	var wordlist []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordlist = append(wordlist, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}
	return wordlist, nil
}
