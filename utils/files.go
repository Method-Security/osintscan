package utils

import (
	"bufio"
	"fmt"
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
		lines, err := readLinesFromFile(absPath)
		if err != nil {
			return nil, err
		}
		entries = append(entries, lines...)
	}
	return entries, nil
}

func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("error reading %s: %w", path, err)
	}
	err = file.Close()
	if err != nil {
		return nil, err
	}
	return lines, nil
}
