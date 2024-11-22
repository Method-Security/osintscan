package dns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// BruteSubdomainsEnumReport represents the report of all subdomains for a given domain including all non-fatal errors that occurred.
type BruteSubdomainsEnumReport struct {
	RecordsReports []RecordsReport `json:"reports" yaml:"reports"`
}

func getBruteForceSubdomains(ctx context.Context, domain string, wordlistFile string, numThreads int, timeoutSeconds int, maxEnumerationMinutes int, maxRecursionDepth int) ([]RecordsReport, error) {
	wordlist, err := loadWordlist(wordlistFile)
	if err != nil {
		return nil, err
	}

	subdomains := startEnumeration(ctx, domain, wordlist, maxRecursionDepth, numThreads)

	return subdomains, err
}

func startEnumeration(ctx context.Context, rootDomain string, wordlist []string, maxDepth, numWorkers int) []RecordsReport {
	tasks := make(chan enumerationTask, 10000) // Adjust the buffer size as needed
	results := make(chan RecordsReport, 10000)
	var mu sync.Mutex
	var found []RecordsReport
	var wg sync.WaitGroup     // WaitGroup for workers
	var taskWg sync.WaitGroup // WaitGroup for tasks

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, tasks, results, &wg, &taskWg)
	}

	// Collect results
	go func() {
		for result := range results {
			mu.Lock()
			found = append(found, result)
			mu.Unlock()
		}
	}()

	// Submit the initial task
	taskWg.Add(1)
	tasks <- enumerationTask{domain: rootDomain, depth: maxDepth, wordlist: &wordlist}

	// Close tasks channel when all tasks are done
	go func() {
		taskWg.Wait()
		close(tasks)
	}()

	// Wait for workers to finish
	wg.Wait()
	close(results) // Close results when workers are done

	return found
}

type enumerationTask struct {
	domain   string
	depth    int
	wordlist *[]string
}

func worker(ctx context.Context, tasks chan enumerationTask, results chan<- RecordsReport, wg *sync.WaitGroup, taskWg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case t, ok := <-tasks:
			if !ok {
				return // Tasks channel closed
			}

			// Ensure taskWg.Done() is called exactly once per task
			func(t enumerationTask) {
				defer taskWg.Done()

				if t.depth == 0 {
					return
				}

				// Process the task
				for _, word := range *t.wordlist {
					select {
					case <-ctx.Done():
						return
					default:
					}

					subdomain := fmt.Sprintf("%s.%s", word, t.domain)
					report, err := validateSubdomain(ctx, subdomain)
					if err != nil {
						continue
					}

					results <- report

					taskWg.Add(1)
					tasks <- enumerationTask{domain: subdomain, depth: t.depth - 1, wordlist: t.wordlist}
				}
			}(t)

		case <-ctx.Done():
			return
		}
	}
}

// Validate if a subdomain resolves
func validateSubdomain(ctx context.Context, domain string) (RecordsReport, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolver := net.Resolver{}
	_, err := resolver.LookupHost(queryCtx, domain)
	if err != nil {
		return RecordsReport{}, err
	}

	records, _ := GetDomainDNSRecords(ctx, domain)
	return records, nil
}

func loadWordlist(wordlistPath string) ([]string, error) {
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

// GetBruteForceDomainSubdomains queries subdomains for a given domain.
// It returns a BruteSubdomainsEnumReport struct containing all subdomains and any errors that occurred.
func GetBruteForceDomainSubdomains(
	ctx context.Context,
	domain string,
	wordlistFile string,
	numThreads int,
	timeoutSeconds int,
	maxEnumerationMinutes int,
	maxRecursionDepth int) (BruteSubdomainsEnumReport, error) {
	errors := []string{}

	// Get all valid subdomains
	subdomains, err := getBruteForceSubdomains(ctx, domain, wordlistFile, numThreads, timeoutSeconds, maxEnumerationMinutes, maxRecursionDepth)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Create report
	report := BruteSubdomainsEnumReport{
		RecordsReports: subdomains,
	}
	return report, nil
}
