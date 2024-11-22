package dns

import (
	"context"
	"fmt"
	"github.com/Method-Security/osintscan/internal/util"
	"log"
	"net"
	"sync"
	"time"
)

// BruteSubdomainsEnumReport represents the report of all subdomains for a given domain including all non-fatal errors that occurred.
type BruteSubdomainsEnumReport struct {
	RecordsReports []RecordsReport `json:"reports" yaml:"reports"`
}

type enumerationTask struct {
	domain   string
	depth    int
	wordlist *[]string
	timeout  time.Duration
}

// GetBruteForceSubdomains queries subdomains for a given domain.
// It returns a BruteSubdomainsEnumReport struct containing all subdomains and any errors that occurred.
func GetBruteForceSubdomains(
	ctx context.Context,
	domain string,
	wordlistFile string,
	numThreads int,
	requestTimeout time.Duration,
	maxRecursionDepth int) (BruteSubdomainsEnumReport, error) {
	errors := []string{}

	// Get all valid subdomains
	subdomains, err := getBruteForceSubdomains(ctx, domain, wordlistFile, numThreads, requestTimeout, maxRecursionDepth)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Create report
	report := BruteSubdomainsEnumReport{
		RecordsReports: subdomains,
	}

	return report, nil
}

func getBruteForceSubdomains(ctx context.Context, domain string, wordlistFile string, numThreads int, requestTimeout time.Duration, maxRecursionDepth int) ([]RecordsReport, error) {
	wordlist, err := util.LoadWordlist(wordlistFile)
	if err != nil {
		return nil, err
	}

	tasks := make(chan enumerationTask, 10000) // Adjust the buffer size as needed
	results := make(chan RecordsReport, 10000)
	var mu sync.Mutex
	var found []RecordsReport
	var workerWg sync.WaitGroup // WaitGroup for workers
	var taskWg sync.WaitGroup   // WaitGroup for tasks

	// Start workers
	for i := 0; i < numThreads; i++ {
		workerWg.Add(1)
		go worker(ctx, tasks, results, &workerWg, &taskWg)
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
	tasks <- enumerationTask{domain: domain, depth: maxRecursionDepth, wordlist: &wordlist, timeout: requestTimeout}

	// Close tasks channel when all tasks are done
	go func() {
		taskWg.Wait()
		close(tasks)
	}()

	// Wait for workers to finish
	workerWg.Wait()
	close(results) // Close results when workers are done
	return found, err
}

func worker(ctx context.Context, tasks chan enumerationTask, results chan<- RecordsReport, workerWg *sync.WaitGroup, taskWg *sync.WaitGroup) {
	defer workerWg.Done()
	for {
		select {
		case <-ctx.Done():
			log.Printf("Enumeration timed out")
			taskWg.Done()
			return
		case task, ok := <-tasks:
			if !ok {
				return
			}

			processTask(ctx, taskWg, task, tasks, results)
		}
	}
}

func processTask(ctx context.Context, taskWg *sync.WaitGroup, task enumerationTask, tasks chan<- enumerationTask, results chan<- RecordsReport) {
	defer taskWg.Done()
	if task.depth == 0 {
		return
	}
	for _, word := range *task.wordlist {
		select {
		case <-ctx.Done():
			log.Printf("Enumeration timed out")
			return
		default:
		}

		subdomain := fmt.Sprintf("%s.%s", word, task.domain)
		report, err := validateSubdomain(ctx, subdomain, task.timeout)
		if err != nil {
			continue
		}

		// Send the result
		results <- report

		// Add a new task for the subdomain
		taskWg.Add(1)
		select {
		case <-ctx.Done():
			log.Printf("Enumeration timed out")
			taskWg.Done()
			return
		case tasks <- enumerationTask{
			domain:   subdomain,
			depth:    task.depth - 1,
			wordlist: task.wordlist,
			timeout:  task.timeout,
		}:
		}
	}
}

// Validate if a subdomain resolves
func validateSubdomain(ctx context.Context, domain string, timeout time.Duration) (RecordsReport, error) {
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver := net.Resolver{}
	_, err := resolver.LookupHost(queryCtx, domain)
	if err != nil {
		return RecordsReport{}, err
	}

	records, _ := GetDomainDNSRecords(ctx, domain)
	return records, nil
}
