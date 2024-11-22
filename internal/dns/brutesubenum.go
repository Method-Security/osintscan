package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const DefaultChannelBufferSize = 10000

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
// It returns a BruteSubdomainsEnumReport struct containing reports for all subdomains which include any errors that occurred.
func GetBruteForceSubdomains(
	ctx context.Context,
	domain string,
	wordlist *[]string,
	numWorkers int,
	requestTimeout time.Duration,
	maxRecursionDepth int) (BruteSubdomainsEnumReport, error) {

	subdomains := getBruteForceSubdomains(ctx, domain, wordlist, numWorkers, requestTimeout, maxRecursionDepth)

	report := BruteSubdomainsEnumReport{
		RecordsReports: subdomains,
	}

	return report, nil
}

func getBruteForceSubdomains(
	ctx context.Context,
	domain string,
	wordlist *[]string,
	numThreads int,
	requestTimeout time.Duration,
	maxRecursionDepth int) []RecordsReport {

	//NB: using a buffered channel so that sending new tasks does not block when there are no free workers

	tasks := make(chan enumerationTask, DefaultChannelBufferSize)
	results := make(chan RecordsReport, DefaultChannelBufferSize)
	var mu sync.Mutex
	var found []RecordsReport
	var workerWg sync.WaitGroup
	var taskWg sync.WaitGroup

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
	tasks <- enumerationTask{domain: domain, depth: maxRecursionDepth, wordlist: wordlist, timeout: requestTimeout}

	// Close tasks channel when all tasks are done
	go func() {
		taskWg.Wait()
		close(tasks)
	}()

	// Wait for workers to finish
	workerWg.Wait()
	close(results) // Close results when workers are done
	return found
}

func worker(ctx context.Context, tasks chan enumerationTask, results chan<- RecordsReport, workerWg *sync.WaitGroup, taskWg *sync.WaitGroup) {
	defer workerWg.Done()
	for {
		select {
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
			log.Printf("Enumeration timed out during task for domain: %s", task.domain)
			return
		default:
		}

		subdomain := fmt.Sprintf("%s.%s", word, task.domain)
		report, err := getRecordsReport(ctx, subdomain, task.timeout)
		if err != nil {
			continue
		}

		// Send the result
		results <- report

		// Add a new task for the subdomain
		taskWg.Add(1)
		select {
		case <-ctx.Done():
			log.Printf("Enumeration timed out during task for domain: %s", task.domain)
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

// TODO(@jcasale): learn more about error handling -- this pattern of passing back an empty struct alongside an
// error and relying on the caller to only use one of them feels weird and dangerous.
func getRecordsReport(ctx context.Context, domain string, timeout time.Duration) (RecordsReport, error) {
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
