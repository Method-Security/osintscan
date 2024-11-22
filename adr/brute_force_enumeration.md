Brute Force Enumeration
=======================

Goals
-----
Core Functionality:
  - Given an input domain, e.g. example.com, check the subdomains specified by the words in the input word list (e.g. a.example.com, b.example.com) against DNS resolvers
  - Recursively search domains (e.g. x.a.example.com) if recursive depth is specified and is more than 1
  - Output those domains that are found, as defined as there being an answer in DNS with a set of records and ownership pertaining to the domain

Command Structure:
  -  osintscan dns brutesubenum --domain [example.com](<http://example.com/>)

Features:
  - Support for reading wordlists from files
  - Support for accepting a wordlist as a comma-separated string arg
  - High throughput -- the more efficiently we can utilize our available network and computing resources,
the more subdomains we can enumerate in any given period.


Basic Approach
--------
I've written task and worker abstractions. A configurable pool of workers receive tasks from a channel, execute them,
and publish results to another channel. A task is recursive in nature -- it involves checking subdomains of a particular
domain and, if there are results, reporting those results and submitting a task for each resulting subdomain.

The results are collected at the end and published in a report.

Considerations
--------------

Concurrency
  - What should the concurrency model be? 
    - The big cost here is network latency. We do almost no computation on results, but we do need to fetch all of the
    results from remote DNS servers. We want to make all of our network calls asynchronously so that we dont
    spend a bunch of time busy-waiting on network results.
    - How do we get asynchrony? 
      - As far as I can tell, the easiest way to do this in Go is with goroutines. These are lightweight user-mode
      threads multiplexed by the go runtime scheduler onto a fixed number of OS threads. The runtime scheduler handles
      interrupts/context-switching for us so we don't have to thing about async/await constructs. Neat!
    - How do we control concurrency?
      - The go runtime assigns a max number of OS threads to the scheduler pool based on the GOMAXPROCS environment
      variable. This defaults to the number of logical cores on the system [(go docs)](https://pkg.go.dev/runtime#GOMAXPROCS).

What information do we need?
  - I've opted for exhaustive dns information via the existing [records.go](./internal/dns/records.go)#GetDomainDNSRecords.
    - There is an opportunity for further optimization here because we might not need all of this information for each
    record. 


Results
-------

Performance:
  - Make sure we clear the dns cache between all runs. 
  - Kind of hard to measure for a couple of reasons:
    - DNS providers will throttle you after some point, so no matter how many threads you throw at a problem,
    if you're not multiplexing your requests across several providers, you will eventually exhaust your rate limits. 
    - DNS caches at multiple levels of the hierarchy, so even if you wipe your local DNS cache, the performance of
    individual requests will be better for subsequent repetitions until/unless the results are evicted from the DNS
    hierarchy. This is just kind of unavoidable, so we have to keep that context in mind. 
    - Without something to compare against, it's hard to say what "good" looks like.
      - However, we can take some absolute numbers:
        - /Users/jcasale/projects/method/osintscan/out/build/osintscan/0.0.4-3-g21a0f28.dirty/darwin-arm64/osintscan dns brutesubenum --output yaml --domain google.com --wordlist-file configs/enumeration/subdomains-top1mil-500.txt --max-recursion-depth 2 --workers 200 --max-enum-minutes 5000
          - started_at: "2024-11-22T13:32:44.131774Z"
          - completed_at: "2024-11-22T13:36:58.777503Z"
          - total time: ~4m 14s
        -
      - And we can additionally verify that we are seeing the sort of scaling we would expect with additional workers:
        - Using top 200 and recursion depth 2:
          - 1 worker: 7m 21s
          - 2 workers: ~3m 17s
          - 5 workers: ~1m 47s
          - 10 workers: ~1m 15s
          - 20 workers: ~1m 2s
          - 40 workers: ~1m 3s
          
        - Observations:
          - Roughly linear scaling from 1 to 5 workers.
          - Less-than-linear scaling from 5 to 10 to 20+.
          - My suspicion here is that I'm hitting DNS rate limits somewhere between 5 and 20 workers, which is why
          throwing extra workers at the problem doesn't help after that point.
Other:
  - Since I saw throttling relatively quickly, I did not test super-high-scale wordlists. I've included them anyway, so
  that when I add some DNS provider-multiplexing functionality we have some higher-scale lists to test on.


Open Questions
--------------
- Am I being throttled by my dns provider?
  - I didn't really have time to dig too deeply into this, but I do see a hard ceiling on perf for my implementation at
  - at some point, regardless of how many workers I throw at it. I suspect that I'm hitting DNS rate limits. My next
  goal would be to verify this and to build a DNS fetching/verification mechanism that can multiplex requests across a
  a variety of DNS providers to maximize my throughput.
- Am I doing error handling right? In Rust we return a result that is either a value or an error. This is pretty
straightforward. In java, we return a result or we throw -- again, somewhat straightforward. In go, it seems like
we generally return a result and an error, and generally exactly one of these will be valid, but there's no guarantee of that.

  - It feels like I've misunderstood this mechanic and I'm doing something wrong; it seems dangerous to rely on
  the caller to check both of these values and then handle 4 separate cases ((val present, error present),
  (val absent, error present), (val absent, err absent), (val present, error absent)) instead of calls either being
  successful or failed.
- Testing
  - There wasn't any testing set up in this project, so I did my testing manually. Not ideal, but not a blocker either.
  My next priority would be to set up some testing, because it makes development quicker & easier. When I was debugging
  some issues with my concurrency setup, some testing would have made it easier to reason about the failures.


Miscellaneous
-------------
- Go style
  - I tried to mimic existing conventions, but it's totally possible that I've got some style issues here. Took a
  quick read of the style guide for thinks like function naming conventions, but I've never written go before so I might
  have gotten some of the style stuff wrong.
- Concurrency
  - Go's concurrency model took a bit of getting used to because it introduces named abstractions that map very closely
    onto concurrency primitives (e.g. work groups vs semaphores). This isn't a big deal, but it tripped me up a little at
    initially. It's easy to increment a work group without remembering to decrement it later, which is something that
    would set off alarm bells in my head for a semaphore, but for some reason didn't initially send up red flags in my brain.
  - Context deadlines
    - This is a really cool abstraction. I absentmindedly set the workers to check for context timeouts IN ADDITION
    to tasks checking for context timeouts and that caused a nasty race conditions. Live and learn.