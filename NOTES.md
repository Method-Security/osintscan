## Performance

Though I didn't confirm this with something like a flame graph, it seems
obvious enough that the bottleneck here is going to be network
requests to a DNS server. The code includes the following performance
considerations in an attempt to address this.

* The obvious/necessary improvement is to parallelize these requests. The
  code processes the words in the wordlist concurrently using a configurable
  number of concurrent goroutines (defaults to 10).
* If network requests are a bottleneck, then we want to make as few of them
  as possible. To that effect, since each DNS record type is checked in a
  separate request, we only check for A, AAAA, and CNAME records. While this
  may cause us to miss mail servers and name servers, we improve performance
  significantly by not checking MX, NS, or TXT records. This seems like an
  accepted practice based on the Sublist3r and DNSRecon code.
* One could take the above a step further by short-circuiting if we get a
  hit, e.g., if the request for an A record comes back positive, then we
  don't need to check the other record types. However, I decided not
  to do this because we're primarily dealing with negative hits anyway, so
  making the positives slightly faster only has a marginal impact in my mind.

## Misc

* There's a potentially nicer version of this where we update `subenum.go`
  to list subdomains using either the current method (passive enumeration
  via subfinder) or brute force dictionary enumeration based on a flag.
  However, messing with the existing code as little as possible seemed better
  for a weekend project where readability of the resulting PR is important.
* The default DNS resolvers from the dnsx client are used since the writeup
  indicated (I think) that letting the user specify resolvers was optional.
  Could update to allow custom resolvers if needed.

## Testing

The below are a handful of test results meant to validate some of the
functionality. The local DNS cache is cleared between runs.

### Parallelism

Running `/osintscan dns brutesubenum --domain google.com --wordlist /home/steven/git/osintscan/configs/wordlists/deepmagic.com-prefixes-top500.txt --threads 1`
returns 14 subdomains and 33 DNS records in 3 minutes and 6 seconds.
Updating the thread count to 10 (the default) returns the same number of
records and subdomains in 22 seconds.

### Recursion

Running `osintscan dns brutesubenum --domain google.com --wordlist /home/steven/git/osintscan/configs/wordlists/deepmagic.com-prefixes-top500.txt --threads 10 --max-recursive-depth 2`
returns 541 subdomains and 1641 DNS records in 5 minutes and 31 seconds.
The math checks out since we should run the wordlist 15 total times (once
initially and then once for each of the 14 subdomains from the first pass),
and that's about 15 times as long as the 22 seconds from the initial run.
The output includes values of the form `a.google.com` and of the form
`a.b.google.com`.

### Performance

This is hard to evaluate, as I'm not sure what would be considered good.
Timings on my laptop for different wordlist lengths, all at 10 threads, a
recursion depth of 1, and using `google.com` as the input domain are:

* 22 seconds for 500 words
* about 38 minutes for 50k words (makes sense, this is roughly 22 seconds
  multiplied by 100)
