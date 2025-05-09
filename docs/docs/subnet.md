# subnet

The `subnet` module provides OSINT scanning and enrichment of all IP addresses within a given IPv4 subnet. It performs reverse DNS lookups, RDAP/WHOIS queries, and ASN information gathering on every IP in the CIDR range.

---

## 🔍 Available Commands

### `research`

Perform a scan of a subnet and return discovered IP metadata including PTR records, WHOIS information, and ASN attribution.

---

## 🧪 Example Usage

```bash
# Basic scan
./osintscan subnet research --subnet 1.1.1.0/30

# Use a custom DNS resolver
./osintscan subnet research --subnet 8.8.8.0/24 --dns-resolver 1.1.1.1

# Display as a human-readable table
./osintscan subnet research --subnet 1.1.1.0/30 --table
```

---

## 📝 Options

| Flag | Type | Description |
|------|------|-------------|
| `--subnet`, `-s` | `string` | IPv4 subnet in CIDR notation (e.g. `192.0.2.0/24`) (**required**) |
| `--dns-resolver` | `string` | Optional custom DNS resolver IP (e.g. `8.8.8.8`) |
| `--table`, `-t` | `bool` | If specified, formats results as a user-friendly table |

---

## 📤 Output Format

By default, the output is returned via the global `--output` flag (e.g., `json`, `yaml`, `signal`). When using `--table`, results are printed in a clean, space-efficient format suitable for terminal inspection.

### Example Table Output:

```
Subnet: 1.1.1.0/30
-------------------------------------------------------------------------------------------------------
IP          PTR                                  ASN         Org                 Email                    
-------------------------------------------------------------------------------------------------------
1.1.1.0                                          13335       APNIC-LABS          research@apnic.net       
1.1.1.1     one.one.one.one.                     13335       APNIC-LABS          research@apnic.net       
1.1.1.2     security.cloudflare-dns.com.         13335       APNIC-LABS          research@apnic.net       
1.1.1.3     family.cloudflare-dns.com.           13335       APNIC-LABS          research@apnic.net 
```

### Example JSON Output:

```json
{
  "subnet": "1.1.1.0/30",
  "hosts": [
    {
      "ip": "1.1.1.1",
      "ptr": "one.one.one.one.",
      "asn": {
        "number": 13335,
        "name": "CLOUDFLARENET"
      },
      "whois": {
        "organization": "APNIC-LABS",
        "handle": "1.1.1.0 - 1.1.1.255",
        "country": "AU",
        "range": "1.1.1.0 - 1.1.1.255",
        "registrationDate": "2011-08-10T23:12:35Z",
        "contactEmail": "research@apnic.net"
      }
    }
  ]
}
```

---

## 🧰 Use Cases

- Identify misconfigured or unused IPs within corporate address space
- Discover legacy or shadow infrastructure
- Perform open-source threat attribution
- Enrich IP context for incident response or threat hunting

---

## 📎 Related Modules

- [`dns`](./dns.md): Query DNS records, zone transfers, subdomain enumeration, and takeover detection
- [`saas`](./saas.md): Discover SaaS service usage by analyzing login portals and headers

---
