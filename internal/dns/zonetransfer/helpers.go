package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	osintscan "github.com/Method-Security/osintscan/generated/go"
)

func sendAXFRRequest(ns, domain string, timeout int, maxJumps int) ([]*osintscan.DnsZoneTransferRecord, bool, []string) {
	errors := []string{}
	addr := net.JoinHostPort(ns, "53")
	fmt.Printf("[Debug] Attempting to connect to %s\n", addr)

	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Printf("[Error] Failed to connect to %s: %v\n", ns, err)
		errors = append(errors, fmt.Sprintf("failed to connect to %s: %v", ns, err))
		return nil, false, errors
	}
	fmt.Printf("[Debug] Connection established with %s\n", ns)

	request, buildErrors := buildAXFRRequest(domain)
	errors = append(errors, buildErrors...)

	err = binary.Write(conn, binary.BigEndian, uint16(len(request)))
	if err != nil {
		fmt.Printf("[Error] Failed to write request length: %v\n", err)
		errors = append(errors, fmt.Sprintf("failed to write request length: %v", err))
		return nil, false, errors
	}

	_, err = conn.Write(request)
	if err != nil {
		fmt.Printf("[Error] Failed to send AXFR request to %s: %v\n", ns, err)
		errors = append(errors, fmt.Sprintf("failed to send request to %s: %v", ns, err))
		return nil, false, errors
	}
	fmt.Printf("[Debug] Sent AXFR request to %s\n", ns)

	var records []*osintscan.DnsZoneTransferRecord
	var axfrSuccessful bool
	var hasValidRecords bool

	for {
		var length uint16
		err := binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("[Debug] Connection closed on %s (end of transfer)\n", ns)
			} else {
				fmt.Printf("[Error] Failed to read message length from %s: %v\n", ns, err)
				errors = append(errors, fmt.Sprintf("failed to read message length from %s: %v", ns, err))
			}
			break
		}

		response := make([]byte, length)
		_, err = io.ReadFull(conn, response)
		if err != nil {
			fmt.Printf("[Error] Failed to read response from %s: %v\n", ns, err)
			errors = append(errors, fmt.Sprintf("failed to read response from %s: %v", ns, err))
			return nil, false, errors
		}

		newRecords, valid, decodeErrors := decodeDNSMessage(response, maxJumps)
		errors = append(errors, decodeErrors...)
		if valid && len(newRecords) > 0 {
			records = append(records, newRecords...)
			hasValidRecords = true
		}

		axfrSuccessful = true
	}

	err = conn.Close()
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to close connection to %s: %v", ns, err))
	}

	if axfrSuccessful && hasValidRecords {
		fmt.Printf("[Debug] Zone transfer successful on %s with %d records\n", ns, len(records))
		return records, true, errors
	}

	return records, false, errors
}

func buildAXFRRequest(domain string) ([]byte, []string) {
	errors := []string{}
	var buf bytes.Buffer

	header := osintscan.DnsQueryHeader{
		Id:      0x1234,
		Flags:   0x0100,
		QdCount: 1,
		AnCount: 0,
		NsCount: 0,
		ArCount: 0,
	}

	// Write header fields
	if err := binary.Write(&buf, binary.BigEndian, uint16(header.Id)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write header ID: %v", err))
		return nil, errors
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(header.Flags)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write header flags: %v", err))
		return nil, errors
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(header.QdCount)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write question count: %v", err))
		return nil, errors
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(header.AnCount)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write answer count: %v", err))
		return nil, errors
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(header.NsCount)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write authority count: %v", err))
		return nil, errors
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(header.ArCount)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write additional count: %v", err))
		return nil, errors
	}

	// Write domain name in DNS format
	domainParts := strings.Split(domain, ".")
	for _, part := range domainParts {
		if len(part) > 0 {
			buf.WriteByte(byte(len(part)))
			buf.WriteString(part)
		}
	}
	buf.WriteByte(0) // Terminating zero length

	// QTYPE (16 bits) - AXFR = 252
	if err := binary.Write(&buf, binary.BigEndian, uint16(252)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write AXFR type: %v", err))
		return nil, errors
	}

	// QCLASS (16 bits) - IN = 1
	if err := binary.Write(&buf, binary.BigEndian, uint16(1)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to write IN class: %v", err))
		return nil, errors
	}

	fmt.Printf("[Debug] Built AXFR request for %s\n", domain)
	return buf.Bytes(), errors
}

func decodeDNSMessage(data []byte, maxJumps int) ([]*osintscan.DnsZoneTransferRecord, bool, []string) {
	errors := []string{}
	var records []*osintscan.DnsZoneTransferRecord

	if len(data) < 12 {
		errors = append(errors, "data is too short to be a valid DNS message")
		return nil, false, errors
	}

	// Read header values individually instead of using binary.Read with struct
	_ = binary.BigEndian.Uint16(data[0:2])
	_ = binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])
	nsCount := binary.BigEndian.Uint16(data[8:10])
	arCount := binary.BigEndian.Uint16(data[10:12])

	totalRecords := int(anCount + nsCount + arCount)
	if totalRecords == 0 {
		return nil, false, append(errors, "no records in DNS message")
	}

	// Skip past the question section
	offset := 12 // Header size
	for i := 0; i < int(qdCount); i++ {
		// Skip the question name
		for offset < len(data) {
			length := int(data[offset])
			if length == 0 {
				offset++
				break
			}
			if length >= 192 { // Compression pointer
				offset += 2
				break
			}
			offset += length + 1
		}

		// Skip QTYPE and QCLASS (4 bytes)
		if offset+4 <= len(data) {
			offset += 4
		} else {
			errors = append(errors, "question section truncated")
			return nil, false, errors
		}
	}

	// Process answer, authority, and additional records
	for i := 0; i < totalRecords && offset < len(data); i++ {
		record, newOffset, valid, decodeErrors := decodeResourceRecord(data, offset, maxJumps)
		errors = append(errors, decodeErrors...)

		if valid && record != nil {
			records = append(records, record)
		}
		if newOffset <= offset {
			errors = append(errors, "parsing error: record offset did not advance")
			break
		}
		offset = newOffset
	}

	if len(records) > 0 {
		return records, true, errors
	}

	return nil, false, errors
}

func decodeResourceRecord(data []byte, offset int, maxJumps int) (*osintscan.DnsZoneTransferRecord, int, bool, []string) {
	errors := []string{}

	if offset >= len(data) {
		return nil, offset, false, append(errors, "offset out of bounds")
	}

	// Read the name
	name, newOffset, nameErrors := decodeDomainName(data, offset, maxJumps)
	errors = append(errors, nameErrors...)
	offset = newOffset

	// Ensure we have enough data for the fixed part of the record
	if offset+10 > len(data) {
		return nil, offset, false, append(errors, "incomplete resource record")
	}

	// Read TYPE, CLASS, TTL, RDLENGTH
	recordType := binary.BigEndian.Uint16(data[offset : offset+2])
	class := binary.BigEndian.Uint16(data[offset+2 : offset+4])
	ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
	rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
	offset += 10

	// Ensure we have enough data for the record data
	if offset+int(rdLength) > len(data) {
		return nil, offset, false, append(errors, "resource data length exceeds message bounds")
	}

	// Process the record based on its type
	var recordValue string
	var recordTypeEnum osintscan.DnsRecordEnum
	valid := true

	switch recordType {
	case 1: // A record
		if rdLength != 4 {
			errors = append(errors, fmt.Sprintf("unexpected RDLENGTH %d for A record", rdLength))
			valid = false
		} else {
			ip := net.IP(data[offset : offset+int(rdLength)])
			recordValue = ip.String()
			recordTypeEnum = osintscan.DnsRecordEnumA
		}
	case 2: // NS record
		nsName, _, nsErrors := decodeDomainName(data, offset, maxJumps)
		errors = append(errors, nsErrors...)
		recordValue = nsName
		recordTypeEnum = osintscan.DnsRecordEnumNs
	case 5: // CNAME record
		cname, _, cnameErrors := decodeDomainName(data, offset, maxJumps)
		errors = append(errors, cnameErrors...)
		recordValue = cname
		recordTypeEnum = osintscan.DnsRecordEnumCname
	case 6: // SOA record
		mname, newOffset, soaErrors := decodeDomainName(data, offset, maxJumps)
		errors = append(errors, soaErrors...)

		rname, newOffset, soaErrors := decodeDomainName(data, newOffset, maxJumps)
		errors = append(errors, soaErrors...)
		if newOffset+20 <= len(data) {
			serial := binary.BigEndian.Uint32(data[newOffset : newOffset+4])
			refresh := binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8])
			retry := binary.BigEndian.Uint32(data[newOffset+8 : newOffset+12])
			expire := binary.BigEndian.Uint32(data[newOffset+12 : newOffset+16])
			minimum := binary.BigEndian.Uint32(data[newOffset+16 : newOffset+20])

			recordValue = fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minimum)
			recordTypeEnum = osintscan.DnsRecordEnumSoa
		} else {
			errors = append(errors, "incomplete SOA record")
			valid = false
		}
	case 15: // MX record
		if offset+2 <= len(data) {
			preference := binary.BigEndian.Uint16(data[offset : offset+2])
			exchange, _, mxErrors := decodeDomainName(data, offset+2, maxJumps)
			errors = append(errors, mxErrors...)

			recordValue = fmt.Sprintf("%d %s", preference, exchange)
			recordTypeEnum = osintscan.DnsRecordEnumMx
		} else {
			errors = append(errors, "incomplete MX record")
			valid = false
		}
	case 16: // TXT record
		if rdLength > 0 {
			txtLen := int(data[offset])
			if offset+1+txtLen <= len(data) && txtLen <= int(rdLength) {
				recordValue = string(data[offset+1 : offset+1+txtLen])
				recordTypeEnum = osintscan.DnsRecordEnumTxt
			} else {
				errors = append(errors, "incomplete TXT record")
				valid = false
			}
		} else {
			recordValue = ""
			recordTypeEnum = osintscan.DnsRecordEnumTxt
		}
	case 28: // AAAA record
		if rdLength != 16 {
			errors = append(errors, fmt.Sprintf("unexpected RDLENGTH %d for AAAA record", rdLength))
			valid = false
		} else {
			ip := net.IP(data[offset : offset+int(rdLength)])
			recordValue = ip.String()
			recordTypeEnum = osintscan.DnsRecordEnumAaaa
		}
	default:
		// Handle unknown record types
		recordValue = fmt.Sprintf("Unknown record type %d", recordType)
		valid = false
	}

	// Advance the offset past the record data
	offset += int(rdLength)

	ttlInt := int(ttl)
	classInt := int(class)
	if valid {
		return &osintscan.DnsZoneTransferRecord{
			Name:  name,
			Type:  recordTypeEnum,
			Ttl:   &ttlInt,
			Class: &classInt,
			Value: recordValue,
		}, offset, true, errors
	}

	return nil, offset, false, errors
}

func decodeDomainName(data []byte, offset int, maxJumps int) (string, int, []string) {
	errors := []string{}
	var parts []string
	originalOffset := offset

	// Prevent infinite loops from malformed packets
	jumps := 0

	for offset < len(data) {
		length := int(data[offset])

		// Check for compression pointer (first two bits are set)
		if length >= 192 {
			if offset+1 >= len(data) {
				return "", originalOffset, append(errors, "incomplete compression pointer")
			}

			// Compression pointer is 14 bits from the two bytes
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF

			// Ensure we don't follow too many pointers
			jumps++
			if jumps > maxJumps {
				return "", originalOffset, append(errors, "too many compression pointer jumps")
			}

			// Follow the pointer
			if pointer >= len(data) {
				return "", originalOffset, append(errors, "compression pointer out of bounds")
			}

			// If we're following a pointer, we'll return the original offset + 2 (the size of a pointer)
			if jumps == 1 {
				originalOffset = offset + 2
			}

			offset = pointer
			continue
		}

		// End of the domain name
		if length == 0 {
			offset++
			break
		}

		// Regular label
		if offset+1+length > len(data) {
			return "", originalOffset, append(errors, "domain name label length exceeds message bounds")
		}

		parts = append(parts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}

	// If we didn't follow any pointers, update the original offset
	if jumps == 0 {
		originalOffset = offset
	}

	return strings.Join(parts, "."), originalOffset, errors
}
