
# PCAP-Based Port Scan Detector

A Python-based network security detection project that analyzes
TCP SYN traffic from PCAP files, identifies potential port scanning,
and applies an approved-scanner policy to security findings.

## Features

- Offline PCAP analysis using Tshark
- Fast port-scan detection
- Long-window port-scan detection
- Traffic episode grouping
- Multiple detections within an episode
- Alert cooldown and evidence-based correlation
- Approved-scanner policy evaluation
- JSON security alerts and audit records
- Automated unit tests

## Detection Rules

| Rule | Threshold | Window |
|------|-----------|--------|
| FAST_PORT_SCAN | 10 unique ports | 10 seconds |
| LONG_WINDOW_PORT_SCAN | 20 unique ports | 600 seconds |

Traffic episodes are separated by 300 seconds of inactivity.

## Requirements

- Python 3
- Tshark (Wireshark command-line tools)

## Usage

Run the detector:

```bash
python3 detector.py
```

Run the tests:

```bash
python3 -m unittest discover -v
```

The detector reads `soc001-portscan.pcap` and generates:

- `alerts.json` — findings requiring investigation
- `audit.json` — findings classified as approved activity

## Lab Environment

- Scanner: Kali Linux
- Target: Ubuntu Linux
- Network: Isolated VirtualBox lab
- Scanner IP: 192.168.56.10
- Target IP: 192.168.56.50

The traffic was generated through authorized testing
inside the isolated lab.

## Validation

The original PCAP contained 21 distinct TCP destination ports
for one source/destination pair.

The detector identified a fast port scan and classified the
finding as approved activity under the configured lab policy.

The automated test suite contains 20 passing tests.

## Security Considerations

Approval is based on source IP, destination IP, and UTC time.

These checks do not prove scanner identity or guarantee that
the activity is benign.

An attacker controlling an approved scanner could produce
traffic that matches the approval policy.

## Known Limitations

- Offline PCAP analysis only; no live capture
- IPv4 TCP SYN traffic only
- Fixed detection thresholds and cooldowns
- Simplified evidence-based correlation
- No authentication or attestation of approved scanners
- No process-level or user-level attribution
- No SIEM integration
- Hardcoded PCAP and output filenames
- No support for overnight or date-specific approval windows
- Detection is heuristic and may produce false positives
  or miss low-rate scanning

## Future Improvements

- Command-line arguments and configurable rules
- SIEM integration
- Live traffic monitoring
- Better correlation and deduplication
- Enrichment with endpoint and authentication logs
- Structured logging and error handling

## Ethical Use

This project is intended for defensive security education,
authorized monitoring, and controlled laboratory testing.
