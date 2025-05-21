# SpoofCheck

A Python tool to check if a domain can be spoofed by analyzing its SPF and DMARC records. This Project is a shameless rip off [spoofcheck](https://github.com/BishopFox/spoofcheck) which was written in python2.

This is my effort to make it compatible with python3.

- Analyzes SPF (Sender Policy Framework) records
- Checks DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies
- Identifies weak configurations that could allow email spoofing
- Examines organizational DMARC records



## Usage

```bash
python3 spoofcheck.py example.com
```

## What Makes a Domain Spoofable?

A domain is considered spoofable if any of these conditions are met:

1. No SPF record exists
2. SPF record exists but never specifies `~all` or `-all`
3. No DMARC record exists
4. DMARC policy is set to `p=none`
5. Organizational DMARC record is weak or nonexistent

## Setup

Run `pip3 install -r requirements.txt` from the command line to install the required dependencies.
