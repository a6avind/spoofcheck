# spoofcheck

This Project is a shameless rip off [spoofcheck](https://github.com/BishopFox/spoofcheck) which was written in python2.

This is my effort to make it compatible with python3.

A program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing.

Additionally, it will alert if the domain has DMARC configuration that sends mail or HTTP requests on failed SPF/DKIM emails.

## Usage

`./spoofcheck.py [DOMAIN]`

Domains are spoofable if any of the following conditions are met:

- Lack of an SPF or DMARC record
- SPF record never specifies `~all` or `-all`
- DMARC policy is set to `p=none` or is nonexistent

## Dependencies

- `dnspython`
- `colorama`
- `py-emailprotections`
- `tldextract`

## Setup

Run `pip3 install -r requirements.txt` from the command line to install the required dependencies.
