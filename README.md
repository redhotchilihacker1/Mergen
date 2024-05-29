# Mergen

Mergen is a web scanning tool to conduct basic recon steps and identify several vulnerabilites during your pentest process.

## How to Install

1-Clone the project:

```bash
git clone https://github.com/redhotchilihacker1/Mergen.git
```

2-Install required libraries:

```bash
pip install -r requirements.txt
```

## How to Use

There are several use cases of this.

You can either test a single domain:

```bash
python3 mergen.py -url https://example.com -all
```

Or you can test several domains by putting all in a file:

```bash
python3 mergen.py -file domains.txt -all
```

You can use several flags at one such as:

```bash
python3 mergen.py -url https://example.com -ssl -cookie -cors
```

## Parameters

options:
```bash
  -h, --help      show this help message and exit
  -url [URL ...]  URL of the website to be analyzed
  -file FILE      File containing URLs to be analyzed
  -cookie         Enable checking of cookie values
  -method         Check if HTTP DEBUG method is enabled
  -headers        Enable checking of security headers
  -ssl            Enable checking of SSL/TLS versions
  -tech           Identify web technologies used
  -social         Check social media links on the website
  -cors           Check for CORS vulnerabilities on the website
  -ports          Scan for popular ports
  -spf            Perform SPF policy check
  -dmarc          Perform DMARC policy check
  -cjacking       Perform clickjacking vulnerability check
  -all            Perform all checks
```

## Special Thanks

To our mascot cat Hashcat and her mother J,
To my gang lolo.txt,
To my beloved family members who supports me in every turn,

Love you all.

# Disclaimer

This project is purely for educational purposes, use at your own risk. I do not in any way encourage the illegal use of this software or attacking targets without prior authorization.
