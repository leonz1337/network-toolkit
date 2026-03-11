# Multi-threaded Port Scanner

A fast, multi-threaded port scanner written in Python that can scan target IP addresses for open ports and retrieve service banners.
only for educational purposes

## Features

- Multi-threaded scanning for faster results
- Customizable port ranges
- Service banner grabbing
- Configurable thread count
- Simple command-line interface

## Prerequisites

- Python 3.x
- No external dependencies required (uses only standard library)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/leonz1337/network-toolkit.git
cd network-toolkit
```

2. Make the script executable (optional):
```bash
chmod +x scanner.py
```

## Usage

### Basic Syntax
```bash
python scanner.py -t <TARGET_IP>/<TARGET_DOMAIN>
```

### Examples

**Scan common ports (1-1024):**
```bash
python scanner.py -t 192.168.1.1

python scanner.py -t target.com

```

**Scan custom port range:**
```bash
python scanner.py -t 192.168.1.1 -p 1-65535
```

**Scan with custom thread count:**
```bash
python scanner.py -t 192.168.1.1 -p 1-5000 --threads 200
```

### Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target IP address or domain(required) | None |
| `--ports` | `-p` | Port range to scan (format: start-end) | 1-1024 |
| `--threads` | `-t` | Number of threads to use | 100 |

## Output Example

```
[*]Starting scan on 192.168.1.1 using threads...
[+]192.168.1.1:22 is OPEN with SSH-2.0-OpenSSH_8.2p1
[+]192.168.1.1:80 is OPEN with HTTP/1.1 200 OK
[+]192.168.1.1:443 is OPEN with 
[*]Finished Scanning....
```

## How It Works

1. The scanner creates a queue of ports to scan
2. Multiple threads simultaneously check ports from the queue
3. For each open port, it attempts to grab the service banner
4. Results are displayed in real-time with proper thread synchronization

## Limitations

- May be detected as malicious by IDS/IPS systems
- Banner grabbing might timeout on some services
- Only scans TCP ports (no UDP support)
- Requires appropriate permissions for scanning external targets

## Legal Disclaimer

This tool is for educational purposes and authorized testing only. Unauthorized scanning of networks or systems may be illegal. Always ensure you have explicit permission before scanning  any target.

## Author

leonz1337

## Version History

- 1.0.2: Initial release with basic functionality


## About me
Im leonz, and i am here for learning cybersecurity and create real world projects so if you intrested in it contact me in insta(@ynot.leonz) or in here
