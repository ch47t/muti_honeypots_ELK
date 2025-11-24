# Multi-Honeypot Platform with ELK Stack Analysis

A comprehensive cybersecurity project featuring multiple low-to-medium interaction honeypots (HTTP, SSH, FTP) integrated with the ELK Stack (Elasticsearch, Logstash, Kibana) for real-time log analysis and visualization. The project utilizes system hardening techniques like **AppArmor** profiles to secure the honeypot processes.

## Architecture

The platform consists of three distinct honeypot services running on a Linux environment (tested on Kali Linux):

1.  **HTTP Honeypot**: A Flask-based web application simulating a "NetOps | HTTP Header Inspector". It logs visitor data, POST requests, and command injection attempts.
    * *Security*: Confined using a strict AppArmor profile to prevent unauthorized file access (e.g., blocking `/etc/passwd` reads).
2.  **SSH Honeypot**: A custom implementation using `paramiko` that simulates a Linux shell. It captures credentials (brute-force attempts) and logs commands executed by attackers.
3.  **FTP Honeypot**: A `pyftpdlib` server listening on port 2121, logging login attempts and file operations.

All logs are generated in JSON format and ingested by a centralized **Logstash** pipeline, which forwards data to **Elasticsearch** for indexing.

## Project Structure

    multi_honeypots_ELK/
    ├── ftp/
    │   └── ftp_honeypot.py       # FTP Server implementation
    ├── http/
    │   ├── honeypot_http.py      # Flask Web App
    │   └── templates/            # HTML Templates (Fake Admin Panel)
    ├── ssh/
    │   └── honeypot_ssh.py       # SSH Server implementation
    ├── logs/
    │   ├── honeypot_pipeline.conf # Logstash pipeline configuration
    │   └── *.json                # Log output files (ignored in git)
    ├── policies/
    │   ├── seccomp_filters.py    # Syscall filtering scripts
    │   └── apparmor/             # AppArmor security profiles
    │       └── home.kali.honeypots.http.honeypot_http.py
    └── systemd/                  # Systemd service files for auto-start
        ├── honeypot-http.service
        ├── honeypot-ftp.service
        └── honeypot-ssh.service

## Installation & Setup

### Prerequisites
* Python 3.x
* Elasticsearch & Logstash (installed and running)
* `apparmor` and `apparmor-utils`

### 1. Environment Setup
Create a virtual environment and install Python dependencies:

    python3 -m venv venv
    source venv/bin/activate
    pip install flask paramiko pyftpdlib

### 2. Security Hardening (AppArmor)
To prevent the HTTP honeypot from being used to compromise the host system via command injection, you must apply the AppArmor profile.

1.  **Configure Profile**: Ensure your AppArmor profile uses a named profile (e.g., `profile honeypot-http {`) rather than a hardcoded path to handle symlinks correctly.

2.  **Copy Profile**:
    
    sudo cp policies/apparmor/home.kali.honeypots.http.honeypot_http.py /etc/apparmor.d/

3.  **Load Profile**:
    
    sudo apparmor_parser -r /etc/apparmor.d/home.kali.honeypots.http.honeypot_http.py

### 3. Service Deployment
Install the Systemd services to run the honeypots in the background.

1.  **Copy Service Files**:
    
    sudo cp systemd/*.service /etc/systemd/system/

2.  **Enable Services**:
    
    sudo systemctl daemon-reload
    sudo systemctl enable --now honeypot-http
    sudo systemctl enable --now honeypot-ssh
    sudo systemctl enable --now honeypot-ftp

### 4. ELK Pipeline
Configure Logstash to read the honeypot logs and send them to Elasticsearch:

    # Run Logstash with the provided config
    sudo /usr/share/logstash/bin/logstash -f logs/honeypot_pipeline.conf

## Logging Format

Logs are stored in JSON format for easy parsing.

**Example SSH Log:**

    {
      "honeypot": "ssh",
      "timestamp": "2025-11-24T12:00:00Z",
      "src_ip": "192.168.1.50",
      "username": "root",
      "password": "password123",
      "action": "auth_attempt"
    }

**Example HTTP Log:**

    {
      "honeypot": "http",
      "timestamp": "2025-11-24T12:05:00Z",
      "src_ip": "192.168.1.50",
      "action": "visit_home",
      "method": "POST",
      "form_data": {"site": "google.com; cat /etc/passwd"}
    }

## Disclaimer

This project is for **educational and research purposes only**. 
* Do not deploy this on a production network without proper isolation (VLANs, DMZ). 
* The SSH honeypot intentionally allows command simulation which, if modified incorrectly, could expose the host system.
* Always monitor your honeypots to ensure they haven't been compromised.