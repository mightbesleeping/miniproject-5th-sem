# Automated Endpoint Threat Detection Engine

> A real-time, modular EDR (Endpoint Detection and Response) tool built in Python that hooks into the Linux kernel auditing framework to detect cyberattacks as they happen.

---

## Features

| Capability | Detail |
|---|---|
| **Real-time ingestion** | Continuously tails `/var/log/audit/audit.log` with rotation detection |
| **Hex decoding** | Automatically decodes all auditd hex-encoded fields and reconstructs full command lines |
| **Multi-record assembly** | Merges SYSCALL + EXECVE + PATH records sharing the same serial number |
| **YAML rule engine** | Modular rules with `process`, `cmd_regex`, `args_regex`, `uid`, `any_of` matchers |
| **27 detection rules** | Covers reverse shells, LotL binaries, privilege escalation, recon, and persistence |
| **Colorized alerts** | Severity-color-coded terminal output with full event context |
| **JSONL alert log** | Structured alert output for SIEM ingestion at `logs/alerts.jsonl` |
| **DuckDB persistence** | All alerts stored in a local DuckDB database for offline querying |
| **Replay mode** | Analyze historical `.log` files without needing root or a live system |

---

## Project Structure

```
miniproject/
├── edr/
│   ├── __init__.py      # Package init
│   ├── collector.py     # auditd log tail + rotation detection
│   ├── parser.py        # Raw log → structured event dicts
│   ├── decoder.py       # Hex field decoding + command reconstruction
│   ├── engine.py        # YAML rule loading + threat matching
│   ├── alerter.py       # Terminal output + JSONL alert log
│   ├── db.py            # DuckDB AlertStore
│   └── utils.py         # Config, logging, shared helpers
├── rules/
│   ├── reverse_shell.yaml   # 5 rules (EDR-001 to EDR-005)
│   ├── privesc.yaml         # 5 rules (EDR-101 to EDR-105)
│   ├── lolbins.yaml         # 7 rules (EDR-201 to EDR-207)
│   ├── recon.yaml           # 7 rules (EDR-301 to EDR-307)
│   └── persistence.yaml     # 6 rules (EDR-401 to EDR-406)
├── logs/
│   └── alerts.jsonl         # Structured alert output (auto-created)
├── data/
│   └── edr_alerts.duckdb    # DuckDB database (auto-created)
├── main.py              # CLI entry point
├── db_setup.py          # One-shot DuckDB schema initializer
├── db_query.py          # Terminal query tool (recent/stats/count)
├── config.yaml          # Global configuration
├── test_edr.py          # Unit + integration tests
└── pyproject.toml       # uv project file
```

---

## Quick Start

### 1. Install dependencies

If `uv` is not found, install it and add its default install directory to this
shell's `PATH`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

Then install the project dependencies as your regular user:

```bash
uv sync
```

### 2. Ensure auditd is running (live mode)

```bash
sudo systemctl start auditd
sudo systemctl enable auditd
```

### 3. Set up DuckDB

```bash
# Initialize the DuckDB database + schema (run once):
uv run python db_setup.py
```

### 4. Run in live mode (requires root)

Run the app with the project virtual environment. Do not use `sudo uv run`:
`sudo` may not include the directory where `uv` was installed.

```bash
sudo .venv/bin/python main.py
```

### 5. Replay a saved audit log (no root needed)

```bash
uv run python main.py --replay /var/log/audit/audit.log
```

### 6. Query alerts from DuckDB

```bash
# Recent 20 alerts in table format:
uv run python db_query.py recent

# Last 50 CRITICAL alerts as JSON:
uv run python db_query.py recent --limit 50 --severity CRITICAL --json

# Aggregate statistics + top rules:
uv run python db_query.py stats

# Total count:
uv run python db_query.py count
```

### 7. Run the test suite

```bash
uv run python -m pytest test_edr.py -v
```

---

## DuckDB Configuration

Edit `config.yaml` to configure the database file path:

```yaml
edr:
  db:
    enabled: true
    path: data/edr_alerts.duckdb
```

> Set `enabled: false` to run the engine without DuckDB. All alerts still appear in the terminal and `logs/alerts.jsonl`.

### Database Schema

```sql
CREATE SEQUENCE IF NOT EXISTS alerts_id_seq START 1;
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER DEFAULT nextval('alerts_id_seq') PRIMARY KEY,
    alert_no        INTEGER NOT NULL,
    rule_id         VARCHAR(50) NOT NULL,
    rule_name       VARCHAR(255) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    description     TEXT,
    tags            VARCHAR(500),
    fired_at        TIMESTAMP,
    event_serial    VARCHAR(30),
    event_timestamp VARCHAR(30),
    event_pid       VARCHAR(20),
    event_uid       VARCHAR(20),
    event_exe       VARCHAR(500),
    event_comm      VARCHAR(255),
    event_cmd       TEXT,
    event_cwd       VARCHAR(500),
    created_at      TIMESTAMP DEFAULT current_timestamp
);
```

---

## CLI Options

```
usage: edr [-h] [--config FILE] [--replay LOG_FILE]
           [--min-severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}]
           [--rules-dir DIR] [--no-color]
           [--log-level {DEBUG,INFO,WARNING,ERROR}]

Options:
  --config FILE        Path to config.yaml (default: config.yaml)
  --replay LOG_FILE    Replay a historical audit log file
  --min-severity SEV   Minimum alert severity to display (default: LOW)
  --rules-dir DIR      Override rules directory
  --no-color           Disable ANSI color output
  --log-level LEVEL    Internal logging verbosity (default: WARNING)
```

---

## Detection Rules

### Reverse Shell (`rules/reverse_shell.yaml`)
| ID | Name | Severity |
|---|---|---|
| EDR-001 | Reverse Shell via Bash /dev/tcp | CRITICAL |
| EDR-002 | Reverse Shell via Netcat -e/-c | CRITICAL |
| EDR-003 | Reverse Shell via Python socket | CRITICAL |
| EDR-004 | Reverse Shell via Perl socket | CRITICAL |
| EDR-005 | Reverse Shell via mkfifo pipe | HIGH |

### Privilege Escalation (`rules/privesc.yaml`)
| ID | Name | Severity |
|---|---|---|
| EDR-101 | sudo -l Enumeration | LOW |
| EDR-102 | SUID Binary Exec from /tmp | HIGH |
| EDR-103 | chmod +s SUID Bit Set | HIGH |
| EDR-104 | su/sudo Interactive Shell | MEDIUM |
| EDR-105 | pkexec (PwnKit CVE-2021-4034) | MEDIUM |

### Living-off-the-Land (`rules/lolbins.yaml`)
| ID | Name | Severity |
|---|---|---|
| EDR-201 | curl/wget Download to /tmp | HIGH |
| EDR-202 | curl Pipe to Shell | CRITICAL |
| EDR-203 | awk/perl Shell Spawn | HIGH |
| EDR-204 | find -exec Shell Command | MEDIUM |
| EDR-205 | vim/less/man Shell Escape | HIGH |
| EDR-206 | base64 Decode Pipe to Shell | MEDIUM |
| EDR-207 | dd Disk Overwrite | HIGH |

### Reconnaissance (`rules/recon.yaml`)
| ID | Name | Severity |
|---|---|---|
| EDR-301 | id/whoami/hostname/uname | INFO |
| EDR-302 | ifconfig/ip/netstat Enum | LOW |
| EDR-303 | /etc/shadow Password File Read | HIGH |
| EDR-304 | SSH Key / Credential Discovery | MEDIUM |
| EDR-305 | ps/pstree Process Listing | INFO |
| EDR-306 | crontab -l Enumeration | LOW |
| EDR-307 | SUID/SGID Binary Search | MEDIUM |

### Persistence (`rules/persistence.yaml`)
| ID | Name | Severity |
|---|---|---|
| EDR-401 | Cron Job Backdoor | HIGH |
| EDR-402 | SSH authorized_keys Write | HIGH |
| EDR-403 | Systemd Service Unit Created | HIGH |
| EDR-404 | .bashrc/.profile Modification | MEDIUM |
| EDR-405 | LD_PRELOAD Hijacking | CRITICAL |
| EDR-406 | at/batch Job Scheduled | MEDIUM |

---

## Writing Custom Rules

Create a `.yaml` file in `rules/` using this schema:

```yaml
- id: EDR-999
  name: My Custom Rule
  severity: HIGH          # INFO | LOW | MEDIUM | HIGH | CRITICAL
  description: >
    What this rule detects and why it matters.
  tags: [custom, execution]
  match:
    process: "^python3$"          # regex against exe basename (optional)
    cmd_regex: "evil_pattern"     # regex against full command (optional)
    args_regex: "--dangerous"     # regex against individual args (optional)
    uid: 0                        # exact UID match (optional)
    not_process: "^safe_app$"     # exclude this process (optional)
    any_of:                       # OR block (optional)
      - cmd_regex: "pattern_a"
      - args_regex: "pattern_b"
```

The engine hot-reloads rules on restart — no code changes needed.

---

## Architecture

```
auditd kernel hook
        |
        v
/var/log/audit/audit.log
        |
        v
  collector.py  ---- tail() / replay()
        |
        v
   parser.py   ---- parse_line() -> EventAssembler -> merged event dict
        |
        v
  decoder.py   ---- hex decode + reconstruct_command()
        |
        v
   engine.py   ---- load_rules() -> ThreatEngine.evaluate()
        |   matches
        v
  alerter.py   ---- terminal print + alerts.jsonl + DuckDB insert
        |
        v
    edr/db.py  ---- AlertStore (DuckDB)
```

---

## Requirements

- Python 3.10+ (managed via uv)
- `uv` installed
- `auditd` installed and running (`apt install auditd` / `dnf install audit`)
- Root privileges for live mode (reads `/var/log/audit/audit.log`)
