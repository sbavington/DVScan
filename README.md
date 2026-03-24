# DVScan — TrendAI DV Release CVE Tracker

A local Python tool for scanning TrendAI Weekly Digital Vaccine (DV) Release spreadsheets, identifying CVE filters marked **"Not enabled by default in any deployment"**, and tracking investigation status and notes in a persistent SQLite database with a web-based UI.

---

## What it does

Each week Trend Micro releases a DV update spreadsheet listing new and modified TippingPoint filters. Some filters are not enabled by default and require manual review before deployment. DVScan:

- Scans a directory of weekly `.xlsx` DV release files
- Extracts all filters marked *"Not enabled by default in any deployment"* across all severities
- Stores results in a local SQLite database (`cve_tracker.db`)
- Tracks investigation status and analyst notes per CVE
- Provides a web UI for filtering, reviewing, and updating records
- Generates a plain-text report file

---

## Files

| File | Purpose |
|------|---------|
| `extract_critical_cves.py` | Command-line scanner and report generator |
| `cve_tracker_web.py` | Flask web UI for the database |
| `cve_tracker.db` | SQLite database (auto-created, not in repo) |

---

## Requirements

- Python 3.9+
- `openpyxl` — reads `.xlsx` files
- `flask` — web UI only

Install in PyCharm via **Settings → Python Interpreter → +**, or from terminal:

```bash
pip3 install openpyxl flask
```

---

## Setup

1. Clone the repo:
```bash
git clone git@github.com:sbavington/DVScan.git
cd DVScan
```

2. Install dependencies (see Requirements above)

3. Set your DVSheets directory — edit the `DEFAULT_DIR` variable at the top of both scripts:
```python
DEFAULT_DIR = '/Users/stephenb/Documents/Trend/TippingPoint/DVSheets'
```

---

## Command-line usage (`extract_critical_cves.py`)

### Scan DVSheets directory
```bash
python3 extract_critical_cves.py scan
python3 extract_critical_cves.py scan /path/to/DVSheets
python3 extract_critical_cves.py scan /path/to/single_file.xlsx
```
Scans all `.xlsx` files, adds new CVEs to the database, updates existing ones. Notes and status are preserved on update.

### List all CVEs (brief)
```bash
python3 extract_critical_cves.py list
```

### Generate report
```bash
python3 extract_critical_cves.py report              # All CVEs
python3 extract_critical_cves.py report open         # Unresolved only
python3 extract_critical_cves.py report critical     # Critical severity only
python3 extract_critical_cves.py report resolved     # Any status value
```
Saves output to `cve_report.txt` in the same directory as the script.

### Add a note to a CVE
```bash
python3 extract_critical_cves.py note CVE-2025-12345 "Reviewed — low risk in our environment"
```
Notes are timestamped and appended, not overwritten.

### Set resolution status
```bash
python3 extract_critical_cves.py status CVE-2025-12345 investigating
```

**Valid statuses:**

| Status | Meaning |
|--------|---------|
| `open` | Newly discovered, not yet reviewed |
| `investigating` | Under active review |
| `accepted` | Risk accepted, not enabling filter |
| `resolved` | Filter enabled or issue resolved |
| `false_positive` | Confirmed false positive |

---

## Web UI (`cve_tracker_web.py`)

```bash
python3 cve_tracker_web.py
```

Open **http://localhost:5001** in your browser.

### Features

- **Sidebar** — filter by status or severity; counts update automatically
- **Stats bar** — at-a-glance counts by severity and open/resolved status
- **Scan button** — scan a directory directly from the browser, no terminal needed
- **Search** — live filter by CVE ID, filter name, or affected system
- **Click any row** — opens a detail panel showing all fields
- **Status & Notes** — update status and add notes directly in the detail panel
- **Orange dot** on CVE ID indicates a record has notes

---

## Typical weekly workflow

1. Download the new DV release `.xlsx` from Trend Micro and save to your DVSheets folder
2. Open the web UI: `python3 cve_tracker_web.py`
3. Click **Scan Now** — new CVEs are added automatically
4. Review any new **Open** items in the sidebar
5. Click each CVE, set a status, add investigation notes, click **Save**
6. Optionally generate a report: `python3 extract_critical_cves.py report open`

---

## Database

The database (`cve_tracker.db`) is created automatically on first scan. It is excluded from the git repo via `.gitignore` — your notes and status history remain local.

**Schema:**

| Column | Description |
|--------|-------------|
| `cve_id` | CVE identifier |
| `filter_desc` | Full TippingPoint filter name |
| `category` | Filter category |
| `severity` | Critical / High / Medium / Moderate / Low |
| `affected` | Affected systems |
| `false_positive` | False positive guidance from Trend Micro |
| `performance` | Performance impact guidance |
| `sheet` | Source sheet in the spreadsheet |
| `source_file` | Source `.xlsx` filename |
| `first_seen` | Date first detected |
| `last_seen` | Date last seen in a scan |
| `status` | Investigation status |
| `notes` | Analyst notes (timestamped, appended) |
| `updated_at` | Last modified timestamp |

---

## Git workflow

```bash
# Pull latest changes
git pull

# After updating scripts, push changes
git add .
git commit -m "describe your change"
git push
```

> **Note:** `cve_tracker.db` and `*.txt` report files are excluded from git. The database stays local to your machine.
