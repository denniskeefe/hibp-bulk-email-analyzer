*Vibe Coded with Claude*

# HIBP Bulk Email Analyzer

A robust Python-based OSINT tool designed to process lists of email addresses through the **Have I Been Pwned (HIBP) v3 API**. It streamlines the process of checking large batches of accounts for compromises while respecting HIBP's strict rate-limiting policies.

## Key Features

* **Bulk Processing**: Load emails from a text file or provide a comma-separated list via CLI.
* **Dual Intelligence**: Checks both known data **breaches** and public **pastes**.
* **Smart Rate-Limiting**: Includes built-in exponential backoff and adjustable delays to avoid 429 errors.
* **Clean CLI Output**: Colorized terminal output with progress bars and summarized results.
* **Multi-Format Export**: Save findings as `.csv`, `.json`, or a simple `.txt` containing only the compromised emails.
* **SSL Compatibility**: Includes a fallback for macOS environments where SSL certificates are often uninitialized.

---

## Prerequisites

* **Python 3.10+**
* **HIBP API Key**: A paid API key from [Have I Been Pwned](https://haveibeenpwned.com/API/Key) is required for v3 API access.
* **Certifi (Optional)**: For enhanced SSL security (`pip install certifi`).

---

## Installation

1. **Clone or save the script**:
Save the code as `hibp_bulk.py`.
2. **Set permissions (Linux/macOS)**:
```bash
chmod +x hibp_bulk.py

```



---

## Usage

### Basic Commands

* **Check a file of emails**:
```bash
python hibp_bulk.py -k YOUR_API_KEY -e emails.txt

```


* **Check specific emails inline**:
```bash
python hibp_bulk.py -k YOUR_API_KEY -e "user1@example.com,user2@gmail.com"

```



### Advanced Options

| Flag | Description |
| --- | --- |
| `-k, --key` | **Required.** Your HIBP API key. |
| `-e, --emails` | **Required.** Path to a file OR a comma-separated list of emails. |
| `--no-pastes` | Skips the paste lookup to speed up the process. |
| `--breach-delay` | Seconds between breach checks (Default: 1.6s). |
| `--paste-delay` | Seconds between paste checks (Default: 3.0s). |
| `--format` | Output format: `csv`, `json`, `txt`, or `all` (Default: `csv`). |
| `--out` | Directory to save results. |
| `--quiet` | Suppresses per-email output and shows only the final summary. |

---

## Output Examples

### Terminal Output

The script provides a live view of the status for each email:

* **✓ CLEAN**: No breaches found.
* **✗ PWNED**: Breach found (displays the names of the breaches).
* **⚠ ERROR**: Rate limit or connectivity issues.

### Exported Data

The results include:

* **CSV/JSON**: Full details including breach names, counts, and timestamps.
* **TXT**: A "hit list" of compromised emails for quick remediation.

---

## Helpful Resources

* [HIBP API Documentation](https://haveibeenpwned.com/API/v3)
* [Get an HIBP API Key](https://haveibeenpwned.com/API/Key)
* [Python urllib Documentation](https://docs.python.org/3/library/urllib.request.html)

