# Static Malware Triage Tool

A static-analysis tool that inspects suspicious Windows executables and
scores them on a 0-100 risk scale using PE structure analysis, entropy,
string analysis, and YARA rule matching — without ever executing the file.

> ⚠️ **Scope note for your report**: this performs *static* analysis only.
> It heuristically scores risk; it does not "guarantee" detection of any
> malware (no tool, including commercial AV, can claim that). Frame it in
> your writeup as a triage/first-pass tool that a SOC L1 analyst would use
> to prioritize what gets escalated for deeper sandbox analysis.

## Setup

```bash
cd malware_detector
pip install -r requirements.txt
```

`yara-python` sometimes needs build tools on Windows — if it fails to
install, grab a prebuilt wheel from PyPI matching your Python version,
or run this inside WSL/Linux where it builds cleanly.

(Optional) For VirusTotal cross-checking:
```bash
export VT_API_KEY="your_free_api_key_here"   # get one at virustotal.com
```
The tool works fully offline without this — VT is just a bonus ground-truth check.

## Usage

```bash
python main.py suspicious_file.exe
python main.py suspicious_file.exe --vt              # also check VirusTotal
python main.py suspicious_file.exe --json report.json # save full JSON report

# Continuous monitoring mode - auto-analyzes any new file dropped into a folder
python main.py --watch ./incoming/
python main.py --watch ./incoming/ --watch-json-dir ./reports/   # also save a report per file
```

**Watch mode** uses the `watchdog` library to monitor a folder and automatically
runs the full analysis pipeline the instant a new file appears in it — useful
for demoing "near real-time" detection (e.g. point it at your Downloads folder,
or a shared/incoming folder) without needing full OS-level hooks. Press Ctrl+C
to stop watching.

## What it checks

| Module | Checks for |
|---|---|
| `pe_analyzer.py` | Missing digital signature, suspicious imports (process injection, anti-debug, keylogging APIs), suspicious section names |
| `entropy.py` | Whole-file and section-level Shannon entropy (packing/encryption indicator) |
| `strings_scan.py` | Hardcoded URLs/IPs, registry keys, PowerShell obfuscation, ransom note language |
| `yara_scan.py` | Custom YARA rules (rules/suspicious.yar) for injection patterns, persistence, packers, anti-VM |
| `hash_lookup.py` | MD5/SHA1/SHA256 + optional VirusTotal lookup |
| `scoring.py` | Combines all of the above into a weighted score + verdict |

## Safe testing (do NOT use real malware on your main machine)

1. **EICAR test file** — industry-standard safe test string, included generation snippet:
   ```python
   with open("eicar_test.txt", "w") as f:
       f.write(r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
   ```
   Note: most AV will quarantine this immediately if real-time protection is on — that's expected/correct behavior.

2. **Benign packed binaries** — download a small legitimate freeware tool and pack it yourself with UPX (`upx file.exe`) to generate realistic high-entropy/packed-section test cases without touching real malware.

3. If you want to test against *real* malware samples for your report (optional, advanced), use an isolated VM with no network/shared folders, and source samples only from a controlled academic dataset (e.g. ones provided by your course) — never download "malware samples" from random sites.



## Known limitations 

- Static analysis can be evaded by advanced packers/obfuscators
- No behavioral analysis (what the file *does* when run)
- YARA ruleset is a starter set (~8 rules) — production tools have thousands
- False positives possible on legitimate packed/protected commercial software
