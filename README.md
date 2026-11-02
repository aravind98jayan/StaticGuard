# StaticGuard

A static-analysis triage tool for suspicious Windows executables. It scores each file from 0 to 100 using PE structure, entropy, string/IOC extraction, YARA rules and an optional VirusTotal hash lookup, without ever executing the file.

It is a first-pass triage aid for prioritising what gets escalated to sandbox analysis, not a replacement for AV or dynamic analysis.

## Setup

```bash
git clone https://github.com/aravind98jayan/StaticGuard.git
cd StaticGuard
pip install -r requirements.txt
```

`yara-python` can need build tools on Windows. If it fails, install a prebuilt wheel matching your Python version, or run inside WSL/Linux.

Optional VirusTotal lookups (free API key from virustotal.com):

```bash
export VT_API_KEY="your_key"        # Linux/macOS
$env:VT_API_KEY="your_key"          # PowerShell
```

Everything else works offline.

## Usage

```bash
python main.py sample.exe
python main.py sample.exe --vt                 # add VirusTotal lookup
python main.py sample.exe --json report.json   # save full JSON report
python main.py --watch ./incoming/             # auto-analyse new files
python main.py --watch ./incoming/ --watch-json-dir ./reports/
python main.py sample.exe --alert-threshold 50 # change alert cutoff (default 40)
```

Watch mode uses `watchdog` to analyse files as they appear in a folder. Press Ctrl+C to stop.

## What it checks

| Module | Checks |
|---|---|
| `analyzers/pe_analyzer.py` | Missing digital signature, suspicious imports (process injection, anti-debug, keylogging APIs), suspicious section names |
| `analyzers/entropy.py` | Whole-file and per-section Shannon entropy (packing/encryption indicator) |
| `analyzers/strings_scan.py` | Hardcoded URLs/IPs, registry keys, PowerShell obfuscation, ransom-note language |
| `analyzers/yara_scan.py` | Custom YARA rules in `rules/suspicious.yar` (injection, persistence, packers, anti-VM) |
| `analyzers/hash_lookup.py` | MD5/SHA1/SHA256 and optional VirusTotal lookup |
| `scoring.py` | Combines all signals into a weighted 0-100 score and a verdict |

Verdicts: CLEAN (<5), LOW (5-19), MEDIUM (20-44), HIGH (45-69), CRITICAL (70+).

## Safe testing

Never test with real malware on your main machine.

1. **EICAR test file**, the industry-standard harmless AV test string:
   ```python
   with open("eicar_test.txt", "w") as f:
       f.write(r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
   ```
   Most AV will quarantine it immediately, which is expected.
2. **Benign packed binaries**: pack a small legitimate freeware tool with `upx file.exe` to get realistic high-entropy test cases.
3. For real samples, use an isolated VM with no network or shared folders, and take samples only from controlled research datasets.

## Results

_To be added after testing: table of test files with score and verdict._

## Known limitations

- Static analysis can be evaded by advanced packers and obfuscators.
- No behavioural analysis (what the file does when run).
- The YARA ruleset is a small starter set (~8 rules).
- Packed or protected legitimate software can trigger false positives.
- Watch mode detects newly created files; files moved or renamed into the folder (e.g. browser downloads) may not trigger analysis.
