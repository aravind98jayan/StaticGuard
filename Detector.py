#!/usr/bin/env python3
"""
Static Malware Triage Tool
Educational project for static analysis of suspicious files.
Usage:
    python main.py <path_to_file>
    python main.py <path_to_file> --json report.json
    python main.py --watch <folder_to_monitor>
NOTE: This tool performs STATIC analysis only (no sandboxing/execution).
It produces a heuristic risk score, not a definitive verdict. Always
cross-check high-risk findings with VirusTotal or a proper sandbox
before treating a file as confirmed malicious.
"""
import sys
import os
import json
import time
import argparse
import datetime

sys.path.insert(0, os.path.dirname(__file__))
from analyzers.pe_analyzer import analyze_pe
from analyzers.entropy import analyze_file_entropy
from analyzers.strings_scan import analyze_strings
from analyzers.yara_scan import scan_file as yara_scan_file
from analyzers.hash_lookup import calculate_hashes, virustotal_lookup
from scoring import compute_score

# Threshold above which an alert is triggered. Tweak as needed.
ALERT_THRESHOLD = 40


def banner():
    print(r"""
   _____ _        _   _      _____                     _
  / ____| |      | | (_)    / ____|                   | |
 | (___ | |_ __ _| |_ _  ___| |  __ _   _  __ _ _ __ __| |
  \___ \| __/ _` | __| |/ __| | |_ | | | |/ _` | '__/ _` |
  ____) | || (_| | |_| | (__| |__| | |_| | (_| | | | (_| |
 |_____/ \__\__,_|\__|_|\___|\_____|\__,_|\__,_|_|  \__,_|
      Static Malware Triage Tool  (educational project)
""")


# ─────────────────────────────────────────────────────────────
# PRINT HELPERS - one per analyzer module
# ─────────────────────────────────────────────────────────────

def print_hash_details(hashes):
    print(f"    MD5    : {hashes.get('md5',  'N/A')}")
    print(f"    SHA1   : {hashes.get('sha1', 'N/A')}")
    print(f"    SHA256 : {hashes.get('sha256','N/A')}")


def print_pe_details(pe_result):
    if not pe_result.get("valid_pe"):
        errors = pe_result.get("errors", [])
        if errors:
            for e in errors:
                print(f"    [!] {e}")
        else:
            print("    [!] Not a valid PE file — skipping PE analysis.")
        return

    ts = pe_result.get("compile_timestamp", 0)
    try:
        ts_str = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        ts_str = str(ts)

    print(f"    Valid PE         : Yes")
    print(f"    Num Sections     : {pe_result.get('num_sections', 'N/A')}")
    print(f"    Compile Time     : {ts_str}")
    print(f"    Digitally Signed : {'Yes' if pe_result.get('is_signed') else 'No'}")

    sus_sections = pe_result.get("suspicious_sections", [])
    if sus_sections:
        print(f"    [!] Suspicious Sections : {', '.join(sus_sections)}")
    else:
        print(f"    Suspicious Sections  : None detected")

    sus_imports = pe_result.get("suspicious_imports", [])
    if sus_imports:
        print(f"    [!] Suspicious Imports ({len(sus_imports)} found):")
        for imp in sus_imports:
            print(f"        - {imp['function']} ({imp['dll']}) -> {imp['reason']}")
    else:
        print(f"    Suspicious Imports   : None detected")

    warnings = pe_result.get("warnings", [])
    if warnings:
        print(f"    Warnings:")
        for w in warnings:
            print(f"        [!] {w}")


def print_entropy_details(entropy_result):
    overall = entropy_result.get("overall_entropy", 0.0)
    verdict = entropy_result.get("verdict", "unknown")
    regions = entropy_result.get("high_entropy_regions", [])

    print(f"    Overall Entropy  : {overall} / 8.0")
    print(f"    Verdict          : {verdict.upper()}")

    if overall > 7.5:
        print(f"    [!] Very high entropy — strongly suggests packed or encrypted content")
    elif overall > 7.0:
        print(f"    [!] Elevated entropy — possibly compressed or packed")
    elif overall > 6.5:
        print(f"    [~] Moderate entropy — may contain compressed sections")
    else:
        print(f"    Entropy level appears normal")

    if regions:
        print(f"    [!] High-Entropy Regions Found ({len(regions)}):")
        for r in regions[:10]:   # show max 10
            print(f"        Offset {r['offset']}  ->  entropy {r['entropy']}")
        if len(regions) > 10:
            print(f"        ... and {len(regions)-10} more regions")
    else:
        print(f"    High-Entropy Regions : None detected")


def print_strings_details(string_result):
    total    = string_result.get("total_strings", 0)
    urls     = string_result.get("urls", [])
    ips      = string_result.get("ips", [])
    reg_keys = string_result.get("registry_keys", [])
    keywords = string_result.get("suspicious_keywords", [])

    print(f"    Total Strings Extracted : {total}")

    if keywords:
        print(f"    [!] Suspicious Keywords ({len(keywords)} found):")
        for kw in keywords:
            print(f"        - {kw}")
    else:
        print(f"    Suspicious Keywords : None detected")

    if urls:
        print(f"    [!] Hardcoded URLs ({len(urls)} found):")
        for u in urls[:10]:
            print(f"        - {u}")
    else:
        print(f"    Hardcoded URLs      : None detected")

    if ips:
        print(f"    [!] Hardcoded IPs ({len(ips)} found):")
        for ip in ips[:10]:
            print(f"        - {ip}")
    else:
        print(f"    Hardcoded IPs       : None detected")

    if reg_keys:
        print(f"    [!] Registry Keys ({len(reg_keys)} found):")
        for rk in reg_keys[:10]:
            print(f"        - {rk}")
    else:
        print(f"    Registry Keys       : None detected")


def print_yara_details(yara_result):
    error   = yara_result.get("error")
    matches = yara_result.get("matches", [])

    if error:
        print(f"    [!] YARA Error : {error}")
        return

    if not matches:
        print(f"    No YARA rules matched.")
        return

    print(f"    [!] {len(matches)} YARA Rule(s) Matched:")
    for m in matches:
        print(f"        Rule        : {m['rule']}")
        print(f"        Severity    : {m.get('severity', 'unknown').upper()}")
        if m.get('description'):
            print(f"        Description : {m['description']}")
        if m.get('matched_strings'):
            print(f"        Matched     : {', '.join(m['matched_strings'])}")
        print()


def print_vt_details(vt_result):
    if not vt_result.get("checked"):
        note = vt_result.get("note", "VT lookup skipped.")
        print(f"    {note}")
        return

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    total = vt_result.get("total_engines", 0)

    print(f"    Engines Checked  : {total}")
    print(f"    Malicious        : {malicious}")
    print(f"    Suspicious       : {suspicious}")
    print(f"    Clean            : {total - malicious - suspicious}")

    if malicious > 0:
        print(f"    [!] DETECTED as malicious by {malicious}/{total} AV engines")
    elif suspicious > 0:
        print(f"    [~] Flagged as suspicious by {suspicious}/{total} engines")
    else:
        print(f"    No engines flagged this file as malicious")


# ─────────────────────────────────────────────────────────────
# ALERT
# ─────────────────────────────────────────────────────────────

def trigger_alert(filepath, score_result):
    score   = score_result["score"]
    max_score = score_result["max_score"]
    verdict = score_result["verdict"]

    # 1. Terminal bell + visual banner
    sys.stdout.write("\a")
    sys.stdout.flush()
    print("\n" + "!" * 60)
    print(f"  ⚠  HIGH RISK ALERT  ⚠")
    print(f"  File:    {filepath}")
    print(f"  Score:   {score} / {max_score}")
    print(f"  Verdict: {verdict}")
    print("!" * 60 + "\n")

    # 2. Desktop notification (optional)
    try:
        from plyer import notification
        notification.notify(
            title="Malware Triage Tool - High Risk File",
            message=f"{os.path.basename(filepath)}\nScore: {score}/{max_score} ({verdict})",
            timeout=10,
        )
    except ImportError:
        print("[i] Tip: run 'pip install plyer' to also get a native desktop notification popup.")
    except Exception as e:
        print(f"[i] Desktop notification unavailable: {e}")

    # 3. Append to alerts.log
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.log")
        with open(log_path, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {filepath} | score={score}/{max_score} | verdict={verdict}\n")
    except Exception as e:
        print(f"[i] Could not write to alerts.log: {e}")


# ─────────────────────────────────────────────────────────────
# CORE ANALYSIS PIPELINE
# ─────────────────────────────────────────────────────────────

def analyze_file(filepath, use_vt=False):
    print(f"[*] Analyzing: {filepath}\n")

    print("[*] Calculating hashes...")
    hashes = calculate_hashes(filepath)
    print_hash_details(hashes)

    print("\n[*] Running PE structural analysis...")
    pe_result = analyze_pe(filepath)
    print_pe_details(pe_result)

    print("\n[*] Calculating entropy...")
    entropy_result = analyze_file_entropy(filepath)
    print_entropy_details(entropy_result)

    print("\n[*] Extracting & scanning strings...")
    string_result = analyze_strings(filepath)
    print_strings_details(string_result)

    print("\n[*] Running YARA rules...")
    yara_result = yara_scan_file(filepath)
    print_yara_details(yara_result)

    vt_result = {"checked": False, "note": "VT lookup skipped (use --vt flag)"}
    if use_vt:
        print("\n[*] Querying VirusTotal...")
        vt_result = virustotal_lookup(hashes["sha256"])
        print_vt_details(vt_result)

    print("\n[*] Computing risk score...\n")
    score_result = compute_score(pe_result, entropy_result, string_result, yara_result, vt_result)

    report = {
        "file": filepath,
        "hashes": hashes,
        "pe_analysis": pe_result,
        "entropy_analysis": entropy_result,
        "string_analysis": string_result,
        "yara_analysis": yara_result,
        "virustotal": vt_result,
        "risk_assessment": score_result,
    }

    print_summary(report)

    if score_result["score"] > ALERT_THRESHOLD:
        trigger_alert(filepath, score_result)

    return report


def print_summary(report):
    score = report["risk_assessment"]
    print("=" * 60)
    print(f"  VERDICT    : {score['verdict']}")
    print(f"  RISK SCORE : {score['score']} / {score['max_score']}")
    print("=" * 60)
    if score["reasons"]:
        print("\nFindings:")
        for r in score["reasons"]:
            print(f"  - {r}")
    else:
        print("\nNo suspicious indicators detected.")
    print()


# ─────────────────────────────────────────────────────────────
# WATCH MODE
# ─────────────────────────────────────────────────────────────

def watch_folder(folder_path, json_dir=None):
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("[!] 'watchdog' library not installed. Run: pip install watchdog")
        sys.exit(1)

    if not os.path.isdir(folder_path):
        print(f"[!] Not a valid folder: {folder_path}")
        sys.exit(1)

    print(f"[*] Watching folder (and all subfolders) for new files: {os.path.abspath(folder_path)}")
    print("[*] Drop files anywhere inside here to have them auto-analyzed. Press Ctrl+C to stop.\n")

    class NewFileHandler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            filepath = event.src_path
            if filepath.endswith(".report.json"):
                return
            time.sleep(1.0)
            prev_size = -1
            while True:
                try:
                    size = os.path.getsize(filepath)
                except OSError:
                    return
                if size == prev_size:
                    break
                prev_size = size
                time.sleep(0.5)
            print(f"\n[NEW FILE DETECTED] {filepath}")
            print("-" * 60)
            try:
                report = analyze_file(filepath, use_vt=False)
                if json_dir:
                    os.makedirs(json_dir, exist_ok=True)
                    out_name = os.path.basename(filepath) + ".report.json"
                    out_path = os.path.join(json_dir, out_name)
                    with open(out_path, "w") as f:
                        json.dump(report, f, indent=2, default=str)
                    print(f"[*] Report saved to {out_path}")
            except Exception as e:
                print(f"[!] Error analyzing {filepath}: {e}")
            print("-" * 60)
            print(f"[*] Watching {os.path.abspath(folder_path)} for new files...\n")

    handler = NewFileHandler()
    observer = Observer()
    observer.schedule(handler, folder_path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Stopped watching.")
    observer.join()


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Static malware triage tool")
    parser.add_argument("file", nargs="?", help="Path to file to analyze")
    parser.add_argument("--json", help="Save full report to JSON file", default=None)
    parser.add_argument("--vt", action="store_true", help="Also check VirusTotal (requires VT_API_KEY env var)")
    parser.add_argument("--watch", metavar="FOLDER", help="Watch a folder and auto-analyze new files as they appear")
    parser.add_argument("--watch-json-dir", metavar="DIR", help="When using --watch, save each report as JSON into this folder", default=None)
    parser.add_argument("--alert-threshold", type=int, default=None, help="Override the risk score threshold for triggering alerts (default: 40)")
    args = parser.parse_args()

    global ALERT_THRESHOLD
    if args.alert_threshold is not None:
        ALERT_THRESHOLD = args.alert_threshold

    banner()

    if args.watch:
        watch_folder(args.watch, json_dir=args.watch_json_dir)
        return

    if not args.file:
        parser.error("Provide a file to analyze, or use --watch FOLDER for continuous monitoring")

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    report = analyze_file(args.file, use_vt=args.vt)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[*] Full report saved to {args.json}")


if __name__ == "__main__":
    main()
