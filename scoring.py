"""
Risk Scoring Engine
Combines all analyzer outputs into a single weighted risk score
and a human-readable verdict. Weights are heuristic - tune them
based on testing, and document your reasoning in your project report.
"""

def compute_score(pe_result, entropy_result, string_result, yara_result, vt_result):
    score = 0
    max_score = 100
    reasons = []

    # --- Entropy (max 20 pts) ---
    overall_entropy = entropy_result.get("overall_entropy", 0)
    if overall_entropy > 7.5:
        score += 20
        reasons.append(f"Very high overall entropy ({overall_entropy}) - likely packed/encrypted")
    elif overall_entropy > 7.0:
        score += 12
        reasons.append(f"Elevated entropy ({overall_entropy}) - possibly compressed/packed")
    elif overall_entropy > 6.5:
        score += 5
        reasons.append(f"Moderate entropy ({overall_entropy})")

    # --- PE structural flags (max 25 pts) ---
    if pe_result.get("valid_pe"):
        if not pe_result.get("is_signed"):
            score += 5
            reasons.append("Binary is not digitally signed")

        n_imports = len(pe_result.get("suspicious_imports", []))
        if n_imports > 0:
            pts = min(n_imports * 4, 15)
            score += pts
            reasons.append(f"{n_imports} suspicious API import(s) found (process injection / evasion APIs)")

        if pe_result.get("suspicious_sections"):
            score += 5
            reasons.append(f"Suspicious section name(s): {pe_result['suspicious_sections']}")

    # --- Strings (max 20 pts) ---
    n_kw = len(string_result.get("suspicious_keywords", []))
    if n_kw > 0:
        pts = min(n_kw * 3, 15)
        score += pts
        reasons.append(f"{n_kw} suspicious keyword(s) found in strings (e.g. PowerShell, persistence, ransom note language)")

    if string_result.get("urls") or string_result.get("ips"):
        score += 5
        reasons.append("Hardcoded URL(s)/IP(s) found - possible C2 or download infrastructure")

    # --- YARA (max 25 pts) ---
    yara_matches = yara_result.get("matches", [])
    severity_pts = {"high": 12, "medium": 7, "low": 3, "test": 0}
    for m in yara_matches:
        pts = severity_pts.get(m.get("severity", "low"), 3)
        score += pts
        reasons.append(f"YARA rule matched: {m['rule']} ({m.get('description', '')})")

    # --- VirusTotal ground truth (max 10 pts, only if available) ---
    if vt_result.get("checked"):
        malicious = vt_result.get("malicious", 0)
        total = vt_result.get("total_engines", 1) or 1
        if malicious > 0:
            ratio_pts = min(int((malicious / total) * 10) + 3, 10)
            score += ratio_pts
            reasons.append(f"VirusTotal: {malicious}/{total} engines flagged this file as malicious")

    score = min(score, max_score)

    if score >= 70:
        verdict = "CRITICAL"
    elif score >= 45:
        verdict = "HIGH"
    elif score >= 20:
        verdict = "MEDIUM"
    elif score >= 5:
        verdict = "LOW"
    else:
        verdict = "CLEAN / NO INDICATORS FOUND"

    return {
        "score": score,
        "max_score": max_score,
        "verdict": verdict,
        "reasons": reasons,
    }
