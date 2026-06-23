"""
Hash Calculator + VirusTotal Lookup
Computes file hashes and (optionally) checks them against VirusTotal's
public API for a ground-truth comparison. VT lookup is optional -
the tool works fully offline without it.

Get a free API key at https://www.virustotal.com/gui/join-us
Free tier: 4 requests/minute, 500/day - fine for a student project.
"""

import hashlib
import os

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VT_API_KEY = os.environ.get("VT_API_KEY", "")  # set this as an env var, never hardcode
VT_URL = "https://www.virustotal.com/api/v3/files/{}"


def calculate_hashes(filepath):
    result = {"md5": None, "sha1": None, "sha256": None}
    if not os.path.exists(filepath):
        return result

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    result["md5"] = md5.hexdigest()
    result["sha1"] = sha1.hexdigest()
    result["sha256"] = sha256.hexdigest()
    return result


def virustotal_lookup(sha256_hash):
    """Returns VT detection stats if API key is configured, else a note
    that the check was skipped. Never fails the whole scan."""
    result = {"checked": False, "malicious": None, "suspicious": None,
              "total_engines": None, "note": ""}

    if not HAS_REQUESTS:
        result["note"] = "requests library not installed - skipping VT lookup"
        return result

    if not VT_API_KEY:
        result["note"] = "No VT_API_KEY env var set - skipping VT lookup (tool works fine offline)"
        return result

    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(VT_URL.format(sha256_hash), headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result["checked"] = True
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["total_engines"] = sum(stats.values())
        elif resp.status_code == 404:
            result["note"] = "Hash not found in VirusTotal database (no prior submissions)"
        else:
            result["note"] = f"VT API returned status {resp.status_code}"
    except Exception as e:
        result["note"] = f"VT lookup failed: {e}"

    return result
