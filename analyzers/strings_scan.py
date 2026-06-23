"""
Suspicious String Extractor
Pulls printable strings from a binary and flags ones that commonly
indicate C2 infrastructure, persistence mechanisms, or malicious intent.
"""

import re
import os

URL_PATTERN = re.compile(rb'(https?://[^\s\x00-\x1f"\'<>]{4,256})')
IP_PATTERN = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
REGISTRY_PATTERN = re.compile(rb'(HKEY_[A-Z_]+\\[^\x00-\x1f"\']{2,128})')

SUSPICIOUS_KEYWORDS = [
    b"cmd.exe", b"powershell", b"-enc ", b"-EncodedCommand",
    b"Invoke-Expression", b"IEX(", b"DownloadString", b"DownloadFile",
    b"reg add", b"schtasks", b"net user", b"vssadmin delete",
    b"bcdedit", b"taskkill", b"BITSAdmin", b"certutil -decode",
    b"AddInProcess", b"rundll32", b"mshta", b"wscript.shell",
    b".onion", b"bitcoin:", b"ransom", b"decrypt your files",
    b"your files have been encrypted",
]


def extract_strings(data, min_length=4):
    """Extract printable ASCII strings from raw bytes."""
    pattern = re.compile(b'[\\x20-\\x7e]{%d,}' % min_length)
    return [m.group() for m in pattern.finditer(data)]


def analyze_strings(filepath):
    result = {
        "urls": [],
        "ips": [],
        "registry_keys": [],
        "suspicious_keywords": [],
        "total_strings": 0,
    }

    if not os.path.exists(filepath):
        return result

    with open(filepath, "rb") as f:
        data = f.read()

    strings = extract_strings(data)
    result["total_strings"] = len(strings)

    urls = set(m.decode(errors="ignore") for m in URL_PATTERN.findall(data))
    ips = set(m.decode(errors="ignore") for m in IP_PATTERN.findall(data))
    reg = set(m.decode(errors="ignore") for m in REGISTRY_PATTERN.findall(data))

    result["urls"] = list(urls)[:30]
    result["ips"] = list(ips)[:30]
    result["registry_keys"] = list(reg)[:30]

    lower_data = data.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in lower_data:
            result["suspicious_keywords"].append(kw.decode(errors="ignore"))

    return result
