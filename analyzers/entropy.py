"""
Entropy Analyzer
High Shannon entropy in a file/section suggests packing, encryption,
or compression - common techniques used to hide malicious payloads
from static signature scanners.
"""

import math
import os


def shannon_entropy(data):
    """Calculate Shannon entropy (0-8) for a chunk of bytes."""
    if not data:
        return 0.0

    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def analyze_file_entropy(filepath, chunk_size=256):
    """Whole-file entropy plus a sliding-window scan to find local
    high-entropy regions (e.g. an encrypted payload embedded in an
    otherwise normal-looking file)."""
    result = {
        "overall_entropy": 0.0,
        "high_entropy_regions": [],
        "verdict": "unknown",
    }

    if not os.path.exists(filepath):
        return result

    with open(filepath, "rb") as f:
        data = f.read()

    result["overall_entropy"] = round(shannon_entropy(data), 3)

    # Sliding window scan for localized packed/encrypted regions
    high_regions = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        e = shannon_entropy(chunk)
        if e > 7.5:
            high_regions.append({"offset": hex(i), "entropy": round(e, 2)})

    result["high_entropy_regions"] = high_regions[:20]  # cap for readability

    if result["overall_entropy"] > 7.2:
        result["verdict"] = "likely packed/encrypted"
    elif result["overall_entropy"] > 6.5:
        result["verdict"] = "moderately compressed"
    else:
        result["verdict"] = "normal"

    return result


def analyze_pe_section_entropy(pe_obj):
    """If a pefile.PE object is available, compute per-section entropy.
    More precise than whole-file since legit files often have one
    compressed resource section that skews overall entropy."""
    sections = []
    try:
        for section in pe_obj.sections:
            data = section.get_data()
            e = shannon_entropy(data)
            sections.append({
                "name": section.Name.decode(errors="ignore").strip("\x00"),
                "entropy": round(e, 3),
                "size": section.SizeOfRawData,
                "flagged": e > 7.2
            })
    except Exception:
        pass
    return sections
