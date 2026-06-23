"""
YARA Rule Scanner
Runs the custom ruleset against a target file and returns matches
with severity metadata.
"""

import os
import yara

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "suspicious.yar")


def load_rules(rules_path=RULES_PATH):
    try:
        return yara.compile(filepath=rules_path)
    except yara.SyntaxError as e:
        raise RuntimeError(f"YARA rule syntax error: {e}")
    except Exception as e:
        raise RuntimeError(f"Could not load YARA rules: {e}")


def scan_file(filepath, rules_path=RULES_PATH):
    result = {"matches": [], "error": None}

    if not os.path.exists(filepath):
        result["error"] = "File not found"
        return result

    try:
        rules = load_rules(rules_path)
        matches = rules.match(filepath)
        for m in matches:
            result["matches"].append({
                "rule": m.rule,
                "severity": m.meta.get("severity", "unknown"),
                "description": m.meta.get("description", ""),
                "matched_strings": [s.identifier for s in m.strings] if hasattr(m, "strings") else []
            })
    except Exception as e:
        result["error"] = str(e)

    return result
