"""
PE Header & Structure Analyzer
Inspects Windows PE (.exe/.dll) files for structural red flags commonly
associated with malicious or packed binaries.
"""

import pefile
import os

# APIs commonly abused for process injection / evasion
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": "Remote memory allocation (process injection)",
    "WriteProcessMemory": "Writing to another process's memory",
    "CreateRemoteThread": "Executing code in another process",
    "SetWindowsHookEx": "Keylogging / hooking",
    "GetAsyncKeyState": "Keystroke capture",
    "NtUnmapViewOfSection": "Process hollowing",
    "ZwUnmapViewOfSection": "Process hollowing",
    "VirtualProtect": "Changing memory permissions (often pre-shellcode exec)",
    "WinExec": "Command execution",
    "ShellExecuteA": "Command execution",
    "URLDownloadToFileA": "File download capability",
    "InternetOpenA": "Network communication",
    "CreateToolhelp32Snapshot": "Process enumeration (often used to find AV/targets)",
    "IsDebuggerPresent": "Anti-debugging check",
    "CheckRemoteDebuggerPresent": "Anti-debugging check",
    "GetTickCount": "Possible sandbox/timing evasion",
}

SUSPICIOUS_SECTION_NAMES = [".upx", ".aspack", ".petite", ".themida", ".vmp"]


def analyze_pe(filepath):
    """Returns a dict of findings, or an error dict if not a valid PE."""
    result = {
        "valid_pe": False,
        "is_signed": False,
        "suspicious_imports": [],
        "suspicious_sections": [],
        "num_sections": 0,
        "compile_timestamp": None,
        "errors": [],
        "warnings": [],
    }

    if not os.path.exists(filepath):
        result["errors"].append("File not found")
        return result

    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
        ])
        result["valid_pe"] = True
    except pefile.PEFormatError as e:
        result["errors"].append(f"Not a valid PE file: {e}")
        return result
    except Exception as e:
        result["errors"].append(f"Could not parse PE: {e}")
        return result

    # Digital signature check (presence of security directory != valid sig,
    # but absence is a strong signal for unsigned/untrusted binaries)
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ]
        result["is_signed"] = sec_dir.VirtualAddress != 0
    except Exception:
        pass

    # Compile timestamp (zero or far-future timestamps are suspicious)
    try:
        result["compile_timestamp"] = pe.FILE_HEADER.TimeDateStamp
    except Exception:
        pass

    # Section name check
    result["num_sections"] = len(pe.sections)
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00").lower()
        if any(bad in name for bad in SUSPICIOUS_SECTION_NAMES):
            result["suspicious_sections"].append(name)

    # Import table check
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode(errors="ignore")
                        if fname in SUSPICIOUS_IMPORTS:
                            result["suspicious_imports"].append({
                                "function": fname,
                                "reason": SUSPICIOUS_IMPORTS[fname],
                                "dll": entry.dll.decode(errors="ignore")
                            })
        else:
            result["warnings"].append("No import table found (unusual for legitimate PE files)")
    except Exception as e:
        result["warnings"].append(f"Import parsing issue: {e}")

    if result["num_sections"] == 0:
        result["warnings"].append("No sections found - highly unusual")

    pe.close()
    return result
