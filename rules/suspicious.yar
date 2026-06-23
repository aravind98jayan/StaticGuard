/*
  Custom YARA ruleset for static malware triage project.
  These are educational/heuristic rules, not production-grade signatures.
  Combine with entropy + import analysis for the overall risk score.
*/

rule Suspicious_Ransom_Note_Strings
{
    meta:
        description = "Strings commonly found in ransomware notes"
        severity = "high"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "pay the ransom" nocase
        $s4 = "bitcoin" nocase
        $s5 = ".onion"
    condition:
        2 of them
}

rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "Encoded/obfuscated PowerShell execution patterns"
        severity = "high"
    strings:
        $a1 = "-EncodedCommand" nocase
        $a2 = "-enc " nocase
        $a3 = "IEX(" nocase
        $a4 = "Invoke-Expression" nocase
        $a5 = "DownloadString" nocase
        $a6 = "FromBase64String" nocase
    condition:
        2 of them
}

rule Possible_Process_Injection
{
    meta:
        description = "API combination typical of process injection techniques"
        severity = "high"
    strings:
        $i1 = "VirtualAllocEx"
        $i2 = "WriteProcessMemory"
        $i3 = "CreateRemoteThread"
        $i4 = "NtUnmapViewOfSection"
    condition:
        2 of them
}

rule Suspicious_Persistence_Mechanism
{
    meta:
        description = "Common Windows persistence techniques"
        severity = "medium"
    strings:
        $p1 = "CurrentVersion\\Run" nocase
        $p2 = "schtasks" nocase
        $p3 = "CurrentVersion\\RunOnce" nocase
        $p4 = "StartupApproved" nocase
    condition:
        any of them
}

rule Known_Packer_Signature
{
    meta:
        description = "Common packer/protector section names"
        severity = "low"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = ".aspack"
        $u4 = ".themida"
        $u5 = ".vmp0"
    condition:
        any of them
}

rule Anti_Debug_Anti_VM
{
    meta:
        description = "Anti-analysis / sandbox evasion indicators"
        severity = "medium"
    strings:
        $d1 = "IsDebuggerPresent"
        $d2 = "CheckRemoteDebuggerPresent"
        $d3 = "VMware" nocase
        $d4 = "VirtualBox" nocase
        $d5 = "Sandboxie" nocase
    condition:
        2 of them
}

rule Suspicious_Network_Beacon_Strings
{
    meta:
        description = "Generic C2/network beacon indicators"
        severity = "medium"
    strings:
        $n1 = "User-Agent:" nocase
        $n2 = "POST /" nocase
        $n3 = "Mozilla/5.0" nocase
        $n4 = /https?:\/\/[a-z0-9\-\.]+\.(top|xyz|club|tk|icu)/ nocase
    condition:
        2 of them
}

rule EICAR_Test_File
{
    meta:
        description = "Industry-standard EICAR antivirus test string (NOT real malware)"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
