#!/usr/bin/env python3
"""
Procmon PML triage. Single streaming pass, prints targeted slices.

    pip install procmon-parser
    python pml_triage.py Logfile.PML            # full output
    python pml_triage.py Logfile.PML --counts   # shape only, no contents
"""
import sys, re
from procmon_parser import ProcmonLogsReader

PML = sys.argv[1] if len(sys.argv) > 1 else "Logfile.PML"
COUNTS_ONLY = "--counts" in sys.argv

# Directories that legitimately host loaded modules.
SYSDIRS = re.compile(
    r"^C:\\(Windows\\(System32|SysWOW64|WinSxS|SystemApps|ShellExperiences|"
    r"assembly|Microsoft\.NET|InfusedApps|Speech|Speech_OneCore|Fonts)\\|"
    r"Program Files( \(x86\))?\\)", re.I)

# User-writable / suspicious drop locations.
DROP = re.compile(r"\\(AppData|Temp|ProgramData|Users\\Public|Downloads|Windows\\Temp)\\", re.I)

# Proxy-execution LOLBins.
LOLBIN = re.compile(r"\b(rundll32|regsvr32|mshta|wscript|cscript|powershell|"
                    r"msiexec|installutil|certutil|odbcconf)\b", re.I)

buckets = {k: [] for k in (
    "proc_create", "mod_nonsys", "mod_drop", "mutex", "crypto",
    "lolbin", "net", "exe_write", "regload")}

def det(e):
    d = e.details or {}
    return " | ".join(f"{k}={v}" for k, v in d.items() if v not in (None, "", 0))

def ts(e):
    try:
        return e.date().isoformat()
    except TypeError:
        return str(e.date)

with open(PML, "rb") as f:
    for e in ProcmonLogsReader(f):
        op, path = e.operation, (e.path or "")
        pname = e.process.process_name
        cmd = getattr(e.process, "command_line", "") or ""

        if op in ("Process_Create", "Process_Start"):
            buckets["proc_create"].append((ts(e), pname, e.process.pid, det(e), cmd))

        elif op == "Load_Image":
            if not SYSDIRS.match(path):
                buckets["mod_nonsys"].append((ts(e), pname, e.process.pid, path))
            if DROP.search(path):
                buckets["mod_drop"].append((ts(e), pname, e.process.pid, path))

        elif op == "RegLoadKey":
            buckets["regload"].append((ts(e), pname, path, det(e)))

        if "BaseNamedObjects" in path:
            buckets["mutex"].append((pname, op, path))

        if re.search(r"Cryptography|MachineGuid|DigitalProductId|HardwareProfileGuid", path, re.I):
            buckets["crypto"].append((pname, op, path, det(e)))

        if LOLBIN.search(cmd) or LOLBIN.search(path):
            buckets["lolbin"].append((ts(e), pname, path, cmd))

        if op.startswith(("TCP", "UDP")):
            buckets["net"].append((ts(e), pname, op, path))

        if op == "WriteFile" and re.search(r"\.(dll|exe|sys|scr|ocx)$", path, re.I):
            buckets["exe_write"].append((ts(e), pname, path))

TITLES = {
    "proc_create": "PROCESS CREATION  -> Q1 (origin), Q3 (export in cmdline)",
    "mod_nonsys":  "MODULES OUTSIDE SYSTEM DIRS  -> Q1/Q2 (module + load time)",
    "mod_drop":    "MODULES FROM USER-WRITABLE DIRS  (subset, highest signal)",
    "exe_write":   "EXECUTABLE FILES WRITTEN  -> who dropped the module",
    "lolbin":      "PROXY EXECUTION (rundll32/regsvr32/...)  -> Q3 export name",
    "mutex":       "NAMED OBJECTS  -> Q5 mutex",
    "crypto":      "MACHINE-UNIQUE CRYPTO VALUES  -> Q4 RC4 key seed",
    "net":         "NETWORK OPS  -> Q7 (cross-check vs pcap)",
    "regload":     "REGISTRY HIVE LOADS  (hive access = offline creds)",
}

for k, title in TITLES.items():
    rows = buckets[k]
    uniq = {tuple(str(x) for x in r[1:]) for r in rows}
    print(f"\n{'='*78}\n{title}\n  events={len(rows):,}  unique={len(uniq):,}")
    if COUNTS_ONLY:
        continue
    seen = set()
    for r in rows:
        key = tuple(str(x) for x in r[1:])
        if key in seen:
            continue
        seen.add(key)
        print("   " + "  |  ".join(str(x)[:110] for x in r))