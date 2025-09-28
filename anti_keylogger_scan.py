# anti_keylogger_scan.py
# Defensive-only process heuristic scanner. No keylogging capabilities.

import os
import sys
import psutil
import pathlib
import platform

SUSPICIOUS_NAME_KEYWORDS = [
    "keylog", "keylogger", "hook", "keyboard", "keystroke", "logger", "klgr"
]
SUSPICIOUS_PATH_DIRS = [
    os.getenv("TEMP") or "/tmp",
    str(pathlib.Path.home() / "AppData" / "Local" / "Temp") if platform.system() == "Windows" else "/tmp"
]

def is_run_from_suspicious_dir(path):
    if not path:
        return False
    lower = path.lower()
    for d in SUSPICIOUS_PATH_DIRS:
        if d and d.lower() in lower:
            return True
    return False

def name_matches_keyword(name):
    if not name:
        return False
    lname = name.lower()
    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in lname:
            return True
    return False

def gather_process_info(proc):
    info = {
        "pid": proc.pid,
        "name": None,
        "exe": None,
        "cmdline": None,
        "username": None,
        "ppid": None,
        "open_files": [],
        "connections": [],
        "modules": [],
    }
    try:
        info["name"] = proc.name()
    except Exception:
        pass
    try:
        info["exe"] = proc.exe()
    except Exception:
        pass
    try:
        info["cmdline"] = " ".join(proc.cmdline())
    except Exception:
        pass
    try:
        info["username"] = proc.username()
    except Exception:
        pass
    try:
        info["ppid"] = proc.ppid()
    except Exception:
        pass
    try:
        files = proc.open_files()
        info["open_files"] = [f.path for f in files]
    except Exception:
        pass
    try:
        conns = proc.connections(kind="inet")
        info["connections"] = [{"laddr": str(c.laddr), "raddr": str(c.raddr), "status": c.status} for c in conns]
    except Exception:
        pass
    try:
        maps = proc.memory_maps()
        info["modules"] = [m.path for m in maps if m.path]
    except Exception:
        pass
    return info

def score_process(info):
    score = 0
    reasons = []

    name = (info.get("name") or "").lower()
    exe = (info.get("exe") or "").lower()
    cmdline = (info.get("cmdline") or "").lower()

    if name_matches_keyword(name):
        score += 50
        reasons.append("name matches suspicious keyword")

    if is_run_from_suspicious_dir(exe):
        score += 30
        reasons.append("executable runs from temp/nonstandard directory")

    if any(kw in cmdline for kw in SUSPICIOUS_NAME_KEYWORDS):
        score += 20
        reasons.append("cmdline contains suspicious keyword")

    mods = info.get("modules") or []
    if any(any(kw in (m or "").lower() for kw in SUSPICIOUS_NAME_KEYWORDS) for m in mods):
        score += 30
        reasons.append("loaded module with suspicious name")

    if info.get("connections"):
        score += 10
        reasons.append("has network connections")

    files = info.get("open_files") or []
    if any("/tmp" in f.lower() or "temp" in f.lower() for f in files):
        score += 5
        reasons.append("opened files in temp locations")

    return score, reasons

def scan_all_processes(threshold=30):
    suspects = []
    for proc in psutil.process_iter(attrs=None):
        try:
            info = gather_process_info(proc)
            score, reasons = score_process(info)
            if score >= threshold:
                suspects.append((info, score, reasons))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    suspects.sort(key=lambda x: x[1], reverse=True)
    return suspects

def print_report(suspects):
    if not suspects:
        print("No high-confidence suspicious processes found by heuristics.")
        return
    print(f"Found {len(suspects)} suspicious process(es):\n")
    for info, score, reasons in suspects:
        print(f"PID {info.get('pid')} - {info.get('name')} (score {score})")
        print(f"  exe: {info.get('exe')}")
        print(f"  cmdline: {info.get('cmdline')}")
        print(f"  user: {info.get('username')}, ppid: {info.get('ppid')}")
        if info.get("open_files"):
            print(f"  open_files (sample): {info['open_files'][:3]}")
        if info.get("connections"):
            print(f"  connections: {info['connections']}")
        if info.get("modules"):
            print(f"  modules (sample): {info['modules'][:3]}")
        print(f"  reasons: {', '.join(reasons)}")
        print("-" * 60)

def main():
    print("Anti-keylogger heuristic scan (defensive). Running process enumeration...\n")
    suspects = scan_all_processes()
    print_report(suspects)
    print("\nNotes:")
    print("- This is heuristic scanning — investigate cautiously before killing processes.")
    print("- Run as admin/root for additional visibility (e.g., module lists, open files).")
    print("- False positives are common; use with other tools (autoruns, process explorers).")

if __name__ == "__main__":
    main()
