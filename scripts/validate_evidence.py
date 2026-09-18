from pathlib import Path
import csv
import hashlib
import re

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "challenge" / "evidence"

LOGS = EVIDENCE / "logs"
BROWSER = EVIDENCE / "browser"
FILESYSTEM = EVIDENCE / "filesystem"
SAMPLES = EVIDENCE / "samples"


def check(condition, message):
    if condition:
        print(f"[PASS] {message}")
        return True

    print(f"[FAIL] {message}")
    return False


print("=" * 60)
print("FORENSIC TRACE - EVIDENCE VALIDATION")
print("=" * 60)

results = []


# ---------------------------------------------------------
# Required files
# ---------------------------------------------------------

required_files = [
    LOGS / "auth.log",
    LOGS / "network.log",
    LOGS / "powershell.log",
    LOGS / "security.log",
    BROWSER / "history.csv",
    FILESYSTEM / "timeline.csv",
    FILESYSTEM / "scheduled_tasks.txt",
    FILESYSTEM / "hashes.txt",
    SAMPLES / "meeting_update.exe",
    SAMPLES / "update.ps1",
    EVIDENCE / "manifest.csv",
]

for path in required_files:
    results.append(
        check(path.exists(), f"Evidence exists: {path.name}")
    )


# ---------------------------------------------------------
# Hostname
# ---------------------------------------------------------

auth = (LOGS / "auth.log").read_text(encoding="utf-8")

results.append(
    check(
        "NS-WS-047" in auth,
        "Compromised workstation hostname is present"
    )
)


# ---------------------------------------------------------
# Suspicious user
# ---------------------------------------------------------

results.append(
    check(
        "user=j.smith" in auth,
        "User j.smith appears in authentication evidence"
    )
)


# ---------------------------------------------------------
# Suspicious source IP
# ---------------------------------------------------------

results.append(
    check(
        "10.20.14.33" in auth,
        "Suspicious source IP 10.20.14.33 appears in authentication evidence"
    )
)


# ---------------------------------------------------------
# Downloaded file
# ---------------------------------------------------------

network = (LOGS / "network.log").read_text(encoding="utf-8")

results.append(
    check(
        "meeting_update.exe" in network,
        "meeting_update.exe appears in network evidence"
    )
)


# ---------------------------------------------------------
# Process creation
# ---------------------------------------------------------

security = (LOGS / "security.log").read_text(encoding="utf-8")

results.append(
    check(
        "EventID=4688" in security,
        "Windows process creation event 4688 is present"
    )
)


# ---------------------------------------------------------
# PowerShell
# ---------------------------------------------------------

results.append(
    check(
        "powershell.exe" in security,
        "PowerShell process appears in security evidence"
    )
)


# ---------------------------------------------------------
# Persistence
# ---------------------------------------------------------

scheduled_tasks = (
    FILESYSTEM / "scheduled_tasks.txt"
).read_text(encoding="utf-8")

results.append(
    check(
        "WindowsUpdateCheck" in scheduled_tasks,
        "WindowsUpdateCheck persistence artifact is present"
    )
)


# ---------------------------------------------------------
# PowerShell script path
# ---------------------------------------------------------

results.append(
    check(
        r"AppData\Roaming\update.ps1" in scheduled_tasks,
        "update.ps1 persistence path is present"
    )
)


# ---------------------------------------------------------
# Static-analysis strings
# ---------------------------------------------------------

sample = (SAMPLES / "meeting_update.exe").read_bytes()

for string in [
    b"CreateProcessA",
    b"powershell.exe",
    b"WindowsUpdateCheck",
    b"update.ps1",
    b"STATIC_ANALYSIS_ONLY",
]:
    results.append(
        check(
            string in sample,
            f"Static-analysis indicator present: {string.decode()}"
        )
    )


# ---------------------------------------------------------
# Verify the executable is NOT a real PE executable
# ---------------------------------------------------------

# The file starts with MZ and PE markers but does not contain
# a valid Windows PE structure. It is intentionally harmless.

results.append(
    check(
        len(sample) < 1000,
        "Sample executable is intentionally small"
    )
)


# ---------------------------------------------------------
# Hash verification
# ---------------------------------------------------------

hash_file = FILESYSTEM / "hashes.txt"
hash_text = hash_file.read_text(encoding="utf-8")

for filename in ["meeting_update.exe", "update.ps1"]:
    path = SAMPLES / filename
    data = path.read_bytes()

    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    results.append(
        check(
            sha256 in hash_text,
            f"SHA-256 verified for {filename}"
        )
    )

    results.append(
        check(
            sha1 in hash_text,
            f"SHA-1 verified for {filename}"
        )
    )

    results.append(
        check(
            md5 in hash_text,
            f"MD5 verified for {filename}"
        )
    )


# ---------------------------------------------------------
# Browser evidence
# ---------------------------------------------------------

with (BROWSER / "history.csv").open(
    newline="",
    encoding="utf-8"
) as f:
    rows = list(csv.DictReader(f))

browser_text = "\n".join(
    ",".join(row.values()) for row in rows
)

results.append(
    check(
        "meeting_update.exe" in browser_text,
        "Browser history contains the suspicious download"
    )
)


# ---------------------------------------------------------
# Timeline evidence
# ---------------------------------------------------------

timeline = (FILESYSTEM / "timeline.csv").read_text(
    encoding="utf-8"
)

results.append(
    check(
        "FILE_CREATED" in timeline,
        "Filesystem creation events are present"
    )
)

results.append(
    check(
        "PROCESS_STARTED" in timeline,
        "Filesystem process events are present"
    )
)


# ---------------------------------------------------------
# Final result
# ---------------------------------------------------------

print()
print("=" * 60)

passed = sum(results)
total = len(results)

print(f"VALIDATION RESULT: {passed}/{total} checks passed")

if passed == total:
    print("[SUCCESS] Evidence package is internally consistent.")
    print("[SUCCESS] Ready for challenge-question development.")
else:
    print("[WARNING] Evidence requires correction.")

print("=" * 60)