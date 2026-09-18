from pathlib import Path
import csv
import hashlib
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "challenge" / "evidence"

LOGS = EVIDENCE / "logs"
BROWSER = EVIDENCE / "browser"
FILESYSTEM = EVIDENCE / "filesystem"
SAMPLES = EVIDENCE / "samples"

for directory in [LOGS, BROWSER, FILESYSTEM, SAMPLES]:
    directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# Authentication log
# ---------------------------------------------------------

auth_log = """\
HOST=NS-WS-047

2026-08-14 08:42:11 INFO LOGIN SUCCESS user=j.smith src=10.20.14.21
2026-08-14 08:51:03 INFO LOGIN SUCCESS user=a.patel src=10.20.14.18
2026-08-14 09:03:17 INFO LOGIN SUCCESS user=j.smith src=10.20.14.21
2026-08-14 09:11:04 INFO LOGIN SUCCESS user=j.smith src=10.20.14.33
2026-08-14 09:13:22 INFO SESSION START user=j.smith src=10.20.14.33
2026-08-14 09:17:23 INFO FILE DOWNLOAD user=j.smith src=10.20.14.33 file=meeting_update.exe
2026-08-14 09:19:41 INFO PROCESS START user=j.smith process=meeting_update.exe
2026-08-14 09:19:45 INFO PROCESS START user=j.smith process=powershell.exe
2026-08-14 09:25:12 INFO LOGIN SUCCESS user=administrator src=10.20.14.33
2026-08-14 09:25:41 INFO PROCESS START user=administrator process=powershell.exe
2026-08-14 09:30:02 INFO SCHEDULED TASK CREATED user=administrator task=WindowsUpdateCheck
2026-08-14 09:41:27 INFO SESSION END user=j.smith src=10.20.14.33
"""

(LOGS / "auth.log").write_text(auth_log, encoding="utf-8")


# ---------------------------------------------------------
# Network log
# ---------------------------------------------------------

network_log = """\
2026-08-14 09:16:58 DNS QUERY host=NS-WS-047 domain=updates-northstar.example
2026-08-14 09:17:12 HTTP GET host=NS-WS-047 url=http://updates-northstar.example/
2026-08-14 09:17:23 HTTP GET host=NS-WS-047 path=/download/meeting_update.exe status=200
2026-08-14 09:17:23 DOWNLOAD file=meeting_update.exe size=206
2026-08-14 09:18:54 DNS QUERY host=NS-WS-047 domain=cdn-northstar.example
2026-08-14 09:19:41 PROCESS NETWORK ACTIVITY process=meeting_update.exe
2026-08-14 09:19:45 PROCESS NETWORK ACTIVITY process=powershell.exe
"""

(LOGS / "network.log").write_text(network_log, encoding="utf-8")


# ---------------------------------------------------------
# PowerShell log
# ---------------------------------------------------------

powershell_log = """\
2026-08-14 09:19:45 USER=j.smith HOST=NS-WS-047
Command: powershell.exe -File C:\\Users\\j.smith\\AppData\\Roaming\\update.ps1

2026-08-14 09:19:46 USER=j.smith HOST=NS-WS-047
Script: update.ps1
Action: Create persistence configuration

2026-08-14 09:25:41 USER=administrator HOST=NS-WS-047
Command: powershell.exe -File C:\\Users\\j.smith\\AppData\\Roaming\\update.ps1

2026-08-14 09:25:42 USER=administrator HOST=NS-WS-047
Script: update.ps1
Action: Verify persistence configuration
"""

(LOGS / "powershell.log").write_text(powershell_log, encoding="utf-8")


# ---------------------------------------------------------
# Windows Security Event simulation
# ---------------------------------------------------------

security_log = """\
EventID=4624 Time=2026-08-14T09:11:04 User=j.smith SourceIP=10.20.14.33
EventID=4688 Time=2026-08-14T09:19:41 User=j.smith NewProcess=meeting_update.exe
EventID=4688 Time=2026-08-14T09:19:45 User=j.smith NewProcess=powershell.exe
EventID=4698 Time=2026-08-14T09:30:02 User=administrator TaskName=WindowsUpdateCheck
"""

(LOGS / "security.log").write_text(security_log, encoding="utf-8")


# ---------------------------------------------------------
# Browser history
# ---------------------------------------------------------

browser_rows = [
    ["timestamp", "user", "url", "title", "download"],
    [
        "2026-08-14 09:16:58",
        "j.smith",
        "http://search.example/",
        "Internal Search",
        "",
    ],
    [
        "2026-08-14 09:17:12",
        "j.smith",
        "http://updates-northstar.example/",
        "Northstar Software Update",
        "",
    ],
    [
        "2026-08-14 09:17:23",
        "j.smith",
        "http://updates-northstar.example/download/meeting_update.exe",
        "Software Update",
        "meeting_update.exe",
    ],
]

with (BROWSER / "history.csv").open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(browser_rows)


# ---------------------------------------------------------
# Suspicious PowerShell script
# ---------------------------------------------------------

update_script = r"""\
# Northstar Software Update Verification
# This file is intentionally harmless and is provided for forensic analysis.

$TaskName = "WindowsUpdateCheck"
$ScriptPath = "C:\Users\j.smith\AppData\Roaming\update.ps1"

Write-Output "Checking software update configuration..."
Write-Output "Task: $TaskName"
Write-Output "Path: $ScriptPath"
Write-Output "Simulation mode enabled."
"""

(SAMPLES / "update.ps1").write_text(update_script, encoding="utf-8")


# ---------------------------------------------------------
# Harmless PE-like sample
# ---------------------------------------------------------

# This is NOT executable malware.
# It is simply a binary-looking file containing forensic strings
# that learners can inspect with strings/file/hex tools.

sample_content = (
    b"MZ"
    + b"\x00" * 58
    + b"PE\x00\x00"
    + b"Northstar Software Update"
    + b"\x00"
    + b"meeting_update.exe"
    + b"\x00"
    + b"CreateProcessA"
    + b"\x00"
    + b"powershell.exe"
    + b"\x00"
    + b"WindowsUpdateCheck"
    + b"\x00"
    + b"AppData\\Roaming\\update.ps1"
    + b"\x00"
    + b"STATIC_ANALYSIS_ONLY"
    + b"\x00"
)

(SAMPLES / "meeting_update.exe").write_bytes(sample_content)


# ---------------------------------------------------------
# Filesystem metadata
# ---------------------------------------------------------

filesystem_rows = [
    [
        "timestamp",
        "path",
        "event",
    ],
    [
        "2026-08-14 09:17:23",
        r"C:\Users\j.smith\Downloads\meeting_update.exe",
        "FILE_CREATED",
    ],
    [
        "2026-08-14 09:19:41",
        r"C:\Users\j.smith\Downloads\meeting_update.exe",
        "PROCESS_STARTED",
    ],
    [
        "2026-08-14 09:19:45",
        r"C:\Users\j.smith\AppData\Roaming\update.ps1",
        "FILE_CREATED",
    ],
    [
        "2026-08-14 09:30:02",
        r"C:\Users\j.smith\AppData\Roaming\update.ps1",
        "PERSISTENCE_REFERENCED",
    ],
]

with (FILESYSTEM / "timeline.csv").open(
    "w", newline="", encoding="utf-8"
) as f:
    writer = csv.writer(f)
    writer.writerows(filesystem_rows)


# ---------------------------------------------------------
# Persistence artifact
# ---------------------------------------------------------

persistence = """\
Task Name: WindowsUpdateCheck
Account: administrator
Created: 2026-08-14 09:30:02

Action:
powershell.exe -File C:\\Users\\j.smith\\AppData\\Roaming\\update.ps1

Trigger:
At logon
"""

(FILESYSTEM / "scheduled_tasks.txt").write_text(
    persistence,
    encoding="utf-8",
)


# ---------------------------------------------------------
# Calculate hashes
# ---------------------------------------------------------

hash_lines = []

for filename in ["meeting_update.exe", "update.ps1"]:
    path = SAMPLES / filename
    data = path.read_bytes()

    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    hash_lines.append(f"{filename}")
    hash_lines.append(f"SHA256: {sha256}")
    hash_lines.append(f"SHA1:   {sha1}")
    hash_lines.append(f"MD5:    {md5}")
    hash_lines.append("")

(FILESYSTEM / "hashes.txt").write_text(
    "\n".join(hash_lines),
    encoding="utf-8",
)


# ---------------------------------------------------------
# Evidence manifest
# ---------------------------------------------------------

manifest = [
    ["Evidence ID", "Filename", "Type", "Description"],
    ["EVID-001", "auth.log", "LOG", "Authentication activity"],
    ["EVID-002", "network.log", "LOG", "Network activity"],
    ["EVID-003", "powershell.log", "LOG", "PowerShell activity"],
    ["EVID-004", "security.log", "LOG", "Windows security events"],
    ["EVID-005", "history.csv", "BROWSER", "Browser history"],
    ["EVID-006", "timeline.csv", "FORENSICS", "Filesystem timeline"],
    ["EVID-007", "scheduled_tasks.txt", "FORENSICS", "Persistence artifact"],
    ["EVID-008", "meeting_update.exe", "SAMPLE", "Suspicious file"],
    ["EVID-009", "update.ps1", "SAMPLE", "Suspicious script"],
]

with (EVIDENCE / "manifest.csv").open(
    "w", newline="", encoding="utf-8"
) as f:
    writer = csv.writer(f)
    writer.writerows(manifest)


print("=" * 60)
print("FORENSIC TRACE EVIDENCE GENERATED")
print("=" * 60)
print(f"Evidence directory: {EVIDENCE}")
print()
print("Generated:")
print("  [OK] Authentication log")
print("  [OK] Network log")
print("  [OK] PowerShell log")
print("  [OK] Security event log")
print("  [OK] Browser history")
print("  [OK] Suspicious executable sample")
print("  [OK] Suspicious PowerShell script")
print("  [OK] Filesystem timeline")
print("  [OK] Persistence artifact")
print("  [OK] Hash database")
print("  [OK] Evidence manifest")
print()
print("IMPORTANT: meeting_update.exe is a NON-EXECUTABLE")
print("forensic sample designed for static analysis.")
print("=" * 60)