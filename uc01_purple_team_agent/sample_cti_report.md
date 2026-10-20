# Threat Intelligence Advisory: FIN-SHADOW Credential Dumping & Scheduled Task Persistence

- **Advisory ID:** CTI-2026-0419
- **Threat Actor / Campaign:** UNC-SHADOW / FIN-SHADOW Intrusion Set
- **Targeted Sectors:** Financial Services, Critical Infrastructure, Cloud & SaaS Providers
- **Severity:** HIGH (CVSS 8.8)
- **MITRE ATT&CK Tactics & Techniques:**
  - **Credential Access:** `T1003.001` — OS Credential Dumping: LSASS Memory (via `rundll32.exe` and `comsvcs.dll` `MiniDump`)
  - **Persistence / Execution:** `T1053.005` — Scheduled Task/Job: Scheduled Task (via `schtasks.exe /create`)

---

## 1. Executive Summary

During recent incident response engagements, Mandiant and Google Threat Intelligence (GTI) observed threat actors leveraging living-off-the-land binaries (LOLBins) on Windows Server and Windows 10/11 endpoints to harvest credentials from the Local Security Authority Subsystem Service (`lsass.exe`) process memory without dropping third-party tools such as Mimikatz or ProcDump to disk.

Immediately prior to or following credential extraction, the adversary establishes local and lateral persistence by registering high-privilege Scheduled Tasks (`SYSTEM` context) masquerading as routine Windows telemetry maintenance jobs.

---

## 2. Technical Analysis & Observed TTPs

### 2.1. TTP #1: LSASS Memory Dumping via `rundll32.exe` and `comsvcs.dll` (`MITRE T1003.001`)

The native Windows library `C:\Windows\System32\comsvcs.dll` exports the `MiniDump` (and `MiniDumpW`) function, which accepts a Process ID (PID) of `lsass.exe`, an output dump file path, and the argument `full`. Threat actors invoke this export via `rundll32.exe` (both by function name and by ordinal `#24`) to write a full memory dump of `lsass.exe` into staging directories such as `C:\Windows\Temp\` or `C:\ProgramData\`.

#### Observed Command Lines:
```cmd
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 672 C:\Windows\Temp\debug_crash.dmp full
rundll32.exe C:\Windows\System32\comsvcs.dll,#24 672 C:\ProgramData\msupdate.bin full
cmd.exe /Q /c for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump ^%B \Windows\Temp\lsass_out.dmp full
```

#### Key UDM Telemetry Indicators (Google SecOps SIEM):
- **`metadata.event_type`:** `PROCESS_LAUNCH` or `PROCESS_OPEN`
- **`target.process.file.full_path`:** `C:\Windows\System32\rundll32.exe`
- **`target.process.command_line`:** Contains `comsvcs.dll` and either `MiniDump` or `#24` along with `full`
- **`principal.user.userid`:** Elevated local administrator or `SYSTEM`

---

### 2.2. TTP #2: Persistence via Scheduled Task Creation (`MITRE T1053.005`)

To maintain access across reboots and credential rotations, the adversary creates a scheduled task using `schtasks.exe` executing a staged PowerShell or rundll32 payload under `NT AUTHORITY\SYSTEM`.

#### Observed Command Lines:
```cmd
schtasks.exe /create /tn "\Microsoft\Windows\Diagnosis\RecommendedTelemetrySync" /tr "powershell.exe -NoP -NonI -W Hidden -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg..." /sc MINUTE /mo 30 /ru SYSTEM /f
```

#### Key UDM Telemetry Indicators (Google SecOps SIEM):
- **`metadata.event_type`:** `PROCESS_LAUNCH`
- **`target.process.file.full_path`:** `C:\Windows\System32\schtasks.exe`
- **`target.process.command_line`:** Contains `/create`, `/tn`, `/tr`, and `/ru SYSTEM` (or encoded PowerShell execution flags `-Enc`, `-W Hidden`).

---

## 3. Recommended Detection Engineering Actions (`UC-01`)

1. **Extract Threat Detection Opportunities (TDOs):** Parse this advisory using `generate_threat_detection_opportunity` to isolate behavioral detection blueprints for `T1003.001` (`rundll32` + `comsvcs.dll` `MiniDump`) and `T1053.005` (`schtasks.exe /create` suspicious persistence).
2. **Generate Synthetic UDM Telemetry:** Synthesize realistic `PROCESS_LAUNCH` UDM events (`generate_synthetic_events`) representing the exact command-line variants above (standard `MiniDump`, ordinal `#24`, and `cmd.exe` tasklist wrapper).
3. **Evaluate Rule Coverage:** Execute `evaluate_rule_coverage_long_running` against the active SecOps rule corpus and verify `alertingEnabled` status on any matched rules.
4. **Author & Validate YARA-L 2.0 Rules:** Where coverage gaps exist, generate (`generate_rules`), compile-check (`validate_rule`), retro-test over 72 hours for false positives (`list_rule_detections`), and deploy (`create_rule`) production-ready YARA-L 2.0 detections.
