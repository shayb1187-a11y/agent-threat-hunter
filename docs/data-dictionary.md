# Telemetry Data Dictionary

The dataset is split into three tables, mirroring the Microsoft Defender for Endpoint /
Microsoft Sentinel *advanced hunting* schema. Real SIEM data is shaped this way, and
keeping the split is what forces us to write genuine `join` and `union` logic later.

| Our table         | Defender equivalent   | Answers the question       |
| ----------------- | --------------------- | -------------------------- |
| `process_events`  | `DeviceProcessEvents` | *What ran, and what started it?* |
| `network_events`  | `DeviceNetworkEvents` | *Who talked to what?*      |
| `logon_events`    | `DeviceLogonEvents`   | *Who authenticated where?* |

---

## Core fields (present on every event)

| Field        | Type        | Meaning | Why a hunter cares |
| ------------ | ----------- | ------- | ------------------ |
| `event_id`   | string      | Stable unique id, e.g. `evt-000322`. Assigned in chronological order. | **Evidence traceability.** Every finding, MITRE mapping and report line cites event IDs. If a claim has no ID, it is an assertion, not evidence. |
| `timestamp`  | datetime (UTC, tz-aware) | When the event was observed. | Attack chains are reconstructed by *time*. Mixing naive and aware timestamps is a classic source of silently wrong correlation, so we force UTC on load. |
| `event_type` | string      | `process` \| `network` \| `logon`. | Lets us `union` the tables into one timeline. |
| `device`     | string      | Hostname where the event was **observed**. | The blast-radius question: which machines are involved? |
| `user`       | string      | Account context the event ran under. | The identity question: whose credentials are being used? |

> Note on `device` for logons: it is the **destination** — the machine being logged
> *into*. The origin is `source_ip` / `source_device`. Getting this backwards is one of
> the most common beginner mistakes in authentication hunting.

---

## `process_events`

| Field | Type | Meaning | Detection relevance |
| ----- | ---- | ------- | ------------------- |
| `process_name` | string | Image name, e.g. `powershell.exe`. | Weak signal on its own. This dataset contains ~79 PowerShell executions, almost all benign — which is exactly the point. |
| `process_id` | Int64 | OS process ID. | Used to link a process to its network connections. |
| `command_line` | string | Full command line. | **The single richest field in endpoint telemetry.** Flags like `-enc`, `-w hidden`, `-nop` and arguments like `comsvcs.dll, MiniDump` are where intent shows up. |
| `parent_process_name` | string | What spawned it. | Context is everything: `powershell.exe` is normal; `WINWORD.EXE → powershell.exe` is not. |
| `parent_process_id` | Int64 | Parent PID. | Lets us walk a process tree. |
| `file_path` | string | Full path of the executed image. | Catches masquerading — a `svchost.exe` running from `C:\Users\...\AppData` is not the real one. |

## `network_events`

| Field | Type | Meaning | Detection relevance |
| ----- | ---- | ------- | ------------------- |
| `process_name` | string | Process that opened the connection. | Joins network activity back to process activity. `powershell.exe` making outbound connections is unusual; `chrome.exe` doing so is not. |
| `process_id` | Int64 | PID of that process. | The join key for correlating a specific execution to its traffic. |
| `remote_ip` | string | Destination address. | Infrastructure pivot: one bad IP found on one host can reveal every other compromised host. |
| `remote_port` | Int64 | Destination port. | Port 443 is normal for browsers, suspicious for `rundll32.exe`. Cleartext `80` for a script download is notable. |
| `protocol` | string | `tcp` / `udp`. | Baseline field. |
| `direction` | string | `outbound` / `inbound`. | Outbound from a workstation to the internet is the C2 direction. |
| `remote_url` | string | URL when observed; may be empty. | Highest-fidelity network artefact when present. |

## `logon_events`

| Field | Type | Meaning | Detection relevance |
| ----- | ---- | ------- | ------------------- |
| `logon_type` | Int64 | Windows logon type code (see below). | Distinguishes someone sitting at a keyboard from a remote process authenticating over the network. |
| `source_ip` | string | Where the attempt came from. | A burst of failures from a *single* source looks like brute force; from many sources it looks like password spraying. |
| `source_device` | string | Resolved source hostname; may be empty. | Human-readable pivot. |
| `action` | string | `success` / `failure`. | The failure→success transition is the classic brute-force signature. |
| `failure_reason` | string | e.g. `bad_password`. Empty on success. | Separates wrong-password from disabled-account and other causes. |

### Windows logon types you actually need to know

| Code | Name | Plain English |
| ---- | ---- | ------------- |
| 2 | Interactive | Someone typed a password at the physical console. |
| 3 | Network | A remote machine authenticated, e.g. accessing a file share over SMB. **The most common lateral-movement logon type.** |
| 4 | Batch | A scheduled task ran. |
| 5 | Service | A Windows service started under an account. |
| 10 | RemoteInteractive | RDP session. |

---

## Ground truth (`ground_truth.json`)

Labels recording which `event_id`s belong to which scenario stage.

**This file is for evaluation only.** No detection, query, or agent tool reads it.
Letting a detection see labels would be grading your own homework, and an interviewer
will ask. It exists so we can measure precision and recall honestly in a later
milestone.

Two scenarios are labelled:

- `intrusion` — a 10-stage simulated compromise of `PC01` pivoting to `FS02`.
- `benign_lookalike` — legitimate IT administration engineered to trip naive rules.

Labelled events are **under 5% of the dataset**, enforced by a unit test.
