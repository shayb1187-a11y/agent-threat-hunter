# KQL Hunting Queries

There are 20 `.kql` files, one per registered pandas detector. The rule ID in each
filename provides the mapping; it does not guarantee identical query semantics.
See the [project README](../README.md#detections) for the current detector catalogue.

## Read this first: execution and schema assumptions

**The pandas detectors are the executable implementation tested by ATH.** These KQL
files are reference queries, not a local execution backend, and have not been
validated against a live Defender/Sentinel tenant as part of this review.

| Rule family | Query input |
| --- | --- |
| `ATH-001`–`ATH-012` | Defender advanced-hunting tables; some examples use additional tables beyond ATH's canonical telemetry. |
| `AWS-001`–`AWS-006` | Sentinel `AWSCloudTrail`; inspect each query's column assumptions. |
| `K8S-001`–`K8S-002` | An illustrative custom `KubeAuditLogs` table; adapt it to your ingestion schema. |

Read the comments in each query before using it. For example, several cloud queries
use fixed time buckets while their pandas counterparts use sliding episodes. Those
can return different results at bucket boundaries. ATH-004 also demonstrates
handle-access telemetry that the Python detector does not ingest. The tests check
rule/file coverage, not live execution or exact parity.

These queries do not execute against ATH's CSVs. Use the normal Python hunting CLI
for local telemetry; a KQL environment must have the query's expected tables.

## Schema mapping: our CSVs → Defender

| Our table / column | Defender table / column |
| --- | --- |
| `process_events` | `DeviceProcessEvents` |
| `network_events` | `DeviceNetworkEvents` |
| `logon_events` | `DeviceLogonEvents` |
| `timestamp` | `Timestamp` |
| `device` | `DeviceName` |
| `user` | `AccountName` for process/logon; `InitiatingProcessAccountName` for network |
| `process_name` | `FileName` for process; `InitiatingProcessFileName` for network |
| `command_line` | `ProcessCommandLine` |
| `parent_process_name` | `InitiatingProcessFileName` |
| `parent_process_id` | `InitiatingProcessId` |
| `file_path` | `FolderPath` |
| `remote_ip` / `remote_port` | `RemoteIP` / `RemotePort` |
| `action` (logon) | `ActionType` (`LogonSuccess` / `LogonFailed`) |
| `source_ip` / `source_device` | `RemoteIP` / `RemoteDeviceName` |
| `event_id` | ATH-generated ID; the original `ReportId` and source location are retained in `source_ref` |

Defender documents event uniqueness using `ReportId`, `DeviceName` and `Timestamp`
together; `ReportId` alone repeats. See [Microsoft’s table reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table).

> Note the naming trap: in `DeviceNetworkEvents`, `RemoteIP` is the **destination**.
> In `DeviceLogonEvents`, `RemoteIP` is the **source** of the authentication. Same
> column name, opposite direction. This catches people out constantly.

---

# KQL in 10 minutes

KQL (Kusto Query Language) is a **pipeline** language. You start with a table and push
rows through `|` operators, left to right. Unlike SQL, order of operations is literally
the order you write them.

```kusto
DeviceProcessEvents          // start with a table
| where Timestamp > ago(24h) // then filter
| project DeviceName, FileName  // then choose columns
```

### `where` — filter rows
The pandas equivalent of boolean masking.

```kusto
| where FileName == "powershell.exe"
```
```python
df[df["process_name"] == "powershell.exe"]
```

**Filter early, especially on time.** Datetime predicates can eliminate data shards
before other work; runtime still depends on data size and query shape. See
[Microsoft’s query best practices](https://learn.microsoft.com/en-us/kusto/query/best-practices?view=azure-monitor).

### `ago()` — relative time
`ago(1h)`, `ago(7d)`, `ago(30m)`. Returns a datetime that far in the past.

```kusto
| where Timestamp > ago(7d)
```
```python
df[df["timestamp"] > pd.Timestamp.utcnow() - pd.Timedelta(days=7)]
```

### `contains` vs `has` — **the question you will be asked**

| Operator | Matches | Speed |
| --- | --- | --- |
| `contains` | substring | generally scans values |
| `has` | whole term | can use the term index for terms of at least three characters |
| `has_any` | any listed term | index use depends on term length and list size |
| `startswith` / `endswith` | prefix / suffix | depends on query and data |

Kusto splits string columns into terms at non-alphanumeric boundaries and indexes those
terms of at least three characters. Shorter terms require scanning; substring
searches do not use that term index. See [string operators](https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators).

```kusto
| where ProcessCommandLine has "mimikatz"        // fast, matches the word
| where ProcessCommandLine contains "kat"        // slow, matches inside words
```

The catch: `has` will **not** match a partial word. `ProcessCommandLine has "lsass"`
matches `dump lsass.exe` (because `lsass` is its own term) but **not** `dumplsassmem`.
So the rule is: reach for `has` first for performance, fall back to `contains` when you
need substring matching. `has` and `contains` are already case-insensitive; their
`_cs` variants are case-sensitive. Equality and membership use `=~` and `in~` for
case-insensitive comparison.

### `project` / `extend` — choose and add columns

`project` selects columns (and can rename). `extend` adds a computed column, keeping
everything else.

```kusto
| extend ParentChild = strcat(InitiatingProcessFileName, " -> ", FileName)
| project Timestamp, DeviceName, ParentChild
```
```python
df = df.assign(parent_child=df["parent_process_name"] + " -> " + df["process_name"])
df[["timestamp", "device", "parent_child"]]
```

`project-away` drops columns; `project-rename` renames without listing everything.

### `summarize` — aggregate

The `groupby` equivalent. `by` names the grouping keys.

```kusto
| summarize Failures = count(), FirstSeen = min(Timestamp) by DeviceName, AccountName
```
```python
df.groupby(["device", "user"]).agg(failures=("event_id", "count"),
                                   first_seen=("timestamp", "min"))
```

Aggregation functions you will use constantly:

- `count()`, `dcount(Col)` — count rows / distinct values
- `min()`, `max()` — earliest / latest
- `make_set(Col)` — collect distinct values into an array (great for "which hosts?")
- `make_list(Col)` — collect all values, preserving duplicates
- `arg_max(Timestamp, *)` — the *whole row* with the latest timestamp
- `bin(Timestamp, 10m)` — bucket time, for rate-based detections

### `join` — combine tables

```kusto
DeviceLogonEvents
| where ActionType == "LogonFailed"
| join kind=inner (
    DeviceLogonEvents
    | where ActionType == "LogonSuccess"
  ) on DeviceName, AccountName
```
```python
failures.merge(successes, on=["device", "user"], how="inner")
```

Join kinds include `inner`, `leftouter`, `rightouter`, `fullouter`, and these useful
existence checks (in pandas 2.x, implement them with membership or merge indicators):

- `leftanti` — rows in the left table with **no** match on the right. This is how you
  express "authentications with no corresponding interactive session", i.e. absence.
- `leftsemi` — left rows that *do* match, without pulling in right-hand columns.

**Performance starting point:** put the smaller table on the left when possible.
Broadcasting is a specific join strategy, not the automatic behavior of every join.
See [Microsoft’s join guidance](https://learn.microsoft.com/en-us/kusto/query/join-operator).

### `let` — named subqueries

```kusto
let Interpreters = dynamic(["powershell.exe", "cmd.exe"]);
let LookBack = 7d;
DeviceProcessEvents
| where Timestamp > ago(LookBack) and FileName in~ (Interpreters)
```

`in~` is case-insensitive set membership — the equivalent of pandas `.str.lower().isin(...)`.

### Other operators used in these files

- `sort by Timestamp asc` (alias: `order by`)
- `top 10 by Timestamp desc`
- `distinct DeviceName`
- `mv-expand` — explode an array column into rows (pandas `explode`)
- `prev()` / `next()` inside `serialize` — look at adjacent rows, for sequence detection
- `base64_decode_tostring()` — decode base64 inline
- `ipv4_is_private()` — checks IPv4 private ranges; it is not the inverse of Python
  `is_public_ip()` for every reserved or special address

---

## The files

| File | Rule | Detects |
| --- | --- | --- |
| `ATH-001-office-spawns-interpreter.kql` | ATH-001 | Office spawning PowerShell/cmd |
| `ATH-002-encoded-powershell.kql` | ATH-002 | `-EncodedCommand` payloads, decoded inline |
| `ATH-003-interpreter-external-connection.kql` | ATH-003 | Script interpreter egress |
| `ATH-004-lsass-credential-access.kql` | ATH-004 | LSASS indicators; includes a handle-access extension beyond the pandas detector |
| `ATH-005-bruteforce-then-success.kql` | ATH-005 | Failure burst followed by success |
| `ATH-006-foreign-host-authentication.kql` | ATH-006 | Credential use from a non-owned host |
| `ATH-007-remote-service-execution.kql` | ATH-007 | PsExec-style service execution |
| `ATH-008-data-staging-archive.kql` | ATH-008 | Bulk archive creation into staging paths |
| `ATH-009-office-macro-attachment-opened.kql` | ATH-009 | Macro-enabled document opened through an email client |
| `ATH-010-discovery-command-sequence.kql` | ATH-010 | Discovery commands sharing a parent process |
| `ATH-011-recovery-inhibition.kql` | ATH-011 | Recovery inhibition |
| `ATH-012-security-tool-tampering.kql` | ATH-012 | Security-tool tampering |
| `AWS-001-iam-privilege-escalation-chain.kql` | AWS-001 | IAM grant followed by access-key creation |
| `AWS-002-cloudtrail-logging-disabled.kql` | AWS-002 | CloudTrail logging disabled |
| `AWS-003-cloud-service-discovery-burst.kql` | AWS-003 | Service-discovery burst |
| `AWS-004-authorization-denial-burst.kql` | AWS-004 | Authorization-denial burst |
| `AWS-005-identity-authority-removed.kql` | AWS-005 | Identity authority removed |
| `AWS-006-rejected-identity-authority-changes.kql` | AWS-006 | Rejected identity-authority changes |
| `K8S-001-rbac-privilege-escalation-grant.kql` | K8S-001 | Privileged RBAC grant |
| `K8S-002-exec-after-privilege-grant.kql` | K8S-002 | Pod exec following a privileged grant |
