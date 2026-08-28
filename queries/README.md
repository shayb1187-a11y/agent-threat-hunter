# KQL Hunting Queries

Each `.kql` file here is the Microsoft Defender / Sentinel equivalent of one pandas
detector in `src/ath/hunting/rules/`. The mapping is one-to-one and the filename
carries the rule id.

## Read this first: what these files are and are not

**The pandas implementation is the executable one in this project.** These KQL files
are written against the real Microsoft Defender **advanced hunting** schema so they
could be pasted into a Defender or Sentinel console and run against real data. They do
*not* run against our CSVs — Kusto is a cloud query engine, not a local library.

That is a deliberate choice, and worth saying plainly in an interview: writing KQL
against fake table names would teach you nothing transferable. Writing it against the
real schema means the queries are portable to an actual SOC.

## Schema mapping: our CSVs → Defender

| Our table / column | Defender table / column |
| --- | --- |
| `process_events` | `DeviceProcessEvents` |
| `network_events` | `DeviceNetworkEvents` |
| `logon_events` | `DeviceLogonEvents` |
| `timestamp` | `Timestamp` |
| `device` | `DeviceName` |
| `user` | `AccountName` |
| `process_name` | `FileName` |
| `command_line` | `ProcessCommandLine` |
| `parent_process_name` | `InitiatingProcessFileName` |
| `parent_process_id` | `InitiatingProcessId` |
| `file_path` | `FolderPath` |
| `remote_ip` / `remote_port` | `RemoteIP` / `RemotePort` |
| `action` (logon) | `ActionType` (`LogonSuccess` / `LogonFailed`) |
| `source_ip` / `source_device` | `RemoteIP` / `RemoteDeviceName` |
| `event_id` | `ReportId` (+ `DeviceId` for uniqueness) |

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

**Always filter on time first.** Kusto scans partitions chronologically, so
`| where Timestamp > ago(7d)` at the top of a query is the difference between a query
that returns in two seconds and one that times out.

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
| `contains` | any substring, anywhere | slow — no index |
| `has` | a whole **term** (word) | fast — uses the term index |
| `has_any` | any of a list of terms | fast |
| `startswith` / `endswith` | prefix / suffix | medium |

Kusto splits string columns into terms at non-alphanumeric boundaries and indexes those
terms. `has` consults that index; `contains` scans every row.

```kusto
| where ProcessCommandLine has "mimikatz"        // fast, matches the word
| where ProcessCommandLine contains "kat"        // slow, matches inside words
```

The catch: `has` will **not** match a partial word. `ProcessCommandLine has "lsass"`
matches `dump lsass.exe` (because `lsass` is its own term) but **not** `dumplsassmem`.
So the rule is: reach for `has` first for performance, fall back to `contains` when you
genuinely need substring matching, and add `~` for case-insensitivity (`=~`, `in~`,
`has_cs` is the case-*sensitive* variant).

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

Join kinds: `inner`, `leftouter`, `rightouter`, `fullouter`, plus two that have no
direct pandas equivalent and are extremely useful in hunting:

- `leftanti` — rows in the left table with **no** match on the right. This is how you
  express "authentications with no corresponding interactive session", i.e. absence.
- `leftsemi` — left rows that *do* match, without pulling in right-hand columns.

**Performance rule:** put the smaller table on the left. Kusto broadcasts the left side.

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
- `ipv4_is_private()` — RFC1918 test, our `is_public_ip()` equivalent

---

## The files

| File | Rule | Detects |
| --- | --- | --- |
| `ATH-001-office-spawns-interpreter.kql` | ATH-001 | Office spawning PowerShell/cmd |
| `ATH-002-encoded-powershell.kql` | ATH-002 | `-EncodedCommand` payloads, decoded inline |
| `ATH-003-interpreter-external-connection.kql` | ATH-003 | Script interpreter egress |
| `ATH-004-lsass-credential-access.kql` | ATH-004 | LSASS dumping (both command-line and handle-based) |
| `ATH-005-bruteforce-then-success.kql` | ATH-005 | Failure burst followed by success |
| `ATH-006-foreign-host-authentication.kql` | ATH-006 | Credential use from a non-owned host |
| `ATH-007-remote-service-execution.kql` | ATH-007 | PsExec-style service execution |
| `ATH-008-data-staging-archive.kql` | ATH-008 | Bulk archive creation into staging paths |
