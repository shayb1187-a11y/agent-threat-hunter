# M19 hypotheses, verbatim, for manual reading (prediction v)

Every HYPOTHESIS claim each arm produced, with its evidence ids. Classification as
actionable versus restating the findings is left to a human reader, as pre-registered.

## A_deterministic

### synthetic:INC-001 / CASE-001
- (identity) The credentials for 'svc_backup' may have been obtained from memory on PC01. This is unverified: no telemetry links the credential-access activity to this specific account.  
  evidence: ``
- (attack) Data staged on disk may have been transferred to the external destination observed in this case. This is unverified: the telemetry records archive creation and outbound connections separately, and does not show the archive's contents leaving.  
  evidence: ``

## B_single_llm

### attack_data_aws / CASE-001
- (synthesis) The principal name 'cloudsploit' matches the open-source CloudSploit cloud security auditing scanner, whose normal behaviour is exactly a broad read-only sweep across every service with many AccessDenied responses; the episode may therefore be an authorised configuration scan rather than adversary reconnaissance, and identity ownership should be checked before escalation.  
  evidence: `cloudtrail-control-002337, cloudtrail-control-002326, cloudtrail-control-001156, cloudtrail-control-001170`

### attack_data_aws / CASE-002
- (synthesis) The account name 'cloudmapper' matches the well-known open-source AWS auditing tool CloudMapper, whose collection phase enumerates many resource types and predictably generates dense AccessDenied bursts when the role is under-privileged; this case may therefore be sanctioned security tooling rather than adversary discovery. Confirming or excluding this requires checking whether the principal is an approved audit role and whether the run was scheduled.  
  evidence: `cloudtrail-control-001204, cloudtrail-control-001224`
- (synthesis) Because the finding is built exclusively from refusals, the case cannot distinguish a credential that reached nothing from one that also succeeded on calls not surfaced here; a targeted review of successful (non-denied) API calls by the same principal in the 13:25-13:45 window would be decisive and should be treated as the next investigative step.  
  evidence: `cloudtrail-control-001220, cloudtrail-control-001222, cloudtrail-control-001224`
- (synthesis) If the enumeration is adversarial, the abrupt end of activity at 13:35:10 with no observed successful action suggests the credential's permission boundary held and the operator either abandoned the principal or pivoted to a different identity; a search for other principals in account 731544447609 showing similar burst patterns shortly after 13:35 would test this.  
  evidence: `cloudtrail-control-001204, cloudtrail-control-001224`

### synthetic:INC-001 / CASE-001
- (synthesis) The 14 failed svc_backup logons indicate the attacker did not obtain a usable svc_backup credential from the LSASS dump and instead guessed or sprayed the password; a successful memory-derived credential or hash would normally authenticate on the first attempt rather than after a 143-second failure burst.  
  evidence: `evt-000419, evt-000442, evt-000444, evt-000457, evt-000381`

### synthetic:INC-005 / CASE-001
- (synthesis) The ci-deployer service account credential was likely abused by an attacker (e.g., via a compromised CI pipeline, leaked token, or malicious pipeline job) rather than acting on legitimate operator intent, since a deliberate operator grant of cluster-admin would normally be accompanied by a change-management artifact and would not be exercised within seconds.  
  evidence: `k8s-control-000003, k8s-control-000004`
- (synthesis) The ~149s delay between grant and exec is consistent with scripted or semi-automated tooling executing a prepared escalation sequence, rather than interactive human exploration, which typically shows more variable and longer intervals.  
  evidence: `k8s-control-000003, k8s-control-000004`

### synthetic:INC-004 / CASE-001
- (synthesis) An encryption/impact payload likely executed on PC03 immediately after 2026-08-17T11:15:40Z; the case currently ends at the last recovery-destruction event, so telemetry after that timestamp (file-write bursts, ransom note creation, mass renames) should be pulled to confirm or rule out completed impact.  
  evidence: `evt-000922, evt-000925, evt-000927`
- (synthesis) Because 'achen' successfully authenticated from PC03 to APP01 and FS02, the same credentials could be reused to stage the identical defense-disable plus recovery-destruction sequence on those hosts; APP01 and FS02 should be triaged for the same three Defender changes and the same three recovery deletions.  
  evidence: `evt-000027, evt-000085, evt-000090, evt-000901, evt-000905, evt-000909, evt-000922, evt-000925, evt-000927`
- (synthesis) PC03's outbound traffic is attributed almost entirely to chrome.exe against common cloud/CDN endpoints, which is consistent with a browser-delivered initial access vector (malicious download or drive-by) preceding the on-host destruction; the browser download history and process-creation chain from chrome.exe on 2026-08-17 warrant review.  
  evidence: `evt-000026, evt-000048, evt-000059, evt-000070, evt-000907`

### flaws_cloud / CASE-005
- (synthesis) An account averaging thousands of successful authentications with a brief interleaved burst of failures is more consistent with an automated client or service principal hitting a transient credential/rotation or throttling error than with an external password-guessing campaign; the T1110.001 mapping may be a false positive.  
  evidence: `cloudtrail-logon-002652, cloudtrail-logon-002676, cloudtrail-logon-007195`
- (synthesis) 255.253.125.115 lies in the reserved 255.0.0.0/8 space and is not a routable Internet source, indicating the source field is anonymized, synthesized, or a placeholder; geolocation- or reputation-based enrichment of this indicator would be meaningless.  
  evidence: `cloudtrail-logon-002652, cloudtrail-logon-002822`

### flaws_cloud / CASE-018
- (synthesis) The 'backup' identity is active in both us-east-1 and us-west-2, but this case's discovery burst is confined to us-east-1; a parallel or subsequent enumeration burst in us-west-2 is plausible and the absence of one in the current case may reflect rule/region scoping rather than actor restraint.  
  evidence: `cloudtrail-logon-000120, cloudtrail-logon-079340, cloudtrail-control-110341`
- (synthesis) The ambiguity between T1526 and T1580 is resolvable from data the rule discarded: if the 21 denials cluster on compute/network/storage inventory APIs (EC2/RDS/VPC describes) the behaviour is Cloud Infrastructure Discovery (T1580), whereas denials spread evenly as single probes per service favour Cloud Service Discovery (T1526). A per-service breakdown of the 10 services should be retrieved before assigning a technique.  
  evidence: `cloudtrail-control-110341, cloudtrail-control-110344, cloudtrail-control-110350, cloudtrail-control-110355, cloudtrail-control-110356`
- (synthesis) The sustained high-volume authentication failure history against 'backup' is consistent with a credential-stuffing or brute-force campaign targeting this identity, which would make the 07:04:50Z discovery burst a post-compromise reconnaissance stage rather than an isolated anomaly; correlating failure timestamps against the 125 successes would confirm or refute a guess-then-succeed pattern.  
  evidence: `cloudtrail-logon-025755, cloudtrail-logon-000120, cloudtrail-control-110341`

### flaws_cloud / CASE-050
- (synthesis) The 11,625 failed authentications on account 'backup' (98.9% failure rate across 11,750 attempts) and the permission-denied enumeration burst are two stages of one credential-abuse sequence: an actor first guessed or sprayed credentials, then used a low-privilege session to map what the credential could reach. This is unproven because the authentication events carry no resolved source and are not time-correlated in the available claims.  
  evidence: `cloudtrail-logon-000120, cloudtrail-logon-000121, cloudtrail-control-189271, cloudtrail-control-189279`
- (synthesis) An equally consistent benign explanation is a misconfigured or credential-expired backup automation job: a looping agent would produce both a very high authentication failure rate and repetitive broad API calls that are uniformly denied, with no successful privileged action. Distinguishing this from intrusion requires the user-agent string, session type (IAM user vs assumed role), and whether the call sequence is alphabetical or ordered by service.  
  evidence: `cloudtrail-logon-000126, cloudtrail-logon-000141, cloudtrail-control-189290, cloudtrail-control-189312`

### flaws_cloud / CASE-065
- (synthesis) The 16% refusal rate argues against the benign inventory/compliance-tooling explanation offered in AWS-003: sanctioned inventory tooling is normally provisioned with a read-only policy matched to the services it scans and would not be denied across 13 distinct resource types. A caller probing the boundaries of an unfamiliar credential fits the observed denial spread better.  
  evidence: `cloudtrail-control-224469, cloudtrail-control-224696, cloudtrail-control-225510, cloudtrail-control-225648, cloudtrail-control-225649, cloudtrail-control-225650, cloudtrail-control-225651, cloudtrail-control-225652`
- (synthesis) The 'Level6' principal's authentication history (5285 failures against only 61 successes, ~99% failure rate, across two regions with no source resolved) is anomalous for a healthy service identity and raises the possibility that the credential used for the discovery burst was not under its legitimate owner's exclusive control. Confirming this requires correlating the timestamps and source identity of the 61 successful authentications against the 11:26-11:32 control-plane window.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000145, cloudtrail-logon-000146, cloudtrail-logon-002347, cloudtrail-logon-007478, cloudtrail-control-224294`
- (synthesis) An alternative benign reading is that 'Level6' is a shared training/lab or CTF-style account: the naming convention, the very high authentication failure ratio, and a short broad read-only sweep with many denials are equally consistent with repeated enumeration exercises against a deliberately restricted credential. Account ownership and purpose should be established before escalating.  
  evidence: `cloudtrail-logon-000144, cloudtrail-control-224294, cloudtrail-control-225366`

### flaws_cloud / CASE-066
- (synthesis) The sequence is most consistent with credential-access-then-defense-evasion: sustained guessing produced at least one valid session, and the operator's first high-value action with that session was to stop the audit trail (T1685) to blind follow-on activity such as privilege escalation, persistence, or data access.  
  evidence: `cloudtrail-control-226796, cloudtrail-logon-018192, cloudtrail-logon-045001`
- (synthesis) The complete absence of resolved source addresses across all 5346 authentication events suggests either systematic source-IP redaction/normalisation loss in the ingestion pipeline or attacker use of AWS-internal/API-gateway paths; this gap, not attacker sophistication, is the primary blocker to attribution and should be treated as a collection defect to remediate.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-017044, cloudtrail-logon-040037, cloudtrail-logon-079347`

### flaws_cloud / CASE-067
- (synthesis) The very high volume of failed authentications for 'Level6' is consistent with credential brute-forcing/password-spraying or repeated token replay against the account, and the 61 successes represent the subset where valid credentials were obtained; the CloudTrail stop at 2019-06-07T11:04:25Z would then be post-compromise defense evasion following that access.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000146, cloudtrail-control-226797`
- (synthesis) The single-event case timeline (a 0-second window on 2019-06-07) understates the true incident scope; the actual intrusion likely extends both before the trail-stop (authentication attempts) and after it (unlogged activity), so the timeline should be treated as a visibility artifact rather than a bound on attacker dwell time.  
  evidence: `cloudtrail-control-226797, cloudtrail-logon-000144`
- (synthesis) The absence of any resolved source address across all 5346 'Level6' authentication events suggests either log-field stripping/normalization loss or use of AWS-internal/assumed-role invocation paths, either of which would frustrate source-based attribution and correlation of the trail-stop actor to the authentication attempts.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000145, cloudtrail-control-226797`

### flaws_cloud / CASE-077
- (synthesis) The overwhelming authentication failure ratio for 'Level6' (5285 of 5346, ~98.9%) is more likely a chronic background condition of this account (misconfigured automation, expired or rotated credential retried in a loop) than a targeted credential-guessing campaign tied to the 221s denial burst, because failure volume of that scale is not concentrated in the case window.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000196, cloudtrail-logon-079346, cloudtrail-logon-079347`
- (synthesis) The same principal is active in at least two regions (authentication observed in both us-east-1 and us-west-2) while the denial burst is confined to us-west-2, so equivalent enumeration may have occurred in us-east-1 and either succeeded quietly or was not captured by the AWS-004 detector; a cross-region review of Level6 control-plane calls is warranted before scoping the case to one region.  
  evidence: `cloudtrail-logon-000144, cloudtrail-control-238972, cloudtrail-control-238986`

### flaws_cloud / CASE-113
- (synthesis) The denial burst is the discovery stage of an attacker-controlled credential obtained earlier; the absence of resolved source addresses on any 'Level6' authentication event would be consistent with access via an anonymising or non-attributable network path, but source attribution is currently unavailable and cannot confirm this.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000145, cloudtrail-control-323923, cloudtrail-control-323928`

### flaws_cloud / CASE-118
- (synthesis) The trail deletion was preceded by reconnaissance and/or resource access (e.g., S3, IAM, or EC2 enumeration) by the same credentials, which would be recoverable from CloudTrail records written before 2019-08-23T15:48:50Z or from other regions' trails, data-event logs, or S3 server access logs.  
  evidence: `cloudtrail-control-1576322, cloudtrail-logon-039246, cloudtrail-logon-044401`
- (synthesis) Because no source addresses resolved for any of the 26 authentication events, attribution and separation of attacker sessions from legitimate administrator sessions cannot currently be performed; enriching these events with sourceIPAddress, userAgent, and accessKeyId would likely reveal whether a subset of the 26 logons originated from infrastructure distinct from normal operations.  
  evidence: `cloudtrail-logon-023843, cloudtrail-logon-023854, cloudtrail-logon-027482, cloudtrail-logon-057066`

### flaws_cloud / CASE-122
- (synthesis) The 61 successful authentications indicate at least one working credential path for 'Level6'; the ap-southeast-1 denial burst is plausibly the post-authentication action of one such successful session probing what that credential can reach, making correlation of the burst's session/access-key identifier against those 61 successes the highest-value next investigative step.  
  evidence: `cloudtrail-control-1649382, cloudtrail-control-1649386, cloudtrail-logon-000249, cloudtrail-logon-007478`
- (synthesis) An equally consistent benign explanation is a misconfigured or newly deployed automation/inventory tool running under 'Level6' against a region where it holds no policy grants: such tooling produces exactly this signature - many denials, many resource types, sub-second spacing, zero successes - and the high background authentication failure count would then reflect the same broken configuration rather than an adversary.  
  evidence: `cloudtrail-control-1649387, cloudtrail-control-1649388, cloudtrail-control-1649391, cloudtrail-logon-000392`
- (synthesis) Because no source address resolved for any of the 5346 authentication events, the denial burst cannot currently be attributed to a specific network origin or tied to the authentication history by infrastructure; until source-IP or user-agent enrichment is recovered, any linkage between the T1580 discovery activity and the credential-guessing volume remains circumstantial and rests only on the shared account name.  
  evidence: `cloudtrail-control-1649392, cloudtrail-control-1649393, cloudtrail-logon-000683, cloudtrail-logon-002347`

### flaws_cloud / CASE-143
- (synthesis) The 'backup' principal is likely compromised rather than misconfigured: a legitimate backup automation would issue a narrow, repeatable set of calls against services it is provisioned for, whereas a 95% denial rate across 69 services indicates the caller did not know its own entitlements.  
  evidence: `cloudtrail-control-1678074, cloudtrail-control-1678075, cloudtrail-control-1678076, cloudtrail-control-1678077, cloudtrail-control-1678078, cloudtrail-control-1678079, cloudtrail-control-1678080, cloudtrail-control-1678081`

### flaws_cloud / CASE-205
- (synthesis) The 5285 failed authentications attributed to 'Level6' occurred on us-east-1/us-west-2, which are disjoint from the ap-south-1/ap-southeast-2 regions of the discovery burst; if the authentication failures precede the burst, this would suggest credential-guessing followed by successful use of the account, but the provided claims contain no timestamps for the logon events and therefore no ordering can be established.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000145, cloudtrail-logon-000146, cloudtrail-control-1760284`
- (synthesis) The combination of broad read coverage (14 services) with denials concentrated on only 3 resource types is more consistent with a permission-boundary probe by a caller mapping what its credential can reach than with a compliance scanner, since an inventory tool is normally provisioned with the read permissions it needs and would not fail on a narrow, repeated set of object kinds.  
  evidence: `cloudtrail-control-1760664, cloudtrail-control-1760670, cloudtrail-control-1760671`
- (synthesis) An alternative benign explanation fits equally well: a newly deployed multi-region inventory or backup agent running under the 'Level6' identity with an incomplete IAM policy would produce exactly this signature - wide read fan-out plus a tight cluster of denials on the three resource types its policy omits. Resolving this requires the userAgent, access-key identity, and whether the same pattern recurs on a schedule, none of which are in the cited evidence.  
  evidence: `cloudtrail-control-1760662, cloudtrail-control-1760663, cloudtrail-control-1760664, cloudtrail-control-1760670`

### flaws_cloud / CASE-219
- (synthesis) The acting principal identifier 'i-aa2d3b42e5c6e801a' has EC2 instance-id form, suggesting the calls were made with an instance-role credential; combined with the low-privilege denial profile this is consistent with credentials harvested from an instance metadata service (e.g. via SSRF or on-host compromise) and then exercised from elsewhere.  
  evidence: `cloudtrail-control-1776510, cloudtrail-control-1776514, cloudtrail-control-1776522, cloudtrail-logon-018208, cloudtrail-logon-072441`
- (synthesis) The same principal's authentication record (45 failures against 5 successes, ~90% failure) mirrors the brute-force-by-breadth pattern seen in the API calls and may represent the credential-acquisition phase that preceded the discovery burst; the 5 successful logons are the highest-value pivot for identifying the true source.  
  evidence: `cloudtrail-logon-011279, cloudtrail-logon-018208, cloudtrail-logon-047152, cloudtrail-logon-057799, cloudtrail-logon-072502, cloudtrail-logon-079343`

### flaws_cloud / CASE-256
- (synthesis) The benign 'inventory/compliance tooling' explanation offered for AWS-003 is weakened by the identity's authentication profile: account 'Level6' shows 5285 failed versus 61 successful authentications (~98.9% failure), which is atypical for sanctioned tooling operating with provisioned credentials and more consistent with credential guessing or a misconfigured/unauthorized client.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-018192, cloudtrail-logon-046949, cloudtrail-control-1817072, cloudtrail-control-1817217`
- (synthesis) The successful authentications for 'Level6' are the likely enabling precursor to this burst: a small number of successes amid mass failures would give a caller a working credential of unknown scope, which the 17-resource-type refusal pattern then maps out. Confirming this requires correlating the specific successful logon immediately preceding 03:54:58Z with the session used for the control-plane calls.  
  evidence: `cloudtrail-logon-000144, cloudtrail-logon-000145, cloudtrail-control-1817072, cloudtrail-control-1817082`

## C_crew_llm

### attack_data_aws / CASE-002
- (synthesis) The principal name 'cloudmapper' matches a well-known open-source AWS auditing tool whose normal operation issues exactly this kind of broad read-only sweep across KMS, Organizations and Glue. If a sanctioned security or compliance scan is scheduled in this account, the entire case is expected tooling behaviour and the Discovery mapping is a false positive.  
  evidence: `cloudtrail-control-001220, cloudtrail-control-001224, cloudtrail-control-001219`
- (synthesis) An adversary who had compromised a credential and was mapping infrastructure would be expected to leave traces in a second tactic (credential access, collection, or exfiltration) either alongside or shortly after the reads. The case being confined to Discovery suggests either that collection was truncated to a narrow window or that no follow-on activity occurred, the latter being more consistent with automated scanning than with an intrusion.  
  evidence: `cloudtrail-control-001204, cloudtrail-control-001219, cloudtrail-control-001220, cloudtrail-control-001222, cloudtrail-control-001224`
- (synthesis) The Glue job and trigger reads are the one pair in this set that could serve execution rather than pure discovery, since Glue jobs run code and triggers schedule it. If the same identity later shows a Glue job create or update, the case should be re-scored as reconnaissance preceding execution rather than Discovery alone.  
  evidence: `cloudtrail-control-001219, cloudtrail-control-001204`

### comiset / CASE-001
- (synthesis) beacon.exe is a command-and-control implant (the name matches Cobalt Strike Beacon), and the two encoded PowerShell launches are operator-issued or automated post-exploitation tasks delivered over that C2 channel.  
  evidence: `comiset_slice.jsonl:b9a5cb4bdabc2fe887d9224d6c42056e5b64ff90, comiset_slice.jsonl:41ece3af25e0f38cccc6d27422a388c739761353, comiset_slice.jsonl:574dffe7a299a4ad9d2b1150574e2cff72b4efb4`
- (synthesis) remotemouse.exe is a legitimate remote-control utility being abused as the initial access or hands-on-keyboard entry point (living-off-trusted-software), with cmd.exe used as the launcher for the implant.  
  evidence: `comiset_slice.jsonl:0a7e197d2e49a2d65785fa2efbca8a1bbdfcdb8a, comiset_slice.jsonl:b9a5cb4bdabc2fe887d9224d6c42056e5b64ff90`

### comiset / CASE-002
- (synthesis) remotemouse.exe is being abused as attacker remote-access tooling (a legitimate remote-control application used in lieu of a custom RAT), making it the hands-on-keyboard entry point for this host rather than a user-initiated convenience tool.  
  evidence: `comiset_slice.jsonl:2123df97130430b012740761f3c88c0bbe4bc345`
- (synthesis) The apparent confinement of the case to a single tactic reflects the narrow scope of the collected slice rather than the true extent of the intrusion; a remote-control tool spawning a SYSTEM shell normally implies preceding initial-access/persistence activity and following actions on objectives that were not captured.  
  evidence: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b, comiset_slice.jsonl:2123df97130430b012740761f3c88c0bbe4bc345`
- (synthesis) Disabling security tooling is typically preparatory; additional child processes of the same cmd.exe instance, new service creations, or payload writes on desktop-4pvps6e within minutes of this chain should be hunted as the likely next stage.  
  evidence: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b`
- (synthesis) An alternative reading of the same sc.exe execution is service creation for persistence rather than service disablement; the two are indistinguishable without the process command line, so the ATH-012 technique mapping should be treated as provisional until arguments are recovered.  
  evidence: `comiset_slice.jsonl:4bdb0f0e83e0a62d3ca40b33ef0d892801fd4d3b`

### synthetic:INC-001 / CASE-001
- (identity) The credentials for 'svc_backup' may have been obtained from memory on PC01. This is unverified: no telemetry links the credential-access activity to this specific account.  
  evidence: ``
- (attack) Data staged on disk may have been transferred to the external destination observed in this case. This is unverified: the telemetry records archive creation and outbound connections separately, and does not show the archive's contents leaving.  
  evidence: ``
- (synthesis) The svc_backup password-guessing burst may have been seeded by material recovered from the PC01 LSASS dump (e.g. a cached username or stale password), which would explain why guessing targeted this one service account rather than many accounts. Unverified: no telemetry ties the dump output to the authentication attempts.  
  evidence: `evt-000381, evt-000419, evt-000422, evt-000444, evt-000457`
- (synthesis) FS02 was the objective of the intrusion rather than a waypoint: it is the host reached by lateral movement, the host where data was archived with a utility, and a host that also contacted the C2 address, making it the likely staging point for collection and exfiltration.  
  evidence: `evt-000457, evt-000469, evt-000481`

### synthetic:INC-002 / CASE-001
- (synthesis) Twelve attempts is a very small number for blind password guessing, so the adversary more likely worked from a short candidate list (prior-breach credentials, a predictable pattern, or partial knowledge of the password) than from an untargeted dictionary; this would imply prior reconnaissance or an external credential-dump source.  
  evidence: `cloudtrail-logon-000002, cloudtrail-logon-000003, cloudtrail-logon-000013, cloudtrail-logon-000014`
- (synthesis) The case contains no post-authentication API or resource-access events for 'dev_alice', which is more likely a telemetry scoping gap (only logon events were collected) than evidence that the adversary took no action; CloudTrail management and data events for this principal after 000014 should be retrieved before concluding impact was nil.  
  evidence: `cloudtrail-logon-000014, cloudtrail-logon-000015`

### synthetic:INC-005 / CASE-001
- (synthesis) ci-deployer is the earlier-compromised identity and ci-runner is a secondary identity it privileged; the investigation should pivot to ci-deployer's authentication source (token issuance, node/pod of origin, source IP) to locate the true initial access point, which is not represented in the current evidence.  
  evidence: `k8s-control-000003, k8s-control-000004`
- (synthesis) The 149-second grant-to-use interval and the clean two-step sequence are more consistent with scripted or pipeline-driven execution than with interactive human operation; conversely, the same pattern would be produced by a legitimate but over-permissioned CI deployment job, so automation alone does not distinguish malicious from benign.  
  evidence: `k8s-control-000003, k8s-control-000004`
- (synthesis) The ClusterRoleBinding 'ci-runner-escalation' likely persists after the exec activity, since no revocation or deletion event appears among the verified claims; if so, ci-runner retains cluster-admin and the cluster remains in a compromised-authorization state independent of any containment applied to the exec session.  
  evidence: `k8s-control-000003, k8s-control-000004`
- (synthesis) The exec into a production pod was plausibly aimed at credential or secret harvesting (mounted service account tokens, environment variables, or mounted Secret volumes inside 'web-1'), which would extend the chain from Execution/Persistence into Credential Access; validating this requires in-container process and file-read telemetry not present in the current evidence.  
  evidence: `k8s-control-000004`

### synthetic:INC-004 / CASE-001
- (synthesis) The sequence is consistent with ransomware pre-encryption staging: security tooling is neutralised first (T1585-style tampering via PowerShell) and shadow copies are then destroyed via vssadmin to prevent restoration, typically immediately preceding a file-encryption or wiper payload that may not yet appear in the telemetry reviewed.  
  evidence: `evt-000901, evt-000905, evt-000909, evt-000922, evt-000925, evt-000927`
- (synthesis) The achen account is likely being operated by an adversary (via credential theft, session hijack, or an implant running in the user context) rather than by the legitimate user, since disabling protection and deleting shadow copies from an interactive cmd.exe session has no ordinary business justification for a standard user.  
  evidence: `evt-000901, evt-000922`
- (synthesis) cmd.exe (PID 7419) is itself a child of some unobserved process; its parent and the method by which it obtained execution (phishing payload, remote service, scheduled task, or lateral movement from another host) are the critical missing links and should be the next collection priority, since the identity of PID 7419 is noted as inferred rather than directly observed.  
  evidence: `evt-000901, evt-000922`
- (synthesis) If the defense-impairment step succeeded before the vssadmin execution, endpoint telemetry collected after that point on PC03 may be incomplete or unreliable, meaning the absence of further malicious events on this host is weak evidence of containment.  
  evidence: `evt-000901, evt-000905, evt-000909, evt-000922`

### flaws_cloud / CASE-005
- (synthesis) The sustained high volume of successful authentications from one IP after the failure burst is more consistent with automated/scripted API access using a validated credential (e.g. programmatic token reuse) than with interactive human console use.  
  evidence: `cloudtrail-logon-002822, cloudtrail-logon-004000, cloudtrail-logon-005000, cloudtrail-logon-006000, cloudtrail-logon-007195`
- (synthesis) The account name 'SecurityMokey' appears to be a misspelling of a security-tooling/automation identity; if so it likely carries elevated or broad read permissions, which would make successful credential guessing disproportionately impactful and should be confirmed against the IAM policy attached to the principal.  
  evidence: `cloudtrail-logon-002652, cloudtrail-logon-002822, cloudtrail-logon-007195`
- (synthesis) Only 53 failures preceding success suggests the guessing was targeted (short curated wordlist or credential-stuffing from a prior leak) rather than exhaustive brute force; an exhaustive attack against a non-trivial password would be expected to generate orders of magnitude more failures.  
  evidence: `cloudtrail-logon-002652, cloudtrail-logon-002676, cloudtrail-logon-002754, cloudtrail-logon-002791, cloudtrail-logon-002822`

### flaws_cloud / CASE-018
- (synthesis) iam:account-summary being the earliest event in the band suggests the session opened by establishing the account's identity posture and quota/limit context before fanning out to service inventory. That ordering — capability check first, resource sweep second — is the characteristic opening move of automated AWS enumeration frameworks (e.g. Pacu, ScoutSuite, CloudFox) as well as of legitimate CSPM baseline scans.  
  evidence: `cloudtrail-control-110341, cloudtrail-control-110344, cloudtrail-control-110347`
- (synthesis) The principal name 'backup' implies a role scoped to snapshot, restore and retention duties. Reads against cloudfront:distribution, sns:topic, elasticbeanstalk:application and iam:account-summary have no plausible backup function, so the observed breadth exceeds the identity's apparent business purpose. This is consistent either with an over-permissioned service role being exercised by an unintended consumer, or with a third party operating stolen 'backup' credentials.  
  evidence: `cloudtrail-control-110341, cloudtrail-control-110351, cloudtrail-control-110352, cloudtrail-control-110357`
- (synthesis) The competing benign explanation (a scheduled compliance or inventory scanner) is directly testable and should be resolved before escalation: a scanner would produce a near-identical service sweep on a fixed cadence from a stable source IP and user agent. If no equivalent enumeration band by 'backup' exists in the preceding days' control-plane logs, the benign explanation fails and the single-session interpretation strengthens substantially.  
  evidence: `cloudtrail-control-110341, cloudtrail-control-110350, cloudtrail-control-110353, cloudtrail-control-110355, cloudtrail-control-110356`

### flaws_cloud / CASE-050
- (synthesis) The combination of high denial volume (AWS-004) with broad enumeration (AWS-003) argues against the benign compliance-scanner explanation that the existing claims correctly flag as an alternative. Sanctioned scanners (Prowler, Scout Suite, Security Hub) are normally granted SecurityAudit or ReadOnlyAccess and therefore succeed on most read calls; a sweep that is refused repeatedly across many service families suggests the caller did not know what the credential was entitled to and was probing blindly. This is a discriminator, not proof — a scanner deployed with a broken or partially-attached policy produces the same pattern.  
  evidence: `cloudtrail-control-189279, cloudtrail-control-189280, cloudtrail-control-189281, cloudtrail-control-189286, cloudtrail-control-189287, cloudtrail-control-189291, cloudtrail-control-189292, cloudtrail-control-189294, cloudtrail-control-189300, cloudtrail-control-189301`
- (synthesis) The principal is named 'backup', yet the observed reads target ACM, ACM-PCA, API Gateway, Athena, CloudFront, CloudHSM, CodeCommit, CodePipeline and CloudTrail — none of which a backup function requires. This semantic mismatch between the identity's apparent purpose and its behaviour is consistent with either (a) an over-permissioned service identity being reused by a general-purpose tool, or (b) a compromised credential whose name no longer reflects who is driving it. Resolving this requires the identity type (IAM user vs assumed role), key age, source IP and user-agent, none of which are in the current evidence.  
  evidence: `cloudtrail-control-189274, cloudtrail-control-189276, cloudtrail-control-189330, cloudtrail-control-189336, cloudtrail-control-189352, cloudtrail-control-189368, cloudtrail-control-189378`

### flaws_cloud / CASE-065
- (synthesis) The bucket names ending in '.flaws.cloud' and the principal name 'Level6' correspond to the publicly published flAWS.cloud AWS security training challenge, in which 'Level6' is a deliberately-provisioned low-privilege IAM user and 'theend-...' is the terminal objective bucket. If correct, this entire case is sanctioned training/CTF activity rather than an intrusion, and the Discovery techniques attributed by AWS-003/AWS-004 are expected by design.  
  evidence: `cloudtrail-control-224696, cloudtrail-control-225648, cloudtrail-control-225659, cloudtrail-control-224300`
- (synthesis) The full pattern — an sts:GetCallerIdentity call to establish credential context, followed by breadth-first list/describe sweeps across ~20 unrelated services, then a fixed per-bucket S3 configuration checklist — matches the execution profile of an off-the-shelf multi-service auditing tool (e.g. ScoutSuite, Prowler, CloudMapper) rather than hand-typed reconnaissance. This would explain both the service breadth in AWS-003 and the authorization refusals in AWS-004 as the tool probing checks the credential is not entitled to.  
  evidence: `cloudtrail-control-224300, cloudtrail-control-224346, cloudtrail-control-224412, cloudtrail-control-224468, cloudtrail-control-224469, cloudtrail-control-225510, cloudtrail-control-225648, cloudtrail-control-225652`

### flaws_cloud / CASE-066
- (synthesis) Defense impairment is rarely an end goal, so the logging stop is likely a precursor step taken to shield follow-on actions; investigation should pivot to non-CloudTrail sources (VPC flow logs, S3 server access logs, GuardDuty, billing/usage anomalies) for the window beginning at the stop event.  
  evidence: `cloudtrail-control-226796`
- (synthesis) The 'Level6' principal held permissions sufficient to alter trail configuration (cloudtrail:StopLogging / DeleteTrail), implying either a highly privileged administrative identity or a prior privilege-escalation step that is not represented in the current evidence; enumerating how that principal obtained those rights is a gap in the timeline.  
  evidence: `cloudtrail-control-226796`
- (synthesis) A benign explanation remains open: scheduled maintenance, cost-reduction of duplicate trails, or an infrastructure-as-code change could produce the same telemetry. The malicious interpretation should be considered unconfirmed until the principal's authorisation, change-ticket context, and whether logging was restored are established.  
  evidence: `cloudtrail-control-226796`

### flaws_cloud / CASE-067
- (synthesis) Disabling audit logging is typically a preparatory step rather than an end goal, so it is likely that 'Level6' intended or performed further actions (credential access, data access, resource creation, or persistence) immediately after the stop, which would be unlogged.  
  evidence: `cloudtrail-control-226797`
- (synthesis) An alternative benign explanation is that 'Level6' is an automation, IaC, or administrative role performing a sanctioned trail reconfiguration or cost-reduction change; this can be distinguished by checking whether a replacement trail was created shortly afterwards and whether a change-management ticket exists.  
  evidence: `cloudtrail-control-226797`
- (synthesis) If the 'Level6' principal is not normally entitled to modify logging configuration, the stop action implies a prior, unobserved privilege-escalation or credential-compromise step that occurred before the visibility gap opened; reviewing IAM policy attachments and prior authentication events for that principal would test this.  
  evidence: `cloudtrail-control-226797`

### flaws_cloud / CASE-077
- (synthesis) The event-identifier ordering suggests the reads preceded the write by a substantial number of intervening control-plane events (238972-238987 versus 239755). If that ordering reflects real time, it indicates reconnaissance first and action second, but identifier sequence is not a verified timestamp and this ordering should be confirmed against event times before being relied on.  
  evidence: `cloudtrail-control-238972, cloudtrail-control-238987, cloudtrail-control-239755`
- (synthesis) Two identifiers inside the otherwise contiguous read block are absent from the claim set (238976 and 238985), which is the expected position of two further GetBucket* calls. The enumeration may therefore be more complete than the fourteen verified events show, with the missing calls either filtered from the case or having failed differently.  
  evidence: `cloudtrail-control-238975, cloudtrail-control-238977, cloudtrail-control-238984, cloudtrail-control-238986`
- (synthesis) The principal name 'Level6', the target bucket 'flaws.cloud', and the created bucket name 'pwnd' together are more consistent with a deliberate security-training or capture-the-flag exercise than with an unsanctioned intrusion. If confirmed, the authorization-refusal pattern is expected behaviour of the exercise rather than an incident.  
  evidence: `cloudtrail-control-238972, cloudtrail-control-239755`

### flaws_cloud / CASE-113
- (synthesis) The creation of a default VPC immediately before running an instance suggests the target region had no usable network prior to this activity, implying the region was previously unused by the organisation and was selected for that reason rather than for a business need. If true, the activity is unlikely to be legitimate operations.  
  evidence: `cloudtrail-control-323942, cloudtrail-control-323974`
- (synthesis) The terminal step of the chain is compute instantiation with an attacker-controlled SSH key pair in a freshly created network, which fits resource hijacking (T1496) or the staging of an interactive foothold rather than Discovery alone. The case's single-tactic Discovery labelling may therefore understate the objective.  
  evidence: `cloudtrail-control-323933, cloudtrail-control-323942, cloudtrail-control-323974`
- (synthesis) The authorization refusals attributed to this identity and its successful create calls are two halves of the same behaviour: the denials mapped the permission boundary and the successes are the subset the credential could actually reach. Under this reading the denials are not evidence of misconfiguration, because a misconfigured role would not typically be followed by a coherent build-out ending in a running instance.  
  evidence: `cloudtrail-control-323923, cloudtrail-control-323928, cloudtrail-control-323933, cloudtrail-control-323942, cloudtrail-control-323974`

### flaws_cloud / CASE-118
- (synthesis) The trail deletion is preparatory rather than terminal — it precedes a higher-impact objective (credential harvesting, data exfiltration from S3, or resource hijacking for cryptomining) that the actor expected to be logged. Testing requires pivoting to log sources independent of the deleted trail (S3 server access logs, VPC flow logs, GuardDuty, billing/usage anomalies).  
  evidence: `cloudtrail-control-1576322`
- (synthesis) The principal 'flaws' held IAM permissions including cloudtrail:DeleteTrail, which is an administrative-grade privilege; either the identity was over-provisioned by design or a prior, unlogged privilege-escalation step occurred. Reviewing the IAM policy attached to 'flaws' and any preceding AttachUserPolicy/CreateAccessKey events would discriminate between these.  
  evidence: `cloudtrail-control-1576322`
- (synthesis) The identity name 'flaws' and the us-west-2 region are consistent with the flaws.cloud deliberately-vulnerable AWS training environment, meaning this may be sanctioned exercise traffic rather than a genuine intrusion. Confirming account 811596193553's ownership and purpose should precede escalation.  
  evidence: `cloudtrail-control-1576322`

### flaws_cloud / CASE-122
- (synthesis) The near-exhaustive coverage of the S3 bucket-metadata API surface (encryption, CORS, ACL, location, replication, policy-status, notification, logging, policy, tagging, website, versioning, request-payment) in one contiguous block is more consistent with an automated tool or SDK enumeration routine iterating a fixed API list than with a human operator or an application performing a task-specific call.  
  evidence: `cloudtrail-control-1649380, cloudtrail-control-1649381, cloudtrail-control-1649382, cloudtrail-control-1649383, cloudtrail-control-1649386, cloudtrail-control-1649387, cloudtrail-control-1649388, cloudtrail-control-1649390, cloudtrail-control-1649391, cloudtrail-control-1649392, cloudtrail-control-1649393, cloudtrail-control-1649394, cloudtrail-control-1649395`
- (synthesis) The subset of calls targeting bucket-policy, bucket-policy-status, bucket-acl, and bucket-website is the portion of the sweep that would reveal public-exposure and permission-boundary information. If the caller is adversarial, this cluster is the likely objective of the enumeration and a precursor to attempted object access or a public-exposure abuse path; its presence raises the priority of checking whether GetObject/ListObjects calls followed against the same bucket.  
  evidence: `cloudtrail-control-1649382, cloudtrail-control-1649387, cloudtrail-control-1649391, cloudtrail-control-1649393`
- (synthesis) The principal name 'Level6' follows the naming convention of tiered lab, CTF, or training accounts (e.g. flAWS-style challenge levels), and the bucket name 'dev-eztax' indicates a development-tier resource. If confirmed, this activity may be sanctioned security exercise or assessment traffic rather than an intrusion, which would explain the benign-alternative reading already noted for AWS-004. Resolving the account's purpose should precede escalation.  
  evidence: `cloudtrail-control-1649380, cloudtrail-control-1649391, cloudtrail-control-1649394`

### flaws_cloud / CASE-143
- (synthesis) The pattern is consistent with an off-the-shelf cloud enumeration framework (e.g. Pacu, ScoutSuite, CloudFox, or a scripted loop over the AWS SDK service list) executed with the 'backup' credential, since such tools walk every known service in sorted order and tolerate per-call AccessDenied responses rather than stopping.  
  evidence: `cloudtrail-control-1678048, cloudtrail-control-1678074, cloudtrail-control-1678081, cloudtrail-control-1678087, cloudtrail-control-1678093, cloudtrail-control-1678099`
- (synthesis) If the 'backup' identity is a service account with a long-lived access key, the most likely origin is credential compromise followed by permission mapping; investigators should pull the source IP, user agent, and access key ID for these events and compare them against the identity's historical baseline, since a legitimate scheduled backup job would show a stable, narrow call profile.  
  evidence: `cloudtrail-control-1678048, cloudtrail-control-1678064, cloudtrail-control-1678087, cloudtrail-control-1678090, cloudtrail-control-1678099`

### flaws_cloud / CASE-205
- (synthesis) sts:GetCallerIdentity carries the highest event identifier in the set, meaning the caller resolved its own principal at or near the END of the sweep rather than the beginning. Legitimate scanners and SDK sessions typically resolve identity first; establishing identity only after discovering which services respond is more consistent with an operator or tool confirming the provenance of a credential whose owner was not known in advance.  
  evidence: `cloudtrail-control-1760846, cloudtrail-control-1760284, cloudtrail-control-1760671`
- (synthesis) The presence of iam:ListUsers within an otherwise infrastructure-focused sweep may indicate the enumeration was aimed at identifying privilege-escalation targets rather than at inventorying assets. If so, follow-on activity would be expected against iam:ListAttachedUserPolicies, GetPolicyVersion or sts:AssumeRole; the absence of such calls in the current evidence argues the sweep either stopped early or was blocked.  
  evidence: `cloudtrail-control-1760425, cloudtrail-control-1760846`

### flaws_cloud / CASE-219
- (synthesis) The service list touched (snowball, mediaconnect, mediapackage, rekognition, gamelift, iotanalytics, datapipeline, amplify, appsync, route53domains) spans domains that a single application workload would almost never legitimately use together, which fits a fixed enumeration wordlist from off-the-shelf cloud recon tooling (e.g. Pacu, ScoutSuite, cloudfox) executed from the instance.  
  evidence: `cloudtrail-control-1776510, cloudtrail-control-1776511, cloudtrail-control-1776515, cloudtrail-control-1776516, cloudtrail-control-1776522, cloudtrail-control-1776527, cloudtrail-control-1776545, cloudtrail-control-1776552, cloudtrail-control-1776556, cloudtrail-control-1776571, cloudtrail-control-1776597`
- (synthesis) A subset of the reads has direct follow-on value for an attacker rather than for a compliance scan - kms:custom-key-store and glue:database/catalog touch key material and data-catalog metadata, route53 hosted-zones and route53domains expose DNS control surface, and cloudfront distributions/field-level-encryption expose edge configuration - so these specific calls should be prioritised when deciding between benign inventory and targeted reconnaissance.  
  evidence: `cloudtrail-control-1776524, cloudtrail-control-1776525, cloudtrail-control-1776530, cloudtrail-control-1776528, cloudtrail-control-1776529, cloudtrail-control-1776556, cloudtrail-control-1776514, cloudtrail-control-1776519, cloudtrail-control-1776520`

### flaws_cloud / CASE-256
- (synthesis) The specific attribute set pulled per bucket (policy, ACL, public-access-block, encryption, logging, versioning) is the exact checklist used by open-source cloud posture scanners such as ScoutSuite, Prowler or CloudMapper; combined with the account-level s3:account-public-access-block, cloudtrail:trail, config:config-rule, config:configuration-recorder-status and monitoring:alarm reads, the run is better explained as a security-audit tool sweep than as targeted adversary reconnaissance.  
  evidence: `cloudtrail-control-1817217, cloudtrail-control-1817317, cloudtrail-control-1817318, cloudtrail-control-1817322, cloudtrail-control-1817321, cloudtrail-control-1817369, cloudtrail-control-1817373, cloudtrail-control-1817374, cloudtrail-control-1817376, cloudtrail-control-1817377, cloudtrail-control-1817378`
- (synthesis) The principal name 'Level6' and the target bucket names ending in '.flaws.cloud' (level4-974134b52e7c35aebcc4b45f19113936.flaws.cloud and b5677c799b465420d8e7b0a6689a0bb0c4afbc9e.flaws.cloud) correspond to the publicly published flAWS.cloud training/CTF exercise, whose levels are named Level1..Level6. If confirmed, this is a deliberately vulnerable teaching account and the case should be triaged as expected exercise traffic, not an intrusion.  
  evidence: `cloudtrail-control-1817246, cloudtrail-control-1817371, cloudtrail-control-1817372, cloudtrail-control-1817373`
