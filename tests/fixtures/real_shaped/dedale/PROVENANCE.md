# Provenance

Source: DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0. Cite the dataset and link the site.

File: `system_logs_winlogbeat.zip`, member `daily_winlogbeat/D3_H8_2024-12-25T08_*.jsonl.bz2` and later hours of the same day; host `CLIENT2.breach.local`; Winlogbeat 7.10.2 / ECS 1.5.0.

Records: 25 (Sysmon 1 process creates and Security 4624 logons), the boot chain from `wininit.exe -> lsass.exe` at 08:20:39Z, service logons, `CompatTelRunner.exe -> powershell.exe`, LibreOffice (`cmd.exe -> soffice.exe -> soffice.bin`). Benign day (week 1, no attack).

Trimming: the `message` field was removed (rendered copy of `event_data`). Nothing else altered. `winlog.record_id` + `host.name` + `winlog.channel` remain the label key.

Cut by `scripts/cut_real_shaped_fixtures.py`.
