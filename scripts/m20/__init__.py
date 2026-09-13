"""Tooling for M20: a predeclared benign cloud corpus.

Every module here exists to execute ``docs/m20-benign-cloud-validation-plan.md`` without
letting the operator improvise. The plan's value is entirely in what it fixed *before*
any data existed -- the workflow catalogue, the 14-day schedule, the calendar split and
the pre-registration -- so the tooling's job is to make the pre-committed version the
only one that is easy to run.

Four invariants, each enforced in code rather than described in prose:

INV-1 *sealing*    ``split.py`` decides dev vs holdout from the CloudTrail **object key's**
                   timestamp, never from ``eventTime`` inside a file, and records only
                   byte size and sha256 for holdout files. No parser, no gzip reader, no
                   ATH adapter touches a holdout byte before pre-registration.
INV-2 *predeclaration*
                   ``sessions.py plan`` writes the schedule before collection and refuses
                   to overwrite it; ``sessions.py record`` may only annotate the four
                   mutable columns of an existing row.
INV-3 *provenance* ``provenance.py`` captures everything section 3 of the plan lists under
                   "Provenance recorded" into the manifest entry shape section 7 proposes.
INV-4 *no tuning on the holdout*
                   ``validate_dev.py`` refuses any path containing "holdout" outright, and
                   ``measure_dev.py`` refuses one unless ``reports/m20/PREREGISTERED.md``
                   exists with no unfilled blanks.

Nothing in this package has been run against AWS: no account existed when it was written.
"""
