# Provenance -- `reports/local/dev/cases/dedale_injected/`

Ten labelled endpoint x identity cases (V1..V10; six malicious, four benign look-alikes)
injected into real benign DEDALE background from day D02 (2024-12-24), hour 08, by
`scripts/local_inject_dedale.py` using the pinned generator `scripts/m19b_inject_dedale.py`
unchanged. Seed 260915. DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/ -- licence CC BY 4.0.

These cases are the V1 *development* split. They are not part of the frozen M19b benchmark
and must never be used to grade it; `tests/test_contamination.py` checks the two are disjoint.
