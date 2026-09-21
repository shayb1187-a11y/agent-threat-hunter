"""The experiment layer: one declared spec, runner-owned paths, run records, gates.

Everything under this package is additive to the frozen ablation surfaces. The
identity module says exactly which values and which source objects are frozen;
``tests/test_frozen_identity_pin.py`` and ``tests/test_frozen_source_pin.py`` hold the
package to it on every ``pytest``.
"""
