# Provenance

Source: Kubernetes project CI artefacts, public GCS bucket `kubernetes-ci-logs`, job `ci-kubernetes-e2e-gci-gce`, run `2065053743543488512`, file `artifacts/bootstrap-e2e-master/kube-apiserver-audit.log` (kube-apiserver 1.37 on GCE, 2026-06-11). No licence text accompanies the bucket; these are unmodified audit records of a disposable test cluster, redistributed here as a test fixture with this citation.

Records: 12, one per line, `audit.k8s.io/v1`, all `ResponseComplete`:
- bootstrap cluster-admin -> system:masters: 1
- per-test-namespace cluster-admin -> default SA: 3
- e2e-test-privileged-psp binding: 1
- namespaced rolebinding: 1
- get-verb exec answered 101: 3
- service-account token request: 1
- secret read: 1
- Request-level pod get: 1

Nothing altered. Cut by `scripts/cut_real_shaped_fixtures.py`.
