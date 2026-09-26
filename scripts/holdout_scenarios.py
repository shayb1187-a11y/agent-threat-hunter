r"""Injected Kubernetes scenarios for the holdout-v1 evaluation set, and their tooling.

This module is the *blind* side of the holdout: it defines synthetic ``audit.k8s.io/v1``
events and the checks that keep them honest, without ever reading the investigator or its
prompts. Two things live here:

* an **expander** that turns a compact scenario record into a full Kubernetes audit
  ``Event`` whose field shapes are copied from the real ``k8s_ingress`` background
  (``user.groups``, ``sourceIPs``, ``userAgent``, ``objectRef``, ``requestObject`` with
  ``subjects``/``roleRef``, ``responseStatus``, ``stage: ResponseComplete``,
  ``requestReceivedTimestamp``/``stageTimestamp``, ``annotations``), so an injected
  record is not stylistically distinguishable from a recorded one;
* the **k8s-benign scenario definitions** (holdout role ``secondary``), hand-authored
  as benign look-alikes of equal surface severity to an escalation, with the label
  rationale kept out of the telemetry and in a separate ``rationale`` field the manifest
  reads. They are a false-accusation / generalisation check only.

No malicious Kubernetes scenario exists in holdout-v1: Kubernetes malicious
discrimination is not evaluated (no suitable fresh labelled dataset existed). This module
defines, infers and accepts benign scenarios only.

Scenario payload schema::

    {
      "quadrant": "k8s-benign",
      "scenarios": [
        {
          "id": "helm-namespace-admin",    # internal id, never the case key
          "label": "benign",
          "rationale": "why this is benign -- manifest only, never telemetry",
          "base_time": "2026-06-11T03:04:00Z",
          "anchor": 0,                      # index into records
          "link": {"kind": "before", "from": 0, "to": 1},   # optional
          "records": [ {compact record}, ... ]
        }
      ]
    }

Compact record (expanded by :func:`expand_record`)::

    {
      "dt": 0,                              # seconds after the scenario base_time
      "actor": "system:serviceaccount:deploy:release-bot",
      "groups": ["system:serviceaccounts", "system:authenticated"],
      "verb": "create",                     # create (binding) | exec (pod exec)
      "resource": "rolebindings",           # rolebindings | clusterrolebindings | pods/exec
      "name": "release-bot-admin",
      "namespace": "deploy",
      "subjects": [{"kind": "ServiceAccount", "name": "release-bot", "namespace": "deploy"}],
      "role_ref": {"kind": "ClusterRole", "name": "admin"},   # bindings only
      "source_ip": "10.40.6.11",
      "user_agent": "helm/v3.14.4 (linux/amd64)",
      "code": 201,                          # 201 create, 101 exec-upgrade, 403 denied, ...
      "annotations": {"change": "CHG-4821"} # optional extra annotations (no label words)
    }
"""

from __future__ import annotations

import re
import uuid
from typing import Any

# A fixed namespace UUID so every run mints the same auditIDs for the same records: the
# builder is deterministic, and an auditID is what a case's anchor ref names.
_AUDIT_NS = uuid.UUID("6f2d5a10-0000-4000-a000-000000000001")

# The API server version string the real ``k8s_ingress`` background advertises; reused so
# an injected caller's client build is not an outlier.
_KUBECTL_UA = "kubectl/v1.37.0 (linux/amd64) kubernetes/3841ba0"

_QUADRANTS = ("k8s-benign",)
_LABELS = {"k8s-benign": "benign"}

# Word-ish, case-insensitive tokens that would leak a label into the telemetry. The lint
# runs over every string value of an injected record. Judgement is applied at authoring
# time so a real background-derived name is not chosen that would false-trip; the lint is
# a backstop, not a substitute for not writing "attacker" into a namespace.
LEAK_TOKENS: tuple[str, ...] = (
    "attack", "attacker", "malicious", "evil", "benign", "pentest", "red-team",
    "redteam", "hack", "exploit", "c2", "backdoor", "legit", "sanctioned",
    "suspicious", "compromise", "adversary", "threat", "victim",
)
# "test" is a leak token per the brief, but the real background is a CI e2e run whose
# namespaces and pods are legitimately named ``*test*``. It is linted with a boundary
# that only fires on the bare word or an explicit label-ish use, so an injected record
# that reuses a real ``e2e.test`` user-agent or a ``test-*`` pod name does not false-trip.
_TEST_RE = re.compile(r"(?<![a-z0-9.\-])test(?![a-z0-9.\-])", re.IGNORECASE)
_LEAK_RES = [re.compile(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])", re.IGNORECASE)
             for tok in LEAK_TOKENS]


def _audit_id(scenario_id: str, index: int) -> str:
    return str(uuid.uuid5(_AUDIT_NS, f"{scenario_id}#{index}"))


def _iso(base: str, dt_seconds: float) -> tuple[str, str]:
    """(requestReceived, stageTimestamp) a few ms apart, mirroring the real records."""
    import datetime as _d

    start = _d.datetime.fromisoformat(base.replace("Z", "+00:00")) + _d.timedelta(seconds=dt_seconds)
    received = start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    stage = (start + _d.timedelta(milliseconds=9)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return received, stage


def _binding_object(record: dict[str, Any], resource: str) -> dict[str, Any]:
    kind = "ClusterRoleBinding" if resource == "clusterrolebindings" else "RoleBinding"
    metadata: dict[str, Any] = {"name": record["name"]}
    if resource == "rolebindings":
        metadata["namespace"] = record.get("namespace", "")
    if record.get("annotations"):
        metadata["annotations"] = dict(record["annotations"])
    return {
        "kind": kind,
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "metadata": metadata,
        "subjects": [dict(s) for s in record.get("subjects", [])],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": record.get("role_ref", {}).get("kind", "ClusterRole"),
            "name": record.get("role_ref", {}).get("name", ""),
        },
    }


def expand_record(scenario_id: str, index: int, base_time: str, record: dict[str, Any]) -> dict[str, Any]:
    """Turn one compact scenario record into a full ``audit.k8s.io/v1`` Event."""
    received, stage = _iso(base_time, float(record.get("dt", 0)))
    audit_id = _audit_id(scenario_id, index)
    verb = record["verb"]
    resource = record["resource"]
    user: dict[str, Any] = {"username": record["actor"]}
    if record.get("groups"):
        user["groups"] = list(record["groups"])
    source_ips = [record["source_ip"]] if record.get("source_ip") else []
    user_agent = record.get("user_agent", _KUBECTL_UA)
    code = int(record.get("code", 201 if verb == "create" else 101))
    decision = "allow" if code < 400 else "forbid"
    annotations = {"authorization.k8s.io/decision": decision, "authorization.k8s.io/reason": ""}

    if resource == "pods/exec":
        namespace = record.get("namespace", "")
        name = record["name"]
        container = record.get("container", "")
        command = record.get("command", "/bin/sh")
        cmd_q = "&".join(f"command={_urlq(c)}" for c in command.split(" "))
        uri = (f"/api/v1/namespaces/{namespace}/pods/{name}/exec?{cmd_q}"
               f"{('&container=' + container) if container else ''}&stderr=true&stdout=true")
        object_ref = {"resource": "pods", "namespace": namespace, "name": name,
                      "apiVersion": "v1", "subresource": "exec"}
        event = {
            "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Request",
            "auditID": audit_id, "stage": "ResponseComplete", "requestURI": uri,
            "verb": "get", "user": user, "sourceIPs": source_ips, "userAgent": user_agent,
            "objectRef": object_ref, "responseStatus": {"metadata": {}, "code": code},
            "requestReceivedTimestamp": received, "stageTimestamp": stage,
            "annotations": annotations,
        }
        return event

    # RBAC binding create.
    object_ref = {"resource": resource, "name": record["name"],
                  "apiGroup": "rbac.authorization.k8s.io", "apiVersion": "v1"}
    if resource == "rolebindings":
        object_ref["namespace"] = record.get("namespace", "")
    uri = (f"/apis/rbac.authorization.k8s.io/v1/{resource}"
           "?fieldManager=kubectl-create&fieldValidation=Strict")
    request_object = _binding_object(record, resource)
    event = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse",
        "auditID": audit_id, "stage": "ResponseComplete", "requestURI": uri,
        "verb": "create", "user": user, "sourceIPs": source_ips, "userAgent": user_agent,
        "objectRef": object_ref, "requestObject": request_object,
        "responseStatus": {"metadata": {}, "code": code},
        "requestReceivedTimestamp": received, "stageTimestamp": stage,
        "annotations": annotations,
    }
    return event


def _urlq(value: str) -> str:
    import urllib.parse

    return urllib.parse.quote(value, safe="")


# -- leak lint --------------------------------------------------------------------------


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item)


def leak_hits(record: dict[str, Any]) -> list[tuple[str, str]]:
    """Every ``(token, string)`` pair where a leak token appears in an injected record."""
    hits: list[tuple[str, str]] = []
    for text in _walk_strings(record):
        for tok, rx in zip(LEAK_TOKENS, _LEAK_RES):
            if rx.search(text):
                hits.append((tok, text))
        if _TEST_RE.search(text) and "e2e.test" not in text and not re.search(r"test[-.]|[-.]test", text, re.IGNORECASE):
            hits.append(("test", text))
    return hits


def assert_no_leaks(records: list[dict[str, Any]]) -> None:
    """Raise if any injected record carries a label-leaking token. The builder calls this."""
    problems = []
    for record in records:
        for tok, text in leak_hits(record):
            problems.append(f"auditID={record.get('auditID', '?')}: token {tok!r} in {text!r}")
    if problems:
        raise ValueError("label-leak lint failed on injected telemetry:\n  " + "\n  ".join(problems))


# -- scenario file loading --------------------------------------------------------------


def scenarios_from_payload(payload: dict[str, Any], expected_quadrant: str) -> list[dict[str, Any]]:
    return _expand_payload(payload, expected_quadrant)


def _expand_payload(payload: dict[str, Any], expected_quadrant: str) -> list[dict[str, Any]]:
    if expected_quadrant not in _QUADRANTS:
        raise ValueError(f"unknown quadrant {expected_quadrant!r}")
    want_label = _LABELS[expected_quadrant]
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("scenario file needs a non-empty 'scenarios' list")
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    all_records: list[dict[str, Any]] = []
    for scenario in scenarios:
        sid = str(scenario.get("id", ""))
        if not sid or sid in seen_ids:
            raise ValueError(f"scenario id {sid!r} must be present and unique")
        seen_ids.add(sid)
        if scenario.get("label") != want_label:
            raise ValueError(f"scenario {sid!r}: label must be {want_label!r} for {expected_quadrant}")
        if not str(scenario.get("rationale", "")).strip():
            raise ValueError(f"scenario {sid!r}: a rationale is required (manifest only)")
        base_time = scenario.get("base_time")
        if not base_time:
            raise ValueError(f"scenario {sid!r}: base_time (ISO Z) is required")
        records = scenario.get("records")
        if not isinstance(records, list) or not records:
            raise ValueError(f"scenario {sid!r}: needs a non-empty records list")
        expanded = [expand_record(sid, i, base_time, r) for i, r in enumerate(records)]
        anchor_index = int(scenario.get("anchor", 0))
        if not 0 <= anchor_index < len(expanded):
            raise ValueError(f"scenario {sid!r}: anchor index out of range")
        link = None
        if scenario.get("link"):
            lk = scenario["link"]
            link = {"kind": lk["kind"],
                    "from_id": expanded[int(lk["from"])]["auditID"],
                    "to_id": expanded[int(lk["to"])]["auditID"]}
        out.append({
            "id": sid, "label": want_label, "rationale": scenario["rationale"],
            "base_time": base_time, "anchor_id": expanded[anchor_index]["auditID"],
            "records": expanded, "link": link,
        })
        all_records.extend(expanded)
    assert_no_leaks(all_records)
    return out


# -- k8s-benign scenarios (holdout role: secondary) ---------------------------------------------------
#
# Six benign look-alikes. Each has the surface shape of an escalation -- an admin-level
# grant or an exec into a pod -- but is what a real deploy, controller or on-call
# operator does. The label rationale stays out of the telemetry: identities, roles,
# namespaces and user-agents are the only signal, exactly as the model will see them.

K8S_BENIGN_PAYLOAD: dict[str, Any] = {
    "quadrant": "k8s-benign",
    "scenarios": [
        {
            "id": "helm-namespace-admin",
            "label": "benign",
            "base_time": "2026-06-11T03:03:00Z",
            "anchor": 0,
            "rationale": (
                "A release pipeline's own service account (deploy:release-bot) grants the "
                "namespaced 'admin' ClusterRole, via a RoleBinding scoped to its own "
                "namespace 'payments', to the application service account it deploys. This "
                "is what `helm upgrade --install` with an RBAC chart does on every release: "
                "the grant is namespaced (not cluster-wide), the beneficiary lives in the "
                "same namespace, the caller is a CI identity, and the user-agent is helm. "
                "No exec follows and nothing kube-system is touched."
            ),
            "records": [
                {"dt": 0, "actor": "system:serviceaccount:deploy:release-bot",
                 "groups": ["system:serviceaccounts", "system:serviceaccounts:deploy", "system:authenticated"],
                 "verb": "create", "resource": "rolebindings", "name": "payments-app-admin",
                 "namespace": "payments",
                 "subjects": [{"kind": "ServiceAccount", "name": "payments-app", "namespace": "payments"}],
                 "role_ref": {"kind": "ClusterRole", "name": "admin"},
                 "source_ip": "10.40.6.11", "user_agent": "helm/v3.14.4 (linux/amd64) kubernetes/3841ba0",
                 "code": 201},
            ],
        },
        {
            "id": "sre-oncall-exec-app",
            "label": "benign",
            "base_time": "2026-06-11T03:12:00Z",
            "anchor": 1,
            "link": {"kind": "before", "from": 0, "to": 1},
            "rationale": (
                "During a paging incident an on-call SRE (user oncall-sre, group platform-sre) "
                "lists pods in the application namespace 'checkout' and then execs a shell into "
                "one to read logs. The exec is into an application pod the SRE's team owns, not "
                "kube-system, from a corporate workstation IP, and it is preceded by the list "
                "call an operator makes first. Surface-severe (an interactive shell) but a "
                "routine incident action."
            ),
            "records": [
                {"dt": 0, "actor": "oncall-sre",
                 "groups": ["platform-sre", "system:authenticated"],
                 "verb": "create", "resource": "pods/exec", "name": "checkout-api-7d9c8b6f5-2xk4p",
                 "namespace": "checkout", "container": "checkout-api", "command": "/bin/sh",
                 "source_ip": "10.12.4.88", "user_agent": _KUBECTL_UA, "code": 101},
                {"dt": 30, "actor": "oncall-sre",
                 "groups": ["platform-sre", "system:authenticated"],
                 "verb": "create", "resource": "pods/exec", "name": "checkout-api-7d9c8b6f5-2xk4p",
                 "namespace": "checkout", "container": "checkout-api", "command": "cat /var/log/app.log",
                 "source_ip": "10.12.4.88", "user_agent": _KUBECTL_UA, "code": 101},
            ],
        },
        {
            "id": "controller-reconcile-rolebinding",
            "label": "benign",
            "base_time": "2026-06-11T03:20:00Z",
            "anchor": 0,
            "rationale": (
                "A namespace controller service account (kube-system:namespace-controller) "
                "recreates a default RoleBinding in a freshly created tenant namespace as part "
                "of reconciliation, from the in-cluster API address (::1) with a controller "
                "user-agent. Controllers create bindings constantly; the caller is a system "
                "controller, the role is a bounded namespaced role, and the loopback source "
                "distinguishes it from an external caller."
            ),
            "records": [
                {"dt": 0, "actor": "system:serviceaccount:kube-system:namespace-controller",
                 "groups": ["system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"],
                 "verb": "create", "resource": "rolebindings", "name": "system:tenant-default",
                 "namespace": "tenant-eng-473",
                 "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "tenant-eng-473"}],
                 "role_ref": {"kind": "Role", "name": "system:tenant-default"},
                 "source_ip": "::1", "user_agent": "kube-controller-manager/v1.37.0 (linux/amd64) kubernetes/3841ba0",
                 "code": 201},
            ],
        },
        {
            "id": "namespace-bootstrap-edit-team",
            "label": "benign",
            "base_time": "2026-06-11T03:31:00Z",
            "anchor": 0,
            "rationale": (
                "A platform admin bootstraps a new team namespace by granting the namespaced "
                "'edit' ClusterRole, via a RoleBinding in that namespace, to the team's OIDC "
                "group (oidc:team-data-eng). The grant is namespaced, the role is 'edit' not "
                "'admin' or 'cluster-admin', the beneficiary is a human team group, and it is a "
                "one-off provisioning action with a change-ticket annotation. Normal onboarding."
            ),
            "records": [
                {"dt": 0, "actor": "platform-admin",
                 "groups": ["platform-admins", "system:authenticated"],
                 "verb": "create", "resource": "rolebindings", "name": "team-data-eng-edit",
                 "namespace": "data-eng",
                 "subjects": [{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "oidc:team-data-eng"}],
                 "role_ref": {"kind": "ClusterRole", "name": "edit"},
                 "source_ip": "10.12.7.20", "user_agent": _KUBECTL_UA,
                 "annotations": {"change.company.example/ticket": "CHG-20614"}, "code": 201},
            ],
        },
        {
            "id": "ci-migration-exec-own-pod",
            "label": "benign",
            "base_time": "2026-06-11T03:42:00Z",
            "anchor": 0,
            "rationale": (
                "A deploy pipeline service account (deploy:release-bot) execs into the "
                "application pod it just rolled out to run a schema migration command, from the "
                "CI runner IP with a kubectl user-agent inside a job. The exec target is the "
                "pipeline's own application pod in the 'payments' namespace, the command is a "
                "migration, and it is the same identity that owns the deployment. A common "
                "post-deploy step, not a foreign shell."
            ),
            "records": [
                {"dt": 0, "actor": "system:serviceaccount:deploy:release-bot",
                 "groups": ["system:serviceaccounts", "system:serviceaccounts:deploy", "system:authenticated"],
                 "verb": "create", "resource": "pods/exec", "name": "payments-app-5f7b9c4d8-qw2mn",
                 "namespace": "payments", "container": "payments-app",
                 "command": "/app/bin/migrate up", "source_ip": "10.40.6.11",
                 "user_agent": _KUBECTL_UA, "code": 101},
            ],
        },
        {
            "id": "argocd-project-admin-binding",
            "label": "benign",
            "base_time": "2026-06-11T03:53:00Z",
            "anchor": 0,
            "rationale": (
                "A GitOps controller (argocd:application-controller) creates a namespaced "
                "RoleBinding granting the namespaced 'admin' role to its own application "
                "service account in a managed application namespace, applying a Git-declared "
                "manifest. The caller is the GitOps controller, the grant is namespaced and to "
                "the app's own SA, and it reconciles declared desired state. Routine GitOps."
            ),
            "records": [
                {"dt": 0, "actor": "system:serviceaccount:argocd:application-controller",
                 "groups": ["system:serviceaccounts", "system:serviceaccounts:argocd", "system:authenticated"],
                 "verb": "create", "resource": "rolebindings", "name": "storefront-admin",
                 "namespace": "storefront",
                 "subjects": [{"kind": "ServiceAccount", "name": "storefront", "namespace": "storefront"}],
                 "role_ref": {"kind": "ClusterRole", "name": "admin"},
                 "source_ip": "10.8.2.44",
                 "user_agent": "argocd-application-controller/v2.11.3+unknown",
                 "code": 201},
            ],
        },
    ],
}
