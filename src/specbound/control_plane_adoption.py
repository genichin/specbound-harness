"""Deterministic Git evidence freezing for control-plane adoption."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import unicodedata

from jsonschema import Draft202012Validator
import yaml


_FULL_SHA1_RE = re.compile(r"[0-9a-f]{40}")
_RFC3339_OFFSET_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)
_UTC_RFC3339_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)"
)
_REQUIREMENT_PATH_RE = re.compile(
    r"\.specbound/requirements/(req-[0-9]+)/(req-[0-9]+)-r([1-9][0-9]*)\.md"
)
_CANARY_OUTCOME_PATH_RE = re.compile(
    r"\.specbound/canary-outcomes/(req-[0-9]+)/"
    r"(cny-[0-9]+-r([1-9][0-9]*)-(iteration_qc|delivery_qc)-a([1-9][0-9]*))\.json"
)
_ACTIVATION_PATH_RE = re.compile(
    r"\.specbound/activations/(req-[0-9]+)/"
    r"(act-[0-9]+-r([1-9][0-9]*)-(iteration_qc|delivery_qc))\.json"
)
_ITERATION_QC_PATH_RE = re.compile(
    r"\.specbound/iteration-qc/(req-[0-9]+)/"
    r"iqc-[0-9]+-[0-9]+-r([1-9][0-9]*)\.json"
)
_ADOPTION_PATH_RE = re.compile(
    r"\.specbound/adoptions/(req-[0-9]+)/"
    r"(adp-[0-9]+-r([1-9][0-9]*)-(iteration_qc|delivery_qc))\.json"
)


class _DuplicateKeyError(ValueError):
    pass


def _strict_json_loads(text: str) -> object:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKeyError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=reject_duplicate_keys)


class _StrictYamlLoader(yaml.SafeLoader):
    pass


def _construct_unique_yaml_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise _DuplicateKeyError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_yaml_mapping,
)


def _strict_yaml_load(text: str) -> object:
    return yaml.load(text, Loader=_StrictYamlLoader)


@dataclass(frozen=True)
class _BootstrapLedgerRow:
    exception_path: str
    transition: str
    target: str
    status: str
    expiry: str


@dataclass(frozen=True)
class _BootstrapLedger:
    active_count: int
    rows: tuple[_BootstrapLedgerRow, ...]


_BOOTSTRAP_LEDGER_HEADER = "| Exception | Transition | Target | Status | Expiry |"
_BOOTSTRAP_LEDGER_SEPARATOR = "| --- | --- | --- | --- | --- |"
_BOOTSTRAP_LEDGER_ROW_RE = re.compile(
    r"^\| \[`(?P<label>[^`]+\.md)`\]\((?P<path>[^)]+\.md)\) "
    r"\| `(?P<transition>[^`]+)` \| `(?P<target>[^`]+)` "
    r"\| `(?P<status>active|closed)` \| (?P<expiry>[^|]+) \|$"
)


def _parse_bootstrap_ledger(
    blob: bytes,
    *,
    requirement_path: str,
    exception_prefix: str,
) -> _BootstrapLedger:
    text = blob.decode("utf-8", errors="strict")
    lines = text.splitlines()
    active_lines = [
        line for line in lines if re.fullmatch(r"\*\*Active exceptions: [0-9]+\*\*", line)
    ]
    if len(active_lines) != 1:
        raise ValueError("Bootstrap ledger must declare one active exception count")
    active_count = int(active_lines[0].removeprefix("**Active exceptions: ").removesuffix("**"))
    if lines.count("## Inventory") != 1:
        raise ValueError("Bootstrap ledger must contain one Inventory section")
    inventory_index = lines.index("## Inventory")
    table_lines = [line for line in lines[inventory_index + 1 :] if line]
    if table_lines[:2] != [_BOOTSTRAP_LEDGER_HEADER, _BOOTSTRAP_LEDGER_SEPARATOR]:
        raise ValueError("Bootstrap ledger has a noncanonical table header")
    rows: list[_BootstrapLedgerRow] = []
    seen_exception_paths: set[str] = set()
    for line in table_lines[2:]:
        if not line.startswith("|"):
            break
        match = _BOOTSTRAP_LEDGER_ROW_RE.fullmatch(line)
        if match is None:
            if exception_prefix in line or requirement_path in line:
                raise ValueError("Bootstrap ledger has a malformed target row")
            continue
        exception_path = match.group("path")
        if match.group("label") != PurePosixPath(exception_path).name:
            raise ValueError("Bootstrap ledger link label does not match its path")
        row_targets_candidate = (
            PurePosixPath(exception_path).name.startswith(exception_prefix)
            or match.group("target") == requirement_path
        )
        if row_targets_candidate and exception_path in seen_exception_paths:
            raise ValueError("Bootstrap ledger contains a duplicate exception row")
        if row_targets_candidate:
            seen_exception_paths.add(exception_path)
        rows.append(
            _BootstrapLedgerRow(
                exception_path=exception_path,
                transition=match.group("transition"),
                target=match.group("target"),
                status=match.group("status"),
                expiry=match.group("expiry").strip(),
            )
        )
    if active_count != sum(row.status == "active" for row in rows):
        raise ValueError("Bootstrap ledger active exception count does not match its rows")
    return _BootstrapLedger(active_count=active_count, rows=tuple(rows))


@dataclass(frozen=True)
class GitEvidenceBlocker:
    """A stable, structured reason that Git evidence could not be frozen."""

    code: str
    path: str
    detail: str


@dataclass(frozen=True)
class LoadedControlPlaneRecord:
    family: str
    path: str
    data: dict[str, object]
    sha256: str


_CONTROL_PLANE_SCHEMAS = {
    "adoption": "adoption-decision.schema.json",
    "canary_outcome": "canary-outcome.schema.json",
    "activation": "activation-decision.schema.json",
}


def _canonical_json_bytes(record: dict[str, object]) -> bytes:
    return (
        json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _record_family_and_match(path: str) -> tuple[str, re.Match[str]] | None:
    for family, pattern in (
        ("adoption", _ADOPTION_PATH_RE),
        ("canary_outcome", _CANARY_OUTCOME_PATH_RE),
        ("activation", _ACTIVATION_PATH_RE),
    ):
        match = pattern.fullmatch(path)
        if match is not None:
            return family, match
    return None


def _record_identity_matches(
    family: str,
    match: re.Match[str],
    record: dict[str, object],
) -> bool:
    requirement_id = match.group(1)
    number = requirement_id[4:]
    revision = int(match.group(3))
    transition = match.group(4)
    requirement_path = (
        f".specbound/requirements/{requirement_id}/"
        f"{requirement_id}-r{revision}.md"
    )
    adoption_path = (
        f".specbound/adoptions/{requirement_id}/"
        f"adp-{number}-r{revision}-{transition}.json"
    )
    if family == "adoption":
        binding = record.get("requirement")
        return (
            match.group(2) == f"adp-{number}-r{revision}-{transition}"
            and record.get("adoption_id") == match.group(2)
            and record.get("transition") == transition
            and isinstance(binding, dict)
            and binding.get("path") == requirement_path
            and binding.get("id") == requirement_id
            and binding.get("revision") == revision
        )
    if family == "canary_outcome":
        adoption = record.get("adoption")
        return (
            match.group(2)
            == f"cny-{number}-r{revision}-{transition}-a{match.group(5)}"
            and record.get("canary_outcome_id") == match.group(2)
            and record.get("transition") == transition
            and record.get("attempt_sequence") == int(match.group(5))
            and isinstance(adoption, dict)
            and adoption.get("path") == adoption_path
        )
    adoption = record.get("adoption")
    outcome = record.get("canary_outcome")
    outcome_path = outcome.get("path") if isinstance(outcome, dict) else None
    outcome_match = (
        _CANARY_OUTCOME_PATH_RE.fullmatch(outcome_path)
        if isinstance(outcome_path, str)
        else None
    )
    return (
        match.group(2) == f"act-{number}-r{revision}-{transition}"
        and record.get("activation_id") == match.group(2)
        and record.get("transition") == transition
        and isinstance(adoption, dict)
        and adoption.get("path") == adoption_path
        and outcome_match is not None
        and outcome_match.group(1) == requirement_id
        and int(outcome_match.group(3)) == revision
        and outcome_match.group(4) == transition
    )


def _load_control_plane_record(
    root: Path,
    path: str,
) -> tuple[LoadedControlPlaneRecord | None, tuple[GitEvidenceBlocker, ...]]:
    family_match = _record_family_and_match(path)
    detail = "control-plane record must use canonical UTF-8 JSON bytes, schema, and path identity"
    blocker = GitEvidenceBlocker("malformed_control_plane_record", path, detail)
    if family_match is None or not _safe_repository_path(path):
        return None, (blocker,)
    family, path_match = family_match
    try:
        payload = (Path(root).resolve() / path).read_bytes()
        text = payload.decode("utf-8", errors="strict")
        record = _strict_json_loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
        return None, (blocker,)
    if not isinstance(record, dict) or payload != _canonical_json_bytes(record):
        return None, (blocker,)
    schema_path = Path(__file__).resolve().parent / "schemas" / _CONTROL_PLANE_SCHEMAS[family]
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, (blocker,)
    if tuple(Draft202012Validator(schema).iter_errors(record)):
        return None, (blocker,)
    if not _record_identity_matches(family, path_match, record):
        return None, (blocker,)
    return (
        LoadedControlPlaneRecord(
            family=family,
            path=path,
            data=record,
            sha256=sha256(payload).hexdigest(),
        ),
        (),
    )


def _validate_record_policy(
    root: Path,
    record: LoadedControlPlaneRecord,
    *,
    risk: str,
) -> tuple[GitEvidenceBlocker, ...]:
    expected_selector = {
        "adoption": "control_plane_adoption_authorities_by_risk",
        "activation": "control_plane_activation_authorities_by_risk",
    }.get(record.family)
    blocker = GitEvidenceBlocker(
        "malformed_control_plane_policy",
        record.path,
        "record policy must bind the exact current production authority matrix",
    )
    if expected_selector is None or risk not in {"low", "medium", "high"}:
        return (blocker,)
    try:
        config_bytes = (Path(root).resolve() / "specbound.yaml").read_bytes()
        config = _strict_yaml_load(config_bytes.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, _DuplicateKeyError):
        return (blocker,)
    policy = config.get("policy") if isinstance(config, dict) else None
    expected_alias = {"inherit": "discovery_confirmation_authorities_by_risk"}
    expected_matrix = {
        "low": ["repository-maintainer"],
        "medium": ["repository-maintainer"],
        "high": ["repository-maintainer", "Justin Ko"],
    }
    if (
        not isinstance(policy, dict)
        or policy.get("control_plane_adoption_authorities_by_risk") != expected_alias
        or policy.get("control_plane_activation_authorities_by_risk") != expected_alias
        or policy.get("discovery_confirmation_authorities_by_risk") != expected_matrix
    ):
        return (blocker,)
    binding = record.data.get("authority_policy")
    if not isinstance(binding, dict) or (
        binding.get("path") != "specbound.yaml"
        or binding.get("selector") != expected_selector
        or binding.get("sha256") != sha256(config_bytes).hexdigest()
    ):
        return (blocker,)
    if record.data.get("authority") not in expected_matrix[risk]:
        return (
            GitEvidenceBlocker(
                "unauthorized_control_plane_record",
                record.path,
                "record authority is not allowlisted for the effective risk",
            ),
        )
    return ()


@dataclass(frozen=True)
class AdoptionReadState:
    path: str
    sha256: str
    requirement_path: str
    requirement_id: str
    revision: int
    transition: str
    risk: str
    authority: str
    source_commit: str
    baseline_commit: str
    authority_action_id: str
    context_id: str


def resolve_adoption_read_state(
    root: Path,
    path: str,
) -> tuple[AdoptionReadState | None, tuple[GitEvidenceBlocker, ...]]:
    """Resolve one exact-canary adoption from canonical bytes and Git objects."""

    root = Path(root).resolve()
    loaded, blockers = _load_control_plane_record(root, path)
    if blockers or loaded is None or loaded.family != "adoption":
        return None, blockers or (
            GitEvidenceBlocker(
                "invalid_adoption_read_state", path, "path is not an adoption record"
            ),
        )
    record = loaded.data
    requirement = record.get("requirement")
    risk = record.get("risk")
    if not isinstance(requirement, dict) or not isinstance(risk, str):
        return None, (
            GitEvidenceBlocker(
                "invalid_adoption_read_state", path, "required adoption bindings are missing"
            ),
        )
    policy_blockers = _validate_record_policy(root, loaded, risk=risk)
    if policy_blockers:
        return None, policy_blockers
    if record.get("canary_work_attested_by") != record.get("authority"):
        return None, (
            GitEvidenceBlocker(
                "invalid_canary_work_attestation",
                path,
                "canary-work attester must be the accountable adoption authority",
            ),
        )

    source_commit = record.get("adoption_source_commit")
    baseline_commit = record.get("canary_capability_baseline_commit")
    requirement_path = requirement.get("path")
    invalid = GitEvidenceBlocker(
        "invalid_adoption_read_state",
        path,
        "adoption bindings do not resolve to one exact prospective Git state",
    )
    if not all(
        isinstance(value, str)
        for value in (source_commit, baseline_commit, requirement_path)
    ):
        return None, (invalid,)
    head, head_error = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    resolved_source, source_error = _git_text(
        root, "rev-parse", "--verify", f"{source_commit}^{{commit}}"
    )
    resolved_baseline, baseline_error = _git_text(
        root, "rev-parse", "--verify", f"{baseline_commit}^{{commit}}"
    )
    if (
        head_error is not None
        or source_error is not None
        or baseline_error is not None
        or head is None
        or resolved_source != source_commit
        or resolved_baseline != baseline_commit
    ):
        return None, (invalid,)
    for ancestor, descendant in (
        (baseline_commit, source_commit),
        (source_commit, head),
    ):
        if _git(root, "merge-base", "--is-ancestor", ancestor, descendant).returncode != 0:
            return None, (invalid,)

    baseline_at, baseline_time_error = _git_text(
        root, "show", "-s", "--format=%cI", baseline_commit
    )
    try:
        baseline_matches = (
            baseline_time_error is None
            and baseline_at is not None
            and _parse_git_timestamp(baseline_at)
            == _parse_utc_timestamp(str(record.get("canary_capability_baseline_at")))
        )
    except ValueError:
        baseline_matches = False
    if not baseline_matches:
        return None, (invalid,)

    requirement_blob = _git(root, "show", f"{source_commit}:{requirement_path}")
    if (
        requirement_blob.returncode != 0
        or sha256(requirement_blob.stdout).hexdigest() != requirement.get("sha256")
    ):
        return None, (invalid,)
    requirement_id = requirement.get("id")
    revision = requirement.get("revision")
    if not isinstance(requirement_id, str) or not isinstance(revision, int):
        return None, (invalid,)
    approval_path = f".specbound/approvals/{requirement_id}-r{revision}.approval.json"
    approval_blob = _git(root, "show", f"{source_commit}:{approval_path}")
    try:
        approval = _strict_json_loads(
            approval_blob.stdout.decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
        return None, (invalid,)
    if not isinstance(approval, dict) or any(
        (
            approval.get("requirement_path") != requirement_path,
            approval.get("requirement_id") != requirement_id,
            approval.get("revision") != revision,
            approval.get("sha256") != requirement.get("sha256"),
            approval.get("risk") != risk,
            approval.get("authority") != record.get("authority"),
        )
    ):
        return None, (
            GitEvidenceBlocker(
                "invalid_adoption_approval_binding",
                approval_path,
                "approval must bind the exact requirement, risk, and adoption authority",
            ),
        )
    try:
        approved_at = _parse_utc_timestamp(str(approval.get("approved_at")))
        baseline_timestamp = _parse_utc_timestamp(
            str(record.get("canary_capability_baseline_at"))
        )
    except ValueError:
        approved_at = baseline_timestamp = None
    if approved_at is None or baseline_timestamp is None or approved_at <= baseline_timestamp:
        return None, (
            GitEvidenceBlocker(
                "invalid_adoption_approval_timing",
                approval_path,
                "approval must be strictly after the capability baseline",
            ),
        )

    source_refs = record.get("canary_work_source_refs", ())
    source_keys: list[tuple[str, str, str]] = []
    for source_ref in source_refs:
        if not isinstance(source_ref, dict):
            return None, (invalid,)
        kind = source_ref.get("kind")
        identity = source_ref.get("path") if kind == "repository" else source_ref.get("id")
        digest = source_ref.get("sha256") if kind == "repository" else source_ref.get("digest")
        if (
            kind not in {"repository", "external"}
            or not isinstance(identity, str)
            or not isinstance(digest, str)
            or unicodedata.normalize("NFC", identity) != identity
        ):
            return None, (
                GitEvidenceBlocker(
                    "invalid_canary_source_refs",
                    path,
                    "source refs must use canonical normalized identities and digests",
                ),
            )
        source_keys.append((kind, identity, digest))
        if source_ref.get("kind") == "repository":
            source_path = source_ref.get("path")
            if not isinstance(source_path, str) or not _safe_repository_path(source_path):
                return None, (invalid,)
            source_blob = _git(root, "show", f"{source_commit}:{source_path}")
            if (
                source_blob.returncode != 0
                or sha256(source_blob.stdout).hexdigest() != source_ref.get("sha256")
            ):
                return None, (invalid,)
    if source_keys != sorted(source_keys) or len(source_keys) != len(set(source_keys)):
        return None, (
            GitEvidenceBlocker(
                "invalid_canary_source_refs",
                path,
                "source refs must be uniquely sorted by canonical identity",
            ),
        )

    prior_work = _current_planning_prior_work(
        root,
        baseline_commit=baseline_commit,
        source_commit=source_commit,
        requirement_path=requirement_path,
    )
    if prior_work:
        return None, prior_work
    return (
        AdoptionReadState(
            path=path,
            sha256=loaded.sha256,
            requirement_path=requirement_path,
            requirement_id=requirement_id,
            revision=revision,
            transition=str(record["transition"]),
            risk=risk,
            authority=str(record["authority"]),
            source_commit=source_commit,
            baseline_commit=baseline_commit,
            authority_action_id=str(record["authority_action_id"]),
            context_id=str(record["context_id"]),
        ),
        (),
    )


@dataclass(frozen=True)
class PassedCanaryOutcomeState:
    path: str
    sha256: str
    adoption_path: str
    adoption_sha256: str
    transition: str
    attempt_sequence: int
    authority: str
    authority_action_id: str
    context_id: str
    pre_close_commit: str
    pre_close_sha256: str
    exception_path: str
    outcome_commit: str


def resolve_passed_canary_outcome(
    root: Path,
    path: str,
) -> tuple[PassedCanaryOutcomeState | None, tuple[GitEvidenceBlocker, ...]]:
    """Resolve one passed outcome and its exact adoption/exception lineage."""

    root = Path(root).resolve()
    loaded, blockers = _load_control_plane_record(root, path)
    if blockers or loaded is None or loaded.family != "canary_outcome":
        return None, blockers or (
            GitEvidenceBlocker(
                "invalid_canary_outcome_lineage", path, "path is not a canary outcome"
            ),
        )
    record = loaded.data
    invalid = GitEvidenceBlocker(
        "invalid_canary_outcome_lineage",
        path,
        "outcome must bind one exact passed canary lineage",
    )
    adoption_binding = record.get("adoption")
    exception_binding = record.get("bootstrap_exception")
    if (
        record.get("outcome") != "passed"
        or not isinstance(adoption_binding, dict)
        or not isinstance(exception_binding, dict)
    ):
        return None, (invalid,)
    adoption_path = adoption_binding.get("path")
    if not isinstance(adoption_path, str):
        return None, (invalid,)
    adoption_state, adoption_blockers = resolve_adoption_read_state(root, adoption_path)
    if adoption_blockers or adoption_state is None:
        return None, adoption_blockers or (invalid,)
    if any(
        (
            adoption_binding.get("sha256") != adoption_state.sha256,
            record.get("transition") != adoption_state.transition,
            record.get("authority") != adoption_state.authority,
            record.get("authority_action_id") == adoption_state.authority_action_id,
            record.get("context_id") == adoption_state.context_id,
        )
    ):
        return None, (invalid,)

    head, error = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    if error is not None or head is None:
        return None, (invalid,)
    outcome_commit, error = _first_introduction(root, head, path)
    if error is not None or outcome_commit is None:
        return None, (invalid,)
    outcome_blob = _git(root, "show", f"{outcome_commit}:{path}")
    if (
        outcome_blob.returncode != 0
        or sha256(outcome_blob.stdout).hexdigest() != loaded.sha256
    ):
        return None, (invalid,)

    exception_path = exception_binding.get("path")
    pre_close_commit = exception_binding.get("pre_close_commit")
    pre_close_sha256 = exception_binding.get("pre_close_sha256")
    if not all(
        isinstance(value, str)
        for value in (exception_path, pre_close_commit, pre_close_sha256)
    ) or not _safe_repository_path(str(exception_path)):
        return None, (invalid,)
    resolved_pre_close, error = _git_text(
        root, "rev-parse", "--verify", f"{pre_close_commit}^{{commit}}"
    )
    if resolved_pre_close != pre_close_commit or error is not None:
        return None, (invalid,)
    if _git(
        root, "merge-base", "--is-ancestor", pre_close_commit, outcome_commit
    ).returncode != 0:
        return None, (invalid,)
    exception_blob = _git(root, "show", f"{pre_close_commit}:{exception_path}")
    if (
        exception_blob.returncode != 0
        or sha256(exception_blob.stdout).hexdigest() != pre_close_sha256
    ):
        return None, (invalid,)
    try:
        exception_text = exception_blob.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, (invalid,)
    expected_fragments = (
        "- Status: `active`",
        f"- Transition: `{adoption_state.transition}`",
        f"- Target artifact: `{adoption_state.requirement_path}`",
        f"- Authority identity: `{adoption_state.authority}`",
        "- Maximum review/attempt budget: `1`",
    )
    if not all(fragment in exception_text for fragment in expected_fragments):
        return None, (invalid,)
    try:
        recorded_at = _parse_utc_timestamp(str(record.get("recorded_at")))
        outcome_at_raw, outcome_time_error = _git_text(
            root, "show", "-s", "--format=%cI", outcome_commit
        )
        outcome_at = (
            _parse_git_timestamp(outcome_at_raw)
            if outcome_time_error is None and outcome_at_raw is not None
            else None
        )
    except ValueError:
        outcome_at = None
        recorded_at = None
    if outcome_at is None or recorded_at != outcome_at:
        return None, (invalid,)
    path_match = _CANARY_OUTCOME_PATH_RE.fullmatch(path)
    if path_match is None:
        return None, (invalid,)
    attempt_sequence = int(record["attempt_sequence"])
    for prior_sequence in range(1, attempt_sequence):
        prior_path = (
            f".specbound/canary-outcomes/{path_match.group(1)}/"
            f"cny-{path_match.group(1)[4:]}-r{path_match.group(3)}-"
            f"{path_match.group(4)}-a{prior_sequence}.json"
        )
        if _git(root, "cat-file", "-e", f"{outcome_commit}:{prior_path}").returncode != 0:
            return None, (
                GitEvidenceBlocker(
                    "noncontiguous_canary_attempt_sequence",
                    path,
                    "every earlier canary attempt must exist before this outcome",
                ),
            )
    return (
        PassedCanaryOutcomeState(
            path=path,
            sha256=loaded.sha256,
            adoption_path=adoption_path,
            adoption_sha256=adoption_state.sha256,
            transition=adoption_state.transition,
            attempt_sequence=attempt_sequence,
            authority=adoption_state.authority,
            authority_action_id=str(record["authority_action_id"]),
            context_id=str(record["context_id"]),
            pre_close_commit=str(pre_close_commit),
            pre_close_sha256=str(pre_close_sha256),
            exception_path=str(exception_path),
            outcome_commit=outcome_commit,
        ),
        (),
    )


@dataclass(frozen=True)
class SuccessfulActivationState:
    path: str
    sha256: str
    requirement_id: str
    requirement_path: str
    revision: int
    transition: str
    adoption_path: str
    outcome_path: str
    outcome_commit: str
    closeout_commit: str
    prospective_baseline_commit: str
    authority_action_id: str
    context_id: str


def resolve_successful_iqc_activation(
    root: Path,
    path: str,
) -> tuple[SuccessfulActivationState | None, tuple[GitEvidenceBlocker, ...]]:
    """Resolve one exact successful prospective iteration-QC activation."""

    root = Path(root).resolve()
    loaded, blockers = _load_control_plane_record(root, path)
    if blockers or loaded is None or loaded.family != "activation":
        return None, blockers or (
            GitEvidenceBlocker(
                "invalid_iqc_activation_chain", path, "path is not an activation record"
            ),
        )
    record = loaded.data
    invalid = GitEvidenceBlocker(
        "invalid_iqc_activation_chain",
        path,
        "activation must bind one exact successful prospective IQC chain",
    )
    if record.get("transition") != "iteration_qc":
        return None, (invalid,)
    adoption_binding = record.get("adoption")
    outcome_binding = record.get("canary_outcome")
    exception_binding = record.get("bootstrap_exception")
    ledger_binding = record.get("bootstrap_exception_ledger")
    if not all(
        isinstance(binding, dict)
        for binding in (
            adoption_binding,
            outcome_binding,
            exception_binding,
            ledger_binding,
        )
    ):
        return None, (invalid,)
    adoption_path = adoption_binding.get("path")
    outcome_path = outcome_binding.get("path")
    if not isinstance(adoption_path, str) or not isinstance(outcome_path, str):
        return None, (invalid,)
    adoption_state, adoption_blockers = resolve_adoption_read_state(root, adoption_path)
    outcome_state, outcome_blockers = resolve_passed_canary_outcome(root, outcome_path)
    if adoption_blockers or adoption_state is None:
        return None, adoption_blockers or (invalid,)
    if outcome_blockers or outcome_state is None:
        return None, outcome_blockers or (invalid,)
    if any(
        (
            adoption_binding.get("sha256") != adoption_state.sha256,
            outcome_binding.get("sha256") != outcome_state.sha256,
            outcome_state.adoption_path != adoption_path,
            record.get("passed_outcome_commit") != outcome_state.outcome_commit,
            record.get("authority") != adoption_state.authority,
        )
    ):
        return None, (invalid,)
    policy_blockers = _validate_record_policy(root, loaded, risk=adoption_state.risk)
    if policy_blockers:
        return None, policy_blockers
    action_ids = (
        adoption_state.authority_action_id,
        outcome_state.authority_action_id,
        record.get("authority_action_id"),
    )
    context_ids = (
        adoption_state.context_id,
        outcome_state.context_id,
        record.get("context_id"),
    )
    if len(set(action_ids)) != 3 or len(set(context_ids)) != 3:
        return None, (
            GitEvidenceBlocker(
                "reused_control_plane_identity",
                path,
                "adoption, outcome, and activation require fresh action and context IDs",
            ),
        )

    head, error = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    if error is not None or head is None:
        return None, (invalid,)
    activation_commit, error = _first_introduction(root, head, path)
    if error is not None or activation_commit is None:
        return None, (invalid,)
    activation_blob = _git(root, "show", f"{activation_commit}:{path}")
    if (
        activation_blob.returncode != 0
        or sha256(activation_blob.stdout).hexdigest() != loaded.sha256
    ):
        return None, (invalid,)

    closeout_commit = exception_binding.get("closeout_commit")
    baseline_commit = record.get("prospective_baseline_commit")
    exception_path = exception_binding.get("path")
    ledger_path = ledger_binding.get("path")
    if not all(
        isinstance(value, str)
        for value in (closeout_commit, baseline_commit, exception_path, ledger_path)
    ):
        return None, (invalid,)
    if closeout_commit == baseline_commit:
        return None, (
            GitEvidenceBlocker(
                "prospective_baseline_not_after_closeout",
                path,
                "prospective baseline must be a distinct descendant of closeout",
            ),
        )
    if any(
        _git(root, "merge-base", "--is-ancestor", ancestor, descendant).returncode
        != 0
        for ancestor, descendant in (
            (outcome_state.outcome_commit, closeout_commit),
            (closeout_commit, baseline_commit),
            (baseline_commit, activation_commit),
            (activation_commit, head),
        )
    ):
        return None, (invalid,)
    if any(
        (
            exception_binding.get("pre_close_commit") != outcome_state.pre_close_commit,
            exception_binding.get("pre_close_sha256") != outcome_state.pre_close_sha256,
            exception_path != outcome_state.exception_path,
        )
    ):
        return None, (invalid,)
    closed_blob = _git(root, "show", f"{closeout_commit}:{exception_path}")
    if (
        closed_blob.returncode != 0
        or sha256(closed_blob.stdout).hexdigest()
        != exception_binding.get("closed_sha256")
    ):
        return None, (invalid,)
    try:
        closed_text = closed_blob.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, (invalid,)
    closed_fragments = (
        "- Status: `closed`",
        f"- Transition: `{adoption_state.transition}`",
        f"- Target artifact: `{adoption_state.requirement_path}`",
        f"- Authority identity: `{adoption_state.authority}`",
        f"- Successful outcome: `{outcome_path}` at `{outcome_state.outcome_commit}`",
    )
    if not all(fragment in closed_text for fragment in closed_fragments):
        return None, (invalid,)

    ledger_blob = _git(root, "show", f"{baseline_commit}:{ledger_path}")
    if (
        ledger_blob.returncode != 0
        or sha256(ledger_blob.stdout).hexdigest() != ledger_binding.get("sha256")
    ):
        return None, (invalid,)
    try:
        ledger = _parse_bootstrap_ledger(
            ledger_blob.stdout,
            requirement_path=adoption_state.requirement_path,
            exception_prefix=(
                f"{adoption_state.requirement_id}-r{adoption_state.revision}-"
            ),
        )
    except (UnicodeDecodeError, ValueError):
        return None, (invalid,)
    exception_name = PurePosixPath(str(exception_path)).name
    matching_rows = [
        row
        for row in ledger.rows
        if row.exception_path == exception_name
        and row.transition == adoption_state.transition
        and row.target == adoption_state.requirement_path
        and row.status == "closed"
    ]
    if ledger.active_count != 0 or len(matching_rows) != 1:
        return None, (invalid,)

    baseline_at_raw, baseline_error = _git_text(
        root, "show", "-s", "--format=%cI", baseline_commit
    )
    activation_at_raw, activation_error = _git_text(
        root, "show", "-s", "--format=%cI", activation_commit
    )
    try:
        times_match = (
            baseline_error is None
            and activation_error is None
            and baseline_at_raw is not None
            and activation_at_raw is not None
            and _parse_git_timestamp(baseline_at_raw)
            == _parse_utc_timestamp(str(record.get("prospective_baseline_at")))
            and _parse_git_timestamp(activation_at_raw)
            == _parse_utc_timestamp(str(record.get("decided_at")))
        )
    except ValueError:
        times_match = False
    if not times_match:
        return None, (invalid,)
    return (
        SuccessfulActivationState(
            path=path,
            sha256=loaded.sha256,
            requirement_id=adoption_state.requirement_id,
            requirement_path=adoption_state.requirement_path,
            revision=adoption_state.revision,
            transition=adoption_state.transition,
            adoption_path=adoption_path,
            outcome_path=outcome_path,
            outcome_commit=outcome_state.outcome_commit,
            closeout_commit=str(closeout_commit),
            prospective_baseline_commit=str(baseline_commit),
            authority_action_id=str(record["authority_action_id"]),
            context_id=str(record["context_id"]),
        ),
        (),
    )


@dataclass(frozen=True)
class EffectiveActivationRegistry:
    activations: tuple[SuccessfulActivationState, ...]
    blockers: tuple[GitEvidenceBlocker, ...]

    @property
    def valid(self) -> bool:
        return not self.blockers


def _aggregate_effective_activation_states(
    states: tuple[SuccessfulActivationState, ...],
    blockers: tuple[GitEvidenceBlocker, ...],
) -> EffectiveActivationRegistry:
    ordered_states = tuple(
        sorted(
            states,
            key=lambda state: (
                state.requirement_id,
                state.revision,
                state.transition,
                state.path,
            ),
        )
    )
    aggregated = list(blockers)
    action_owners: dict[str, str] = {}
    context_owners: dict[str, str] = {}
    key_owners: dict[tuple[str, int, str], str] = {}
    for state in ordered_states:
        effective_key = (state.requirement_id, state.revision, state.transition)
        key_owner = key_owners.get(effective_key)
        if key_owner is not None:
            aggregated.append(
                GitEvidenceBlocker(
                    "ambiguous_effective_activation",
                    min(state.path, key_owner),
                    "more than one activation claims the same effective registry key",
                )
            )
        action_owner = action_owners.get(state.authority_action_id)
        context_owner = context_owners.get(state.context_id)
        if action_owner is not None or context_owner is not None:
            owners = [
                owner for owner in (action_owner, context_owner) if owner is not None
            ]
            aggregated.append(
                GitEvidenceBlocker(
                    "conflicting_effective_activation_identity",
                    min([state.path, *owners]),
                    "effective activations must use globally unique action and context IDs",
                )
            )
        action_owners.setdefault(state.authority_action_id, state.path)
        context_owners.setdefault(state.context_id, state.path)
        key_owners.setdefault(effective_key, state.path)
    ordered_blockers = tuple(
        sorted(aggregated, key=lambda blocker: (blocker.path, blocker.code, blocker.detail))
    )
    return EffectiveActivationRegistry(
        activations=() if ordered_blockers else ordered_states,
        blockers=ordered_blockers,
    )


def resolve_effective_activation_registry(root: Path) -> EffectiveActivationRegistry:
    """Reconstruct the effective activation registry from one sorted Git HEAD."""

    root = Path(root).resolve()
    head, error = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    if error is not None or head is None:
        return EffectiveActivationRegistry(
            activations=(),
            blockers=(
                GitEvidenceBlocker(
                    "git_query_failed",
                    ".specbound/activations",
                    error or "could not resolve HEAD",
                ),
            ),
        )
    listing, error = _git_text(
        root,
        "ls-tree",
        "-r",
        "--name-only",
        head,
        "--",
        ".specbound/activations",
    )
    if error is not None:
        return EffectiveActivationRegistry(
            activations=(),
            blockers=(
                GitEvidenceBlocker(
                    "git_query_failed", ".specbound/activations", error
                ),
            ),
        )
    paths = sorted(listing.splitlines() if listing else [])
    states: list[SuccessfulActivationState] = []
    blockers: list[GitEvidenceBlocker] = []
    for candidate_path in paths:
        if _ACTIVATION_PATH_RE.fullmatch(candidate_path) is None:
            candidate_blob = _git(root, "show", f"{head}:{candidate_path}")
            target_bound = False
            if candidate_blob.returncode == 0:
                try:
                    candidate = _strict_json_loads(
                        candidate_blob.stdout.decode("utf-8", errors="strict")
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    _DuplicateKeyError,
                ):
                    candidate = None
                if isinstance(candidate, dict):
                    activation_id = candidate.get("activation_id")
                    adoption_binding = candidate.get("adoption")
                    target_bound = (
                        isinstance(activation_id, str)
                        and activation_id.startswith("act-")
                        and isinstance(adoption_binding, dict)
                        and isinstance(adoption_binding.get("path"), str)
                        and candidate.get("transition") == "iteration_qc"
                    )
            if target_bound:
                blockers.append(
                    GitEvidenceBlocker(
                        "ambiguous_effective_activation",
                        candidate_path,
                        "noncanonical target-bound activation conflicts with the effective registry",
                    )
                )
            continue
        state, candidate_blockers = resolve_successful_iqc_activation(
            root, candidate_path
        )
        if state is None or candidate_blockers:
            detail = "; ".join(
                f"{blocker.code}:{blocker.path}" for blocker in candidate_blockers
            ) or "activation did not resolve"
            blockers.append(
                GitEvidenceBlocker(
                    "invalid_effective_activation",
                    candidate_path,
                    detail,
                )
            )
            continue
        states.append(state)
    return _aggregate_effective_activation_states(
        tuple(states),
        tuple(blockers),
    )


@dataclass(frozen=True)
class FrozenGitEvidence:
    """Immutable identities and blob digests read from one clean Git HEAD."""

    blockers: tuple[GitEvidenceBlocker, ...]
    object_format: str | None = None
    head_commit: str | None = None
    baseline_commit: str | None = None
    baseline_at: datetime | None = None
    requirement_path: str | None = None
    approval_path: str | None = None
    requirement_first_commit: str | None = None
    approval_first_commit: str | None = None
    blob_sha256: dict[str, str] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return not self.blockers


@dataclass(frozen=True)
class AdoptionEligibility:
    """Read-only result for one frozen exact-canary eligibility decision."""

    blockers: tuple[GitEvidenceBlocker, ...]

    @property
    def eligible(self) -> bool:
        return not self.blockers


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_text(root: Path, *args: str) -> tuple[str | None, str | None]:
    completed = _git(root, *args)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        return None, detail or f"git {' '.join(args)} exited {completed.returncode}"
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip(), None
    except UnicodeDecodeError as exc:
        return None, f"git {' '.join(args)} returned non-UTF-8 output: {exc}"


def _safe_repository_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _parse_utc_timestamp(value: str) -> datetime:
    if _UTC_RFC3339_RE.fullmatch(value) is None:
        raise ValueError("timestamp must be RFC3339 with an exact UTC offset")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use the UTC offset")
    return parsed.astimezone(timezone.utc)


def _parse_git_timestamp(value: str) -> datetime:
    if _RFC3339_OFFSET_RE.fullmatch(value) is None:
        raise ValueError("Git timestamp must be RFC3339 with an offset")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Git timestamp must include an offset")
    return parsed.astimezone(timezone.utc)


def _yaml_frontmatter(blob: bytes) -> dict | None:
    try:
        text = blob.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not text.startswith("---\n"):
        return None
    closing = text.find("\n---\n", 4)
    if closing < 0:
        return None
    try:
        value = _strict_yaml_load(text[4:closing])
    except (yaml.YAMLError, _DuplicateKeyError):
        return None
    return value if isinstance(value, dict) else None


def _mapping_values(node: yaml.Node, key: str) -> list[yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        return []
    return [
        value_node
        for key_node, value_node in node.value
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key
    ]


def _recover_unambiguous_malformed_binding(
    blob: bytes,
    *,
    frontmatter: bool,
) -> dict[str, object] | None:
    try:
        text = blob.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if frontmatter:
        if not text.startswith("---\n"):
            return None
        closing = text.find("\n---\n", 4)
        if closing < 0:
            return None
        text = text[4:closing]
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return None
    if root is None:
        return None
    mappings = _mapping_values(root, "requirement") if frontmatter else [root]
    if not mappings or any(not isinstance(node, yaml.MappingNode) for node in mappings):
        return None
    field_names = (
        ("path", "id", "revision")
        if frontmatter
        else ("requirement_path", "requirement_id", "revision")
    )
    recovered: dict[str, object] = {}
    for output_name, field_name in zip(("path", "id", "revision"), field_names):
        values = [
            value_node
            for mapping in mappings
            for value_node in _mapping_values(mapping, field_name)
        ]
        if not values or any(not isinstance(node, yaml.ScalarNode) for node in values):
            return None
        if output_name == "revision":
            if any(
                node.tag != "tag:yaml.org,2002:int"
                or re.fullmatch(r"[1-9][0-9]*", node.value) is None
                for node in values
            ):
                return None
            normalized: set[object] = {int(node.value) for node in values}
        else:
            if any(node.tag != "tag:yaml.org,2002:str" for node in values):
                return None
            normalized = {node.value for node in values}
        if len(normalized) != 1:
            return None
        recovered[output_name] = normalized.pop()
    return recovered


def _current_planning_prior_work(
    root: Path,
    *,
    baseline_commit: str,
    source_commit: str,
    requirement_path: str,
) -> tuple[GitEvidenceBlocker, ...]:
    match = _REQUIREMENT_PATH_RE.fullmatch(requirement_path)
    if match is None or match.group(1) != match.group(2):
        return ()
    requirement_id = match.group(1)
    revision = int(match.group(3))
    root_paths = (
        f".specbound/micro-specs/{requirement_id}",
        f".specbound/micro-spec-reviews/{requirement_id}",
        f".specbound/iteration-qc/{requirement_id}",
        ".specbound/delivery-qc",
        f".specbound/adoptions/{requirement_id}",
        f".specbound/canary-outcomes/{requirement_id}",
        f".specbound/activations/{requirement_id}",
        "docs/governance/bootstrap-exceptions",
    )
    history, error = _git_text(
        root, "rev-list", "--reverse", source_commit, f"^{baseline_commit}"
    )
    if error is not None:
        return (GitEvidenceBlocker("git_query_failed", root_paths[0], error),)
    blockers: dict[str, GitEvidenceBlocker] = {}
    for commit in history.splitlines() if history else []:
        if _FULL_SHA1_RE.fullmatch(commit) is None:
            blockers["adoption_source_commit"] = GitEvidenceBlocker(
                "git_query_failed",
                "adoption_source_commit",
                "prior-work history returned a non-SHA-1 commit identity",
            )
            continue
        listing, error = _git_text(
            root, "ls-tree", "-r", "--name-only", commit, "--", *root_paths
        )
        if error is not None:
            blockers[root_paths[0]] = GitEvidenceBlocker(
                "git_query_failed", root_paths[0], error
            )
            continue
        for path in sorted(listing.splitlines() if listing else []):
            blob = _git(root, "show", f"{commit}:{path}")
            if blob.returncode != 0:
                detail = blob.stderr.decode("utf-8", errors="replace").strip()
                blockers[path] = GitEvidenceBlocker(
                    "git_query_failed", path, detail or "could not read prior-work blob"
                )
                continue
            if path.startswith("docs/governance/bootstrap-exceptions/"):
                if path.endswith("/README.md"):
                    try:
                        ledger = _parse_bootstrap_ledger(
                            blob.stdout,
                            requirement_path=requirement_path,
                            exception_prefix=f"{requirement_id}-r{revision}-",
                        )
                    except (UnicodeDecodeError, ValueError) as exc:
                        blockers[path] = GitEvidenceBlocker(
                            "malformed_prior_work_evidence",
                            path,
                            str(exc),
                        )
                        continue
                    binding = None
                    for row in ledger.rows:
                        exception_name = PurePosixPath(row.exception_path).name
                        filename_targets_candidate = exception_name.startswith(
                            f"{requirement_id}-r{revision}-"
                        )
                        target_is_candidate = row.target == requirement_path
                        filename_transition = (
                            "iteration_qc"
                            if "-iteration-qc-" in exception_name
                            else "delivery_qc"
                            if "-delivery-qc-" in exception_name
                            else None
                        )
                        row_targets_candidate = (
                            filename_targets_candidate or target_is_candidate
                        )
                        if row_targets_candidate and not (
                            filename_targets_candidate
                            and target_is_candidate
                            and row.transition
                            and row.status in {"active", "closed"}
                            and row.expiry
                        ):
                            blockers[path] = GitEvidenceBlocker(
                                "malformed_prior_work_evidence",
                                path,
                                "Bootstrap ledger row has conflicting or incomplete target identity",
                            )
                            ledger_malformed = True
                            break
                        if (
                            row_targets_candidate
                            and filename_transition is not None
                            and row.transition != filename_transition
                        ):
                            blockers[path] = GitEvidenceBlocker(
                                "malformed_prior_work_evidence",
                                path,
                                "Bootstrap ledger transition conflicts with exception identity",
                            )
                            break
                        if row_targets_candidate:
                            binding = {
                                "path": row.target,
                                "id": requirement_id,
                                "revision": revision,
                            }
                    if path in blockers:
                        continue
                else:
                    try:
                        text = blob.stdout.decode("utf-8", errors="strict")
                    except UnicodeDecodeError:
                        text = ""
                    target_match = re.search(
                        r"(?m)^- Target artifact: `([^`]+)`$", text
                    )
                    identity_match = re.search(
                        r"(?m)^- Target ID/revision: `([^`]+)`$", text
                    )
                    transition_match = re.search(
                        r"(?m)^- Transition: `([^`]+)`$", text
                    )
                    target_bound_path = PurePosixPath(path).name.startswith(
                        f"{requirement_id}-r{revision}-"
                    )
                    filename_transition = (
                        "iteration_qc"
                        if "-iteration-qc-" in PurePosixPath(path).name
                        else "delivery_qc"
                        if "-delivery-qc-" in PurePosixPath(path).name
                        else None
                    )
                    exact_binding = (
                        target_match is not None
                        and target_match.group(1) == requirement_path
                        and identity_match is not None
                        and identity_match.group(1) == f"{requirement_id}-r{revision}"
                    )
                    transition_conflict = (
                        filename_transition is not None
                        and (
                            transition_match is None
                            or transition_match.group(1) != filename_transition
                        )
                    )
                    if target_bound_path and (not exact_binding or transition_conflict):
                        blockers[path] = GitEvidenceBlocker(
                            "malformed_prior_work_evidence",
                            path,
                            "target-bound Bootstrap exception identity is missing or inconsistent",
                        )
                        continue
                    binding = (
                        {
                            "path": target_match.group(1),
                            "id": requirement_id,
                            "revision": revision,
                        }
                        if exact_binding
                        else None
                    )
            elif path.startswith(".specbound/micro-specs/"):
                frontmatter = _yaml_frontmatter(blob.stdout)
                binding = (
                    frontmatter.get("requirement") if frontmatter is not None else None
                )
                if not isinstance(binding, dict) or not (
                    isinstance(binding.get("path"), str)
                    and isinstance(binding.get("id"), str)
                    and isinstance(binding.get("revision"), int)
                ):
                    recovered = _recover_unambiguous_malformed_binding(
                        blob.stdout,
                        frontmatter=True,
                    )
                    if (
                        recovered is not None
                        and recovered["id"] == requirement_id
                        and recovered["revision"] != revision
                        and recovered["path"]
                        == f".specbound/requirements/{requirement_id}/"
                        f"{requirement_id}-r{recovered['revision']}.md"
                    ):
                        continue
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "same-requirement Micro-SPEC has no parseable revision binding",
                    )
                    continue
                expected_binding_path = (
                    f".specbound/requirements/{binding['id']}/"
                    f"{binding['id']}-r{binding['revision']}.md"
                )
                if binding["id"] != requirement_id or binding["path"] != expected_binding_path:
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "Micro-SPEC requirement identity is inconsistent with its canonical root",
                    )
                    continue
            elif path.startswith(".specbound/micro-spec-reviews/"):
                try:
                    record = _strict_json_loads(blob.stdout.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
                    record = None
                if not isinstance(record, dict):
                    recovered = _recover_unambiguous_malformed_binding(
                        blob.stdout,
                        frontmatter=False,
                    )
                    if (
                        recovered is not None
                        and recovered["id"] == requirement_id
                        and recovered["revision"] != revision
                        and recovered["path"]
                        == f".specbound/requirements/{requirement_id}/"
                        f"{requirement_id}-r{recovered['revision']}.md"
                    ):
                        continue
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "same-requirement Micro-SPEC review is not a UTF-8 JSON object",
                    )
                    continue
                binding = (
                    {
                        "path": record.get("requirement_path"),
                        "id": record.get("requirement_id"),
                        "revision": record.get("revision"),
                    }
                )
                if not (
                    isinstance(binding["path"], str)
                    and isinstance(binding["id"], str)
                    and isinstance(binding["revision"], int)
                ):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "same-requirement review has no parseable requirement binding",
                    )
                    continue
            elif path.startswith(".specbound/iteration-qc/"):
                iqc_path_match = _ITERATION_QC_PATH_RE.fullmatch(path)
                if (
                    iqc_path_match is not None
                    and (
                        iqc_path_match.group(1) != requirement_id
                        or int(iqc_path_match.group(2)) != revision
                    )
                ):
                    continue
                try:
                    record = _strict_json_loads(blob.stdout.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
                    record = None
                if not isinstance(record, dict):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "same-requirement IQC record is not a UTF-8 JSON object",
                    )
                    continue
                micro_spec = record.get("micro_spec") if isinstance(record, dict) else None
                micro_spec_path = (
                    micro_spec.get("path") if isinstance(micro_spec, dict) else None
                )
                if not isinstance(micro_spec_path, str):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "same-requirement IQC record has no Micro-SPEC binding",
                    )
                    continue
                else:
                    micro_blob = _git(root, "show", f"{commit}:{micro_spec_path}")
                    micro_frontmatter = (
                        _yaml_frontmatter(micro_blob.stdout)
                        if micro_blob.returncode == 0
                        else None
                    )
                    binding = (
                        micro_frontmatter.get("requirement")
                        if micro_frontmatter is not None
                        else None
                    )
                    if not isinstance(binding, dict):
                        blockers[path] = GitEvidenceBlocker(
                            "malformed_prior_work_evidence",
                            path,
                            "IQC Micro-SPEC binding is missing or malformed in the same tree",
                        )
                        continue
            elif path.startswith((".specbound/canary-outcomes/", ".specbound/activations/")):
                try:
                    record = _strict_json_loads(blob.stdout.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
                    record = None
                path_match = (
                    _CANARY_OUTCOME_PATH_RE.fullmatch(path)
                    if path.startswith(".specbound/canary-outcomes/")
                    else _ACTIVATION_PATH_RE.fullmatch(path)
                )
                identity_field = (
                    "canary_outcome_id"
                    if path.startswith(".specbound/canary-outcomes/")
                    else "activation_id"
                )
                target_bound = (
                    path_match is not None
                    and path_match.group(1) == requirement_id
                    and path_match.group(3) == str(revision)
                )
                if not target_bound:
                    binding = None
                elif (
                    not isinstance(record, dict)
                    or record.get(identity_field) != path_match.group(2)
                    or record.get("transition") != path_match.group(4)
                    or (
                        path.startswith(".specbound/canary-outcomes/")
                        and record.get("attempt_sequence") != int(path_match.group(5))
                    )
                ):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "target-bound prior-work identity does not match its canonical path",
                    )
                    continue
                else:
                    binding = {
                        "path": requirement_path,
                        "id": requirement_id,
                        "revision": revision,
                    }
            else:
                try:
                    record = _strict_json_loads(blob.stdout.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
                    record = None
                number = requirement_id[4:]
                target_bound = path == (
                    f".specbound/delivery-qc/dqc-{number}-r{revision}.json"
                ) or path.startswith(
                    f".specbound/adoptions/{requirement_id}/"
                    f"adp-{number}-r{revision}-"
                )
                if not isinstance(record, dict) and _raw_mentions_candidate(
                    blob.stdout,
                    requirement_path=requirement_path,
                    requirement_id=requirement_id,
                    revision=revision,
                ):
                    target_bound = True
                if target_bound and not isinstance(record, dict):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "target-bound QC/adoption evidence is not a UTF-8 JSON object",
                    )
                    continue
                binding = record.get("requirement") if isinstance(record, dict) else None
                if target_bound and not isinstance(binding, dict):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "target-bound QC/adoption evidence has no requirement binding",
                    )
                    continue
                if target_bound and not (
                    binding.get("path") == requirement_path
                    and binding.get("id") == requirement_id
                    and binding.get("revision") == revision
                ):
                    blockers[path] = GitEvidenceBlocker(
                        "malformed_prior_work_evidence",
                        path,
                        "target-bound QC/adoption identity conflicts with its canonical path",
                    )
                    continue
                if target_bound and path.startswith(".specbound/adoptions/"):
                    adoption_path_match = _ADOPTION_PATH_RE.fullmatch(path)
                    if (
                        adoption_path_match is None
                        or record.get("adoption_id") != adoption_path_match.group(2)
                        or record.get("transition") != adoption_path_match.group(4)
                    ):
                        blockers[path] = GitEvidenceBlocker(
                            "malformed_prior_work_evidence",
                            path,
                            "target-bound adoption identity conflicts with its canonical path",
                        )
                        continue
            if not isinstance(binding, dict):
                continue
            if (
                binding.get("path") == requirement_path
                and binding.get("id") == requirement_id
                and binding.get("revision") == revision
            ):
                blockers[path] = GitEvidenceBlocker(
                    "prior_work_detected",
                    path,
                    "exact candidate has prior planning work after the capability baseline",
                )
    return tuple(blockers[path] for path in sorted(blockers))



def _raw_mentions_candidate(
    blob: bytes,
    *,
    requirement_path: str,
    requirement_id: str,
    revision: int,
) -> bool:
    try:
        text = blob.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return requirement_path in text or bool(
        re.search(
            rf"(?:['\"](?:requirement_)?id['\"]\s*:\s*['\"]{re.escape(requirement_id)}['\"])"
            rf"(?s:.*?)['\"]revision['\"]\s*:\s*{revision}(?:\D|$)",
            text,
        )
    )



def _first_introduction(root: Path, source_commit: str, path: str) -> tuple[str | None, str | None]:
    output, error = _git_text(
        root,
        "log",
        "--reverse",
        "--format=%H",
        "--diff-filter=A",
        source_commit,
        "--",
        path,
    )
    if error is not None:
        return None, error
    commits = output.splitlines() if output else []
    if not commits or not _FULL_SHA1_RE.fullmatch(commits[0]):
        return None, "path has no full SHA-1 introduction commit reachable from frozen HEAD"
    return commits[0], None


def freeze_git_evidence(
    root: Path,
    *,
    requirement_path: str,
    approval_path: str,
    baseline_commit: str,
    baseline_at: str,
    repository_source_paths: tuple[str, ...] = (),
) -> FrozenGitEvidence:
    """Freeze clean-HEAD identities and Git-tree blob digests for adoption checks.

    The checkout is used only to locate the repository. Commit identities,
    timestamps, introduction history, and bytes all come from Git objects.
    """

    root = Path(root).resolve()
    blockers: list[GitEvidenceBlocker] = []

    object_format, error = _git_text(root, "rev-parse", "--show-object-format")
    if error is not None:
        return FrozenGitEvidence(
            blockers=(GitEvidenceBlocker("not_git_repository", ".", error),)
        )
    if object_format != "sha1":
        return FrozenGitEvidence(
            blockers=(
                GitEvidenceBlocker(
                    "unsupported_git_object_format",
                    ".git",
                    "control-plane adoption V1 requires exact sha1 Git object format",
                ),
            ),
            object_format=object_format,
        )

    shallow, error = _git_text(root, "rev-parse", "--is-shallow-repository")
    if error is not None:
        blockers.append(GitEvidenceBlocker("git_query_failed", ".git", error))
    elif shallow != "false":
        blockers.append(
            GitEvidenceBlocker(
                "shallow_repository",
                ".git",
                "complete reachable history is required to freeze introduction evidence",
            )
        )

    head_commit, error = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    if error is not None or head_commit is None or not _FULL_SHA1_RE.fullmatch(head_commit):
        blockers.append(
            GitEvidenceBlocker(
                "invalid_head_commit",
                "HEAD",
                error or "HEAD is not a full lowercase SHA-1 commit",
            )
        )
        head_commit = None

    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status.returncode != 0:
        detail = status.stderr.decode("utf-8", errors="replace").strip()
        blockers.append(
            GitEvidenceBlocker("git_query_failed", ".", detail or "could not inspect worktree")
        )
    else:
        status_lines = tuple(line for line in status.stdout.splitlines() if line)
        if any(not line.startswith(b"??") for line in status_lines):
            blockers.append(
                GitEvidenceBlocker(
                    "dirty_tracked_worktree",
                    ".",
                    "tracked worktree changes must be absent before evidence freeze",
                )
            )
        if any(line.startswith(b"??") for line in status_lines):
            blockers.append(
                GitEvidenceBlocker(
                    "untracked_worktree",
                    ".",
                    "untracked worktree changes must be absent before evidence freeze",
                )
            )

    verified_baseline: str | None = None
    if not _FULL_SHA1_RE.fullmatch(baseline_commit):
        blockers.append(
            GitEvidenceBlocker(
                "invalid_baseline_commit",
                "baseline_commit",
                "baseline must be a full lowercase 40-hex SHA-1 commit",
            )
        )
    else:
        verified_baseline, error = _git_text(
            root, "rev-parse", "--verify", f"{baseline_commit}^{{commit}}"
        )
        if error is not None or verified_baseline != baseline_commit:
            blockers.append(
                GitEvidenceBlocker(
                    "invalid_baseline_commit",
                    "baseline_commit",
                    error or "baseline did not resolve to the exact requested commit",
                )
            )
            verified_baseline = None

    derived_baseline_at: datetime | None = None
    if verified_baseline is not None:
        timestamp, error = _git_text(root, "show", "-s", "--format=%cI", verified_baseline)
        if error is not None or timestamp is None:
            blockers.append(
                GitEvidenceBlocker(
                    "git_query_failed", "baseline_commit", error or "missing committer timestamp"
                )
            )
        else:
            try:
                derived_baseline_at = _parse_git_timestamp(timestamp)
                requested_baseline_at = _parse_utc_timestamp(baseline_at)
            except ValueError as exc:
                blockers.append(
                    GitEvidenceBlocker("invalid_baseline_timestamp", "baseline_at", str(exc))
                )
            else:
                if requested_baseline_at != derived_baseline_at:
                    blockers.append(
                        GitEvidenceBlocker(
                            "baseline_timestamp_mismatch",
                            "baseline_at",
                            "caller timestamp differs from the baseline commit committer timestamp",
                        )
                    )

    if head_commit is not None and verified_baseline is not None:
        ancestry = _git(root, "merge-base", "--is-ancestor", verified_baseline, head_commit)
        if ancestry.returncode == 1:
            blockers.append(
                GitEvidenceBlocker(
                    "baseline_not_ancestor",
                    "baseline_commit",
                    "baseline commit is not an ancestor of frozen HEAD",
                )
            )
        elif ancestry.returncode != 0:
            detail = ancestry.stderr.decode("utf-8", errors="replace").strip()
            blockers.append(
                GitEvidenceBlocker(
                    "git_query_failed",
                    "baseline_commit",
                    detail or "could not verify baseline ancestry",
                )
            )

    paths = (requirement_path, approval_path, *repository_source_paths)
    seen: set[str] = set()
    for path in paths:
        if not _safe_repository_path(path):
            blockers.append(
                GitEvidenceBlocker(
                    "unsafe_repository_path",
                    path,
                    "path must use canonical safe repository-relative POSIX spelling",
                )
            )
        elif path in seen:
            blockers.append(
                GitEvidenceBlocker(
                    "duplicate_repository_path", path, "evidence paths must be unique"
                )
            )
        seen.add(path)

    blob_sha256: dict[str, str] = {}
    if head_commit is not None:
        for path in paths:
            if not _safe_repository_path(path) or path in blob_sha256:
                continue
            blob = _git(root, "show", f"{head_commit}:{path}")
            if blob.returncode != 0:
                detail = blob.stderr.decode("utf-8", errors="replace").strip()
                blockers.append(
                    GitEvidenceBlocker(
                        "missing_repository_blob",
                        path,
                        detail or "path is absent from frozen HEAD tree",
                    )
                )
                continue
            blob_sha256[path] = sha256(blob.stdout).hexdigest()

    requirement_first_commit: str | None = None
    approval_first_commit: str | None = None
    if head_commit is not None and _safe_repository_path(requirement_path):
        requirement_first_commit, error = _first_introduction(
            root, head_commit, requirement_path
        )
        if error is not None:
            blockers.append(
                GitEvidenceBlocker("missing_introduction_commit", requirement_path, error)
            )
    if head_commit is not None and _safe_repository_path(approval_path):
        approval_first_commit, error = _first_introduction(root, head_commit, approval_path)
        if error is not None:
            blockers.append(
                GitEvidenceBlocker("missing_introduction_commit", approval_path, error)
            )

    return FrozenGitEvidence(
        blockers=tuple(blockers),
        object_format=object_format,
        head_commit=head_commit,
        baseline_commit=verified_baseline,
        baseline_at=derived_baseline_at,
        requirement_path=requirement_path,
        approval_path=approval_path,
        requirement_first_commit=requirement_first_commit,
        approval_first_commit=approval_first_commit,
        blob_sha256=blob_sha256,
    )


def resolve_adoption_eligibility(
    root: Path,
    *,
    evidence: FrozenGitEvidence,
    approved_at: str,
    transition: str,
) -> AdoptionEligibility:
    """Resolve eligibility from one immutable Git evidence snapshot."""

    if evidence.blockers:
        return AdoptionEligibility(blockers=evidence.blockers)
    if transition not in {"iteration_qc", "delivery_qc"}:
        return AdoptionEligibility(
            blockers=(
                GitEvidenceBlocker(
                    "unsupported_adoption_transition",
                    "transition",
                    "transition must be iteration_qc or delivery_qc",
                ),
            )
        )
    if (
        evidence.baseline_commit is None
        or evidence.baseline_at is None
        or evidence.requirement_path is None
        or evidence.approval_path is None
    ):
        return AdoptionEligibility(
            blockers=(
                GitEvidenceBlocker(
                    "incomplete_git_evidence",
                    "baseline_commit",
                    "eligibility requires a frozen baseline, requirement path, and approval path",
                ),
            )
        )

    root = Path(root).resolve()
    blockers: list[GitEvidenceBlocker] = []
    for family, path, introduction_commit in (
        (
            "requirement",
            evidence.requirement_path,
            evidence.requirement_first_commit,
        ),
        ("approval", evidence.approval_path, evidence.approval_first_commit),
    ):
        history, error = _git_text(
            root,
            "rev-list",
            "--full-history",
            evidence.baseline_commit,
            "--",
            path,
        )
        if error is not None:
            blockers.append(
                GitEvidenceBlocker(
                    "git_query_failed", path, error
                )
            )
        elif history:
            blockers.append(
                GitEvidenceBlocker(
                    f"{family}_existed_at_or_before_baseline",
                    path,
                    f"{family} path has history reachable from the capability baseline",
                )
            )
        elif introduction_commit is None:
            blockers.append(
                GitEvidenceBlocker(
                    "incomplete_git_evidence",
                    path,
                    f"{family} introduction commit is missing",
                )
            )
        else:
            introduced_at, error = _git_text(
                root, "show", "-s", "--format=%cI", introduction_commit
            )
            if error is not None or introduced_at is None:
                blockers.append(
                    GitEvidenceBlocker(
                        "git_query_failed",
                        path,
                        error or f"could not read {family} introduction timestamp",
                    )
                )
            else:
                try:
                    parsed_introduced_at = _parse_git_timestamp(introduced_at)
                except ValueError as exc:
                    blockers.append(
                        GitEvidenceBlocker(
                            "invalid_introduction_timestamp", path, str(exc)
                        )
                    )
                else:
                    if parsed_introduced_at <= evidence.baseline_at:
                        blockers.append(
                            GitEvidenceBlocker(
                                f"{family}_introduction_not_after_baseline",
                                path,
                                f"{family} introduction must be strictly after the capability baseline",
                            )
                        )
    try:
        parsed_approved_at = _parse_utc_timestamp(approved_at)
    except ValueError as exc:
        blockers.append(
            GitEvidenceBlocker("invalid_approved_at", "approved_at", str(exc))
        )
    else:
        if parsed_approved_at <= evidence.baseline_at:
            blockers.append(
                GitEvidenceBlocker(
                    "approval_not_after_baseline",
                    "approved_at",
                    "approval timestamp must be strictly after the capability baseline",
                )
            )
    if evidence.head_commit is not None:
        blockers.extend(
            _current_planning_prior_work(
                root,
                baseline_commit=evidence.baseline_commit,
                source_commit=evidence.head_commit,
                requirement_path=evidence.requirement_path,
            )
        )
    if transition == "delivery_qc":
        requirement_match = _REQUIREMENT_PATH_RE.fullmatch(evidence.requirement_path)
        requirement_id = (
            requirement_match.group(1) if requirement_match is not None else "unknown"
        )
        revision = requirement_match.group(3) if requirement_match is not None else "0"
        number = requirement_id[4:] if requirement_id.startswith("req-") else "unknown"
        activation_root = f".specbound/activations/{requirement_id}"
        activation_path = (
            f"{activation_root}/act-{number}-r{revision}-iteration_qc.json"
        )
        listing, listing_error = _git_text(
            root,
            "ls-tree",
            "-r",
            "--name-only",
            evidence.head_commit or "HEAD",
            "--",
            activation_root,
        )
        activation_paths = set(listing.splitlines() if listing else [])
        expected_adoption_path = (
            f".specbound/adoptions/{requirement_id}/"
            f"adp-{number}-r{revision}-iteration_qc.json"
        )
        expected_activation_id = f"act-{number}-r{revision}-iteration_qc"
        conflicting_paths: list[str] = []
        for candidate_path in sorted(activation_paths - {activation_path}):
            candidate_blob = _git(
                root,
                "show",
                f"{evidence.head_commit or 'HEAD'}:{candidate_path}",
            )
            if candidate_blob.returncode != 0:
                conflicting_paths.append(candidate_path)
                continue
            try:
                candidate = _strict_json_loads(
                    candidate_blob.stdout.decode("utf-8", errors="strict")
                )
            except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError):
                if PurePosixPath(candidate_path).name.startswith(expected_activation_id):
                    conflicting_paths.append(candidate_path)
                continue
            adoption_binding = candidate.get("adoption") if isinstance(candidate, dict) else None
            if isinstance(candidate, dict) and (
                candidate.get("activation_id") == expected_activation_id
                or (
                    isinstance(adoption_binding, dict)
                    and adoption_binding.get("path") == expected_adoption_path
                    and candidate.get("transition") == "iteration_qc"
                )
            ):
                conflicting_paths.append(candidate_path)
        if listing_error is not None:
            blockers.append(
                GitEvidenceBlocker("git_query_failed", activation_root, listing_error)
            )
        elif conflicting_paths:
            blockers.append(
                GitEvidenceBlocker(
                    "invalid_iteration_qc_activation",
                    conflicting_paths[0],
                    "duplicate or malformed target-bound activation evidence is ambiguous",
                )
            )
        elif activation_path not in activation_paths:
            blockers.append(
                GitEvidenceBlocker(
                    "missing_successful_iteration_qc_activation",
                    activation_root,
                    "delivery-QC adoption requires one exact successful iteration-QC activation",
                )
            )
        else:
            activation_state, activation_blockers = resolve_successful_iqc_activation(
                root, activation_path
            )
            if activation_state is None or activation_blockers:
                detail = "; ".join(
                    f"{blocker.code}:{blocker.path}"
                    for blocker in activation_blockers
                ) or "activation did not resolve"
                blockers.append(
                    GitEvidenceBlocker(
                        "invalid_iteration_qc_activation",
                        activation_path,
                        detail,
                    )
                )
    return AdoptionEligibility(blockers=tuple(blockers))
