#!/usr/bin/env python3
"""Scoped controller mutations; real FRB tests, exact restoration, no concurrent edits."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
source = root / "companion/lib/provider/controller.dart"
original = source.read_bytes()
page = root / "companion/lib/provider/page.dart"
page_original = page.read_bytes()
review_files = {
    "session": root / "companion/lib/provider/review/review_session.dart",
    "review": root / "companion/lib/provider/request_review.dart",
}
review_originals = {key: path.read_bytes() for key, path in review_files.items()}
evidence = Path(sys.argv[1]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
mutations = {
    "saved-id": ("uncertainId: loaded.uncertainId", "uncertainId: ''"),
    "settlement-admission": ("      settingUp ||\n      _reconciling ||\n      _operation;", "      settingUp ||\n      _reconciling;"),
    "settlement-reload": ("} catch (_) {\n        _ready = false;", "} catch (_) {\n        _ready = true;"),
    "settlement-already-cleared": ("if (same &&\n          loaded.configured &&", "if (false &&\n          loaded.configured &&"),
    "route-eligibility": (" && _routeCurrent", ""),
    "foreground-eligibility": ("!suspended && _routeCurrent", "_routeCurrent"),
    "startup-reconciliation": ("if (!_ready) await _reconcile();", "if (!_ready && _loaded) await _reconcile();"),
    "setup-reconciliation": ("await _reconcile();\n    if (eligible)", "_ready = true;\n    if (eligible)"),
    "status-following": ("state.statusProgress == core.ProviderStatusProgress.committed", "false"),
    "typed-refresh": ("return accepted && _settlementId.isEmpty;", "return _settlementId.isEmpty;"),
}

page_mutations = {
    # The shell regressions assert nullable typed review as well as legacy text,
    # so these mutations exercise the generated structured-display path too.
    "navigation-retirement": ("controller.invalidate(); // mutation: navigation retirement", "// mutation: navigation retirement removed"),
    "back-retirement": ("controller.invalidate(); // mutation: back retirement", "// mutation: back retirement removed"),
}

# Review step and countdown (#50 slice 2): (file, anchor, replacement).
review_mutations = {
    "selection-closes-step": ("page", "reviewSession.beginLoad(id); // mutation: selection closes step", "// mutation: selection step close removed"),
    "changed-scope-closes-step": ("session", "closeStep(); // mutation: changed scope closes step", "// mutation: changed scope step close removed"),
    "step-clears-secrets": ("page", "clearPasswords(); // mutation: step change clears secrets", "// mutation: step secret clear removed"),
    "step-binding": ("session", "return bound ? _step : ReviewStep.review; // mutation: step binding", "return _step; // mutation: step binding removed"),
    "expiry-reached": ("session", "if (reached) _expired = true; // mutation: expiry reached", "// mutation: expiry never reached"),
    "expiry-latch": ("session", "return _expired; // mutation: expiry latch", "return reached; // mutation: expiry not latched"),
    "expired-view": ("review", "if (expired) {\n      // mutation: expired view", "if (false) {\n      // mutation: expired view removed"),
}
review_tests = ["test/review_authorization_test.dart", "test/review_states_test.dart"]

def run(name, tests=("test/provider_test.dart", "test/access_shell_test.dart")):
    with (evidence / f"{name}.log").open("wb") as log:
        return subprocess.run(["flutter", "test", "--reporter=expanded", *tests], cwd=root / "companion",
                              stdout=log, stderr=subprocess.STDOUT, timeout=180).returncode

report = {"source_sha256": hashlib.sha256(original).hexdigest(), "page_sha256": hashlib.sha256(page_original).hexdigest(), "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("controller baseline failed")
    if run("review-baseline", review_tests) != 0:
        raise RuntimeError("review baseline failed")
    for name, (old, new) in mutations.items():
        # saved-ID loading has two intentional paths (startup and reconciliation).
        expected = 2 if name == "saved-id" else 1
        if original.decode().count(old) != expected:
            raise RuntimeError(f"{name}: unexpected mutation anchor count")
        source.write_text(original.decode().replace(old, new))
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "[E]" in log and "Compilation failed" not in log and "Failed to load" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        source.write_bytes(original)
        if not caught:
            raise RuntimeError(f"{name}: escaped or did not reach assertions")
    for name, (old, new) in page_mutations.items():
        if page_original.decode().count(old) != 1:
            raise RuntimeError(f"{name}: unexpected mutation anchor count")
        page.write_text(page_original.decode().replace(old, new))
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "[E]" in log and "Compilation failed" not in log and "Failed to load" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        page.write_bytes(page_original)
        if not caught:
            raise RuntimeError(f"{name}: escaped or did not reach assertions")
    for name, (key, old, new) in review_mutations.items():
        path = page if key == "page" else review_files[key]
        pristine = page_original if key == "page" else review_originals[key]
        if pristine.decode().count(old) != 1:
            raise RuntimeError(f"{name}: unexpected mutation anchor count")
        path.write_text(pristine.decode().replace(old, new))
        code = run(name, review_tests)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "[E]" in log and "Compilation failed" not in log and "Failed to load" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        path.write_bytes(pristine)
        if not caught:
            raise RuntimeError(f"{name}: escaped or did not reach assertions")
finally:
    source.write_bytes(original)
    page.write_bytes(page_original)
    for key, path in review_files.items():
        path.write_bytes(review_originals[key])
    report["restored_page_sha256"] = hashlib.sha256(page.read_bytes()).hexdigest()
    report["restored_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    report["restored_test_exit"] = run("restored")
    report["restored_review_test_exit"] = run("review-restored", review_tests)
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
if report["restored_test_exit"] != 0 or report["restored_review_test_exit"] != 0:
    raise SystemExit("restored controller baseline failed")
