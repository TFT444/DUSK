# Compliance Control Catalogue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an evidence-backed compliance control catalogue for the first 50% of DUSK security work without claiming external certification.

**Architecture:** Store stable control metadata in a versioned YAML catalogue next to the existing enterprise policy pack. Add a small Python validator that checks IDs, statuses, framework references, and evidence links. Keep enforcement decisions in the existing policy engine and use the catalogue as traceability metadata.

**Tech Stack:** YAML, Python, pytest, existing DUSK policy files and documentation.

**Spec:** `docs/enterprise-policy-pack.md`, `docs/threat-model.md`, and issue #234.

## Global Constraints

- Use stable control IDs and explicit version fields.
- Valid statuses are `implemented`, `partial`, `planned`, `blocked`, and `unverified`.
- A mapping must never imply OWASP, NIST, ISO 27001, SOC 2, or CIS certification.
- Evidence references must point to repository paths, tests, or documented workflow evidence.
- Missing evidence must remain visible and must not be converted into an implemented claim.

### Task 1: Define the catalogue contract

**Files:**
- Create: `src/dusk/policies/compliance-v1.yaml`
- Test: `tests/test_compliance_catalogue.py`

**Interfaces:**
- The YAML contains `catalogue_id`, `version`, and `controls`.
- Each control contains `id`, `title`, `status`, `frameworks`, `evidence`, and `notes`.
- The test module exposes a loader and validator contract for later documentation checks.

- [ ] **Step 1: Write failing tests**

```python
def test_catalogue_has_unique_ids_and_allowed_statuses():
    catalogue = load_catalogue()
    assert catalogue["catalogue_id"] == "dusk-compliance"
    ids = [control["id"] for control in catalogue["controls"]]
    assert len(ids) == len(set(ids))
    assert {control["status"] for control in catalogue["controls"]} <= VALID_STATUSES

def test_catalogue_controls_have_frameworks_and_evidence():
    catalogue = load_catalogue()
    for control in catalogue["controls"]:
        assert control["frameworks"]
        assert control["evidence"]
```

- [ ] **Step 2: Run tests and verify the expected failure**

Run: `pytest tests/test_compliance_catalogue.py -q`
Expected: FAIL because the catalogue and loader do not exist.

- [ ] **Step 3: Add the minimal catalogue and loader**

Create the ten first-50-percent controls approved in the design, with truthful statuses and repository evidence paths. Add a loader that reads YAML and validates the top-level shape.

- [ ] **Step 4: Run the focused tests**

Run: `pytest tests/test_compliance_catalogue.py -q`
Expected: PASS.

### Task 2: Validate evidence references and framework mappings

**Files:**
- Modify: `tests/test_compliance_catalogue.py`
- Modify: `src/dusk/policies/compliance-v1.yaml`

**Interfaces:**
- Evidence paths are repository-relative strings.
- Framework names are limited to `OWASP`, `NIST AI RMF`, `NIST CSF`, `ISO 27001`, `SOC 2`, and `CIS Controls`.

- [ ] **Step 1: Add failing tests**

```python
def test_evidence_paths_exist_or_are_explicitly_unverified():
    catalogue = load_catalogue()
    for control in catalogue["controls"]:
        if control["status"] in {"implemented", "partial"}:
            assert all(Path(path).exists() for path in control["evidence"])

def test_framework_names_are_allowlisted():
    catalogue = load_catalogue()
    for control in catalogue["controls"]:
        assert set(control["frameworks"]) <= ALLOWED_FRAMEWORKS
```

- [ ] **Step 2: Run the tests and verify failure for missing references**

Run: `pytest tests/test_compliance_catalogue.py -q`
Expected: FAIL for any incorrect path or unsupported framework name.

- [ ] **Step 3: Correct the catalogue metadata**

Use existing policy, test, threat-model, and evidence files. Mark controls without direct enforcement as `partial`, `planned`, or `unverified`.

- [ ] **Step 4: Run the focused tests**

Run: `pytest tests/test_compliance_catalogue.py -q`
Expected: PASS with no warnings.

### Task 3: Publish the compliance documentation

**Files:**
- Create: `docs/compliance-control-catalogue.md`
- Modify: `docs/enterprise-policy-pack.md`
- Modify: `docs/owasp-technical-evidence.json`

**Interfaces:**
- Documentation renders the same control IDs, statuses, frameworks, and evidence paths as the YAML catalogue.
- Documentation includes a clear statement that mappings are not certifications.

- [ ] **Step 1: Add documentation consistency tests**

```python
def test_documentation_mentions_catalogue_and_claim_boundary():
    text = Path("docs/compliance-control-catalogue.md").read_text(encoding="utf-8")
    assert "compliance-v1.yaml" in text
    assert "does not claim certification" in text
```

- [ ] **Step 2: Run the documentation test and verify the expected failure**

Run: `pytest tests/test_compliance_catalogue.py -q`
Expected: FAIL until the documentation is created.

- [ ] **Step 3: Write the catalogue documentation**

Describe the statuses, framework scope, evidence rules, review process, and known gaps. Link the YAML catalogue and existing policy and threat-model documents.

- [ ] **Step 4: Run focused and repository policy tests**

Run: `pytest tests/test_compliance_catalogue.py tests/test_enterprise_policies.py tests/test_owasp_readiness.py -q`
Expected: PASS.

### Task 4: Final verification and issue evidence

**Files:**
- Modify: `docs/compliance-control-catalogue.md`

- [ ] Run: `pytest tests/test_compliance_catalogue.py tests/test_enterprise_policies.py tests/test_owasp_readiness.py -q`
- [ ] Run the repository lint and formatting commands documented by the project.
- [ ] Confirm no secrets, customer data, or certification claims are present.
- [ ] Add the final test command, commit SHA, and changed-file summary to issue #234.
