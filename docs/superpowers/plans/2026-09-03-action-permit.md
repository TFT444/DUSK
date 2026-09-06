# Signed Action Permit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a signed, short-lived, single-use Action Permit verifier for binding approved agent actions to DUSK policy decisions.

**Architecture:** A focused `dusk.permits` module will canonicalize a permit payload, sign it with Ed25519, and verify signature, time, action, policy version, and replay state. Private keys are supplied by callers and are never persisted by DUSK.

**Tech Stack:** Python 3.11+, `cryptography` Ed25519 primitives, dataclasses, pytest.

**Spec:** Issue #231 and the approved design in the conversation.

## Global Constraints

- Never store private keys, tokens, or customer data in the repository.
- Invalid, expired, replayed, or mismatched permits must fail closed.
- Canonical serialization must be deterministic and authenticated.
- Verification must not mutate state except recording a successfully consumed permit ID.
- Keep issue #231 and the PR open for review; do not merge.

### Task 1: Add failing permit contract tests

**Files:**
- Create: `tests/test_action_permits.py`

- [ ] **Step 1: Write tests for issuance and verification, expiry, binding, and replay.**
- [ ] **Step 2: Run `pytest tests/test_action_permits.py -q` and confirm collection fails because the module is absent.**

### Task 2: Implement the minimal signed permit module

**Files:**
- Create: `src/dusk/permits/__init__.py`
- Create: `src/dusk/permits/action.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Add the cryptography dependency.**
- [ ] **Step 2: Implement canonical payload creation, Ed25519 issuance, and fail-closed verification.**
- [ ] **Step 3: Run focused tests and confirm they pass.**

### Task 3: Document the protocol and verify repository checks

**Files:**
- Create: `docs/action-permit-protocol.md`

- [ ] **Step 1: Document fields, lifecycle, failure modes, and key handling.**
- [ ] **Step 2: Run focused tests, Ruff, and relevant policy tests.**
- [ ] **Step 3: Review the diff, commit with DCO signoff, push, and open a PR linked to #231.**

