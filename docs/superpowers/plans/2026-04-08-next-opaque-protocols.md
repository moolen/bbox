# Next Opaque Protocols Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend bbox's opaque TCP observability with a conservative next tier of protocol detection for `mongodb`, `amqp`, `nats`, and `memcached`.

**Architecture:** Keep the protocol classifier isolated in `internal/helperruntime/ingress/protocol_detect.go` and expand it with only strong client-first byte signatures. Preserve existing `Kind` values and confidence semantics, and prefer `unknown` over speculative matches.

**Tech Stack:** Go, existing ingress protocol classifier, table-driven unit tests

---

### Task 1: Add failing tests for the next protocol tier

**Files:**
- Modify: `internal/helperruntime/ingress/protocol_detect_test.go`

- [ ] **Step 1: Write the failing tests**

Add table-driven cases for:

- MongoDB OP_MSG prefix -> `mongodb`
- AMQP protocol header -> `amqp`
- NATS `CONNECT {}` preface -> `nats`
- Memcached text request or binary request prefix -> `memcached`

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/helperruntime/ingress -run 'TestDetectOpaqueTCPProtocol' -count=1`

Expected: FAIL because the new protocol signatures are not recognized yet.

### Task 2: Implement conservative detection helpers

**Files:**
- Modify: `internal/helperruntime/ingress/protocol_detect.go`

- [ ] **Step 1: Write minimal implementation**

Add focused helpers that:

- detect MongoDB wire message headers by plausible frame length plus known opcode
- detect AMQP with the exact protocol header
- detect NATS with client-first textual commands such as `CONNECT `
- detect Memcached with either text protocol verbs or binary magic bytes

- [ ] **Step 2: Run focused test to verify it passes**

Run: `go test ./internal/helperruntime/ingress -run 'TestDetectOpaqueTCPProtocol' -count=1`

Expected: PASS

### Task 3: Regression verification and commit

**Files:**
- Modify: `docs/superpowers/specs/2026-04-08-protocol-observability-design.md` if the supported protocol list needs to stay in sync

- [ ] **Step 1: Run regression tests**

Run: `go test ./internal/helperruntime/ingress -run 'TestDetectOpaqueTCPProtocol|TestServeTransparentTCPConn' -count=1`

Expected: PASS

- [ ] **Step 2: Run broader verification**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/helperruntime/ingress/protocol_detect.go internal/helperruntime/ingress/protocol_detect_test.go docs/superpowers/plans/2026-04-08-next-opaque-protocols.md
git commit -m "feat: detect additional opaque tcp protocols"
```
