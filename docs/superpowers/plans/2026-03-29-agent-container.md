# Agent Container Plan

> **For agentic workers:** Execute inline in this session. Keep the changes focused on container/tooling support for local development and AI-agent workflows.

**Goal:** Add a `Dockerfile`, `Makefile`, and Docker usage documentation so this repository can be opened in a tool-rich container and used directly by an AI agent.

**Architecture:** Build `bbox` and `bbox-helper` in a dedicated builder stage, then provide a Debian-based runtime image with the Go toolchain, Bubblewrap runtime dependencies, lint tooling, and common shell utilities. Default the container to an interactive shell in `/workspace` so a mounted checkout behaves like a ready-to-use agent environment.

**Files:**
- Create: `Dockerfile`
- Create: `Makefile`
- Create: `.dockerignore`
- Modify: `.gitignore`
- Modify: `README.md`

### Task 1: Add local build and image targets

- [ ] Add a `Makefile` with `build`, `docker-build`, and `lint` targets.
- [ ] Build `cmd/bbox` and `cmd/bbox-helper` into `bin/`.
- [ ] Keep image name and tag overridable via Make variables.

### Task 2: Add the agent-ready container image

- [ ] Create a multi-stage `Dockerfile`.
- [ ] Install Bubblewrap, Go, `golangci-lint`, seccomp build deps, and common shell/debugging tools in the runtime image.
- [ ] Put `bbox` and `bbox-helper` on `PATH`.
- [ ] Default the image to an interactive shell in `/workspace`.

### Task 3: Document Docker usage

- [ ] Add README instructions for `make build`, `make docker-build`, and interactive container usage.
- [ ] Add a proxy-mode example and a transparent-mode example.
- [ ] Document the container security options needed for Bubblewrap and note the low-port binding requirement in transparent mode.

### Task 4: Verify

- [ ] Run `make build`.
- [ ] Run `make lint` or the equivalent lint command from the image if the host lacks `golangci-lint`.
- [ ] Run `docker build` via the new target.
- [ ] Smoke-test the built image with at least one `bbox` invocation.
