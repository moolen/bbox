// Package bbox exposes the stable host-side API for running processes inside
// unprivileged bubblewrap sandboxes and routing their egress through a
// host-side policy engine.
//
// A ProxyManager owns the shared host-side policy state and creates one
// long-lived helper per sandbox. Each Sandbox gets isolated filesystem, PID,
// and network namespaces, plus either a sandbox-local proxy endpoint or
// transparent TCP ingress with supervised DNS forwarding depending on
// SandboxOptions.TrafficMode.
//
// The public package stays intentionally thin. Sandbox root assembly, helper
// control, helper runtime internals, and optional docker-build entrypoints live
// behind internal packages so the exported API can remain focused on manager
// construction and sandbox lifecycle.
package bbox
