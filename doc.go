// Package bbox runs processes inside unprivileged bubblewrap sandboxes and
// routes their egress through a host-side policy engine.
//
// A ProxyManager owns the shared host-side policy state and creates one
// long-lived helper per sandbox. Each Sandbox gets isolated filesystem, PID,
// and network namespaces, plus either a sandbox-local proxy endpoint or
// transparent TCP ingress with supervised DNS forwarding depending on
// SandboxOptions.TrafficMode.
package bbox
