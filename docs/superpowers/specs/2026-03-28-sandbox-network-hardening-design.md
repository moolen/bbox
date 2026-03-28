# Sandbox Network Hardening Design

## Scope

Address three concrete security issues in the sandbox runtime:

1. Make the default seccomp profile stricter so payload processes cannot inspect or interfere with the long-lived helper process.
2. Bind transparent HTTPS authorization to the actual upstream authority instead of trusting the decrypted HTTP `Host` header alone.
3. Add bounded buffering for proxied request and response bodies so allowed traffic cannot trivially exhaust helper or manager memory.

## Design

### Default Seccomp Hardening

Move helper-inspection syscalls into the baseline profile:

- `ptrace`
- `process_vm_readv`
- `process_vm_writev`
- `pidfd_getfd`
- `kcmp`

This makes the secure default stricter and treats helper isolation as part of the default security boundary, not an opt-in hardening tier.

### Transparent HTTPS Authority Binding

Transparent HTTPS currently terminates TLS based on SNI and later evaluates policy on the decrypted request host. The fix is:

- carry the upstream authority chosen during TLS termination into host-side MITM policy evaluation
- validate that the decrypted request host is consistent with that authority
- deny requests when the decrypted host and the actual upstream authority disagree

This prevents clients from using one host for authorization and another for the real network connection.

### Body Size Limits

Introduce manager-wide request and response buffering limits with safe defaults. They apply to:

- proxy-mode request bodies buffered in the helper
- MITM request bodies buffered in the helper
- proxy and MITM response bodies buffered in the manager

When a limit is exceeded, the request should fail with a deterministic error instead of buffering unbounded data.

## Compatibility

- Some workloads that relied on `ptrace`-style inspection in the default seccomp profile will now fail unless seccomp is customized or disabled.
- Transparent HTTPS clients that send mismatched SNI and `Host` values will now be denied.
- Large uploads/downloads that previously worked by consuming arbitrary memory will now fail once they exceed configured limits.
