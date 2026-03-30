// Package seccompnotify supervises sandbox network syscalls with seccomp
// user notifications.
//
// The runtime only actively manages two classes of traffic:
//   - TCP sockets, which are redirected into the helper's raw transparent
//     ingress so the helper can sniff plaintext HTTP versus TLS and apply
//     policy before forwarding.
//   - UDP DNS sockets targeting port 53, which are emulated across the helper
//     bridge so DNS can be forwarded to the host resolver path.
//
// Other AF_INET/AF_INET6 socket types are intentionally left unmanaged so they
// continue through the kernel's normal networking behavior instead of being
// rewritten by the helper.
package seccompnotify
