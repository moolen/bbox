package bbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNormalizeSeccompOptionsDefaultsToBaseline(t *testing.T) {
	normalized := normalizeSeccompOptions(SeccompOptions{})

	if normalized.disabled {
		t.Fatal("expected seccomp to be enabled by default")
	}
	if normalized.profile != SeccompProfileBaseline {
		t.Fatalf("expected baseline profile by default, got %q", normalized.profile)
	}
}

func TestValidateSandboxOptionsRejectsUnknownSeccompProfile(t *testing.T) {
	opts := SandboxOptions{
		Seccomp: SeccompOptions{
			Profile: SeccompProfile("unknown"),
		},
	}

	if err := validateSandboxOptions(opts, true); err == nil {
		t.Fatal("expected unknown seccomp profile to fail validation")
	}
}

func TestSeccompProfileRulesIncludeExpectedBuiltins(t *testing.T) {
	baseline := seccompProfileRules(SeccompProfileBaseline)
	if !containsSeccompRule(baseline, "ioctl") {
		t.Fatal("expected baseline profile to deny TIOCSTI ioctl")
	}
	if !containsSeccompConditionalRule(baseline, "clone") {
		t.Fatal("expected baseline profile to guard namespace clone flags")
	}
	if containsSeccompRule(baseline, "seccomp") {
		t.Fatal("expected baseline profile to keep runtime seccomp available")
	}
	for _, syscall := range []string{
		"ptrace",
		"process_vm_writev",
		"pidfd_getfd",
		"kcmp",
	} {
		if !containsSeccompRule(baseline, syscall) {
			t.Fatalf("expected baseline profile to deny %s", syscall)
		}
	}

	restricted := seccompProfileRules(SeccompProfileRestricted)
	if !containsSeccompRule(restricted, "seccomp") {
		t.Fatal("expected restricted profile to deny the seccomp syscall")
	}
	if !containsSeccompRule(restricted, "process_vm_readv") {
		t.Fatal("expected restricted profile to deny process_vm_readv")
	}
	if !containsSeccompConditionalRule(restricted, "prctl") {
		t.Fatal("expected restricted profile to deny PR_SET_SECCOMP")
	}
}

func TestCompileSeccompFilterExportsBPF(t *testing.T) {
	program, err := compileSeccompProgram(SeccompOptions{})
	if err != nil {
		t.Fatalf("compileSeccompProgram failed: %v", err)
	}
	if len(program) == 0 {
		t.Fatal("expected exported BPF program")
	}
}

func TestCompileSeccompFilterRejectsUnknownUserSyscall(t *testing.T) {
	_, err := compileSeccompProgram(SeccompOptions{
		Profile: SeccompProfileCustom,
		Rules: []SeccompRule{
			{Syscall: "definitely_not_a_real_syscall"},
		},
	})
	if err == nil {
		t.Fatal("expected invalid user syscall to fail")
	}
}

func TestDefaultSeccompHelpers(t *testing.T) {
	rule := DenySyscall("mount")
	if rule.Syscall != "mount" {
		t.Fatalf("unexpected syscall: got %q", rule.Syscall)
	}
	if rule.Action != SeccompActionErrno {
		t.Fatalf("unexpected action: got %q", rule.Action)
	}
	if rule.Errno != int(unix.EPERM) {
		t.Fatalf("unexpected errno: got %d", rule.Errno)
	}
}

func containsSeccompRule(rules []seccompRuleSpec, syscall string) bool {
	for _, rule := range rules {
		if rule.rule.Syscall == syscall {
			return true
		}
	}
	return false
}

func containsSeccompConditionalRule(rules []seccompRuleSpec, syscall string) bool {
	for _, rule := range rules {
		if rule.rule.Syscall == syscall && len(rule.rule.Conditions) > 0 {
			return true
		}
	}
	return false
}
