//go:build linux

package bbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// SeccompProfile selects a built-in seccomp hardening preset.
type SeccompProfile string

const (
	// SeccompProfileBaseline keeps common workloads working while blocking
	// namespace mutation, mount reconfiguration, TIOCSTI terminal injection,
	// and uncommon privileged kernel attack surfaces.
	SeccompProfileBaseline SeccompProfile = "baseline"
	// SeccompProfileRestricted extends the baseline profile with stricter
	// process-inspection limits and blocks in-sandbox seccomp installation.
	SeccompProfileRestricted SeccompProfile = "restricted"
	// SeccompProfileCustom applies only user-supplied rules.
	SeccompProfileCustom SeccompProfile = "custom"
)

// SeccompAction controls what happens when a rule matches.
type SeccompAction string

const (
	// SeccompActionErrno makes the syscall fail with the configured errno.
	SeccompActionErrno SeccompAction = "errno"
	// SeccompActionTrap raises SIGSYS in the sandboxed process.
	SeccompActionTrap SeccompAction = "trap"
	// SeccompActionKillProcess terminates the entire process.
	SeccompActionKillProcess SeccompAction = "kill-process"
)

// SeccompCompareOp controls how a syscall argument is matched.
type SeccompCompareOp string

const (
	SeccompCompareNotEqual       SeccompCompareOp = "ne"
	SeccompCompareLessThan       SeccompCompareOp = "lt"
	SeccompCompareLessOrEqual    SeccompCompareOp = "le"
	SeccompCompareEqual          SeccompCompareOp = "eq"
	SeccompCompareGreaterOrEqual SeccompCompareOp = "ge"
	SeccompCompareGreaterThan    SeccompCompareOp = "gt"
	SeccompCompareMaskedEqual    SeccompCompareOp = "masked-eq"
)

// SeccompCondition constrains one syscall argument.
type SeccompCondition struct {
	// Argument is the zero-based syscall argument index (0-5).
	Argument uint
	// Operation controls how Value is compared.
	Operation SeccompCompareOp
	// Value is the comparison value, or the masked value for masked-eq.
	Value uint64
	// Mask is used only for masked-eq comparisons.
	Mask uint64
}

// SeccompRule describes one user-supplied seccomp rule.
type SeccompRule struct {
	// Syscall is the Linux syscall name as understood by libseccomp.
	Syscall string
	// Action defaults to errno when empty.
	Action SeccompAction
	// Errno is returned when Action is errno. It defaults to EPERM.
	Errno int
	// Conditions optionally constrain specific syscall arguments.
	Conditions []SeccompCondition
}

// SeccompOptions configures per-sandbox seccomp hardening.
type SeccompOptions struct {
	// Disabled turns seccomp off for this sandbox. The zero value keeps
	// seccomp enabled with the baseline profile.
	Disabled bool
	// Profile selects a built-in rule set. Empty defaults to baseline.
	Profile SeccompProfile
	// Rules adds extra rules after the selected built-in profile. Use the
	// custom profile to start from an empty built-in rule set.
	Rules []SeccompRule
}

type normalizedSeccompOptions struct {
	disabled bool
	profile  SeccompProfile
	rules    []SeccompRule
}

type seccompRuleSpec struct {
	rule     SeccompRule
	optional bool
}

type preparedSeccompProgram struct {
	file    *os.File
	cleanup func() error
}

func effectiveSeccompOptions(opts SandboxOptions) SeccompOptions {
	return opts.Seccomp
}

func (p *preparedSeccompProgram) Close() error {
	if p == nil {
		return nil
	}

	var err error
	if p.file != nil {
		err = p.file.Close()
	}
	if p.cleanup != nil {
		err = errors.Join(err, p.cleanup())
	}
	return err
}

// DenySyscall returns a rule that fails the syscall with EPERM.
func DenySyscall(syscall string) SeccompRule {
	return SeccompRule{
		Syscall: syscall,
		Action:  SeccompActionErrno,
		Errno:   int(unix.EPERM),
	}
}

func normalizeSeccompOptions(opts SeccompOptions) normalizedSeccompOptions {
	normalized := normalizedSeccompOptions{
		disabled: opts.Disabled,
		profile:  opts.Profile,
		rules:    append([]SeccompRule(nil), opts.Rules...),
	}
	if normalized.disabled {
		return normalized
	}
	if normalized.profile == "" {
		normalized.profile = SeccompProfileBaseline
	}
	return normalized
}

func validateSeccompOptions(opts SeccompOptions) error {
	normalized := normalizeSeccompOptions(opts)
	if normalized.disabled {
		return nil
	}

	switch normalized.profile {
	case SeccompProfileBaseline, SeccompProfileRestricted, SeccompProfileCustom:
	default:
		return fmt.Errorf("sandbox seccomp profile %q is not supported", opts.Profile)
	}

	for _, rule := range normalized.rules {
		if err := validateSeccompRule(rule); err != nil {
			return err
		}
	}

	return nil
}

func validateSeccompRule(rule SeccompRule) error {
	if strings.TrimSpace(rule.Syscall) == "" {
		return errors.New("sandbox seccomp rule syscall is required")
	}

	switch normalizeSeccompAction(rule.Action) {
	case SeccompActionErrno, SeccompActionTrap, SeccompActionKillProcess:
	default:
		return fmt.Errorf("sandbox seccomp action %q is not supported", rule.Action)
	}

	if normalizeSeccompAction(rule.Action) != SeccompActionErrno && rule.Errno != 0 {
		return fmt.Errorf("sandbox seccomp rule for %q sets errno without errno action", rule.Syscall)
	}
	if rule.Errno < 0 || rule.Errno > 0x7fff {
		return fmt.Errorf("sandbox seccomp errno for %q must be between 0 and 32767", rule.Syscall)
	}

	for _, condition := range rule.Conditions {
		if condition.Argument > 5 {
			return fmt.Errorf("sandbox seccomp rule for %q uses invalid argument index %d", rule.Syscall, condition.Argument)
		}
		switch normalizeSeccompCompareOp(condition.Operation) {
		case SeccompCompareNotEqual,
			SeccompCompareLessThan,
			SeccompCompareLessOrEqual,
			SeccompCompareEqual,
			SeccompCompareGreaterOrEqual,
			SeccompCompareGreaterThan,
			SeccompCompareMaskedEqual:
		default:
			return fmt.Errorf("sandbox seccomp compare op %q is not supported", condition.Operation)
		}
		if normalizeSeccompCompareOp(condition.Operation) == SeccompCompareMaskedEqual && condition.Mask == 0 {
			return fmt.Errorf("sandbox seccomp masked-eq rule for %q requires a non-zero mask", rule.Syscall)
		}
	}

	return nil
}

func normalizeSeccompAction(action SeccompAction) SeccompAction {
	if strings.TrimSpace(string(action)) == "" {
		return SeccompActionErrno
	}
	return SeccompAction(strings.ToLower(strings.TrimSpace(string(action))))
}

func normalizeSeccompCompareOp(op SeccompCompareOp) SeccompCompareOp {
	return SeccompCompareOp(strings.ToLower(strings.TrimSpace(string(op))))
}

func seccompProfileRules(profile SeccompProfile) []seccompRuleSpec {
	switch profile {
	case SeccompProfileBaseline:
		return append([]seccompRuleSpec(nil), baselineSeccompRuleSpecs...)
	case SeccompProfileRestricted:
		rules := append([]seccompRuleSpec(nil), baselineSeccompRuleSpecs...)
		rules = append(rules, restrictedSeccompRuleSpecs...)
		return rules
	case SeccompProfileCustom:
		return nil
	default:
		return nil
	}
}

func compileSeccompProgram(opts SeccompOptions) ([]byte, error) {
	program, err := prepareSeccompProgram(opts)
	if err != nil {
		return nil, err
	}
	if program == nil {
		return nil, nil
	}
	defer program.Close()

	if _, err := program.file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("rewind seccomp program: %w", err)
	}

	programBytes, err := io.ReadAll(program.file)
	if err != nil {
		return nil, fmt.Errorf("read seccomp program: %w", err)
	}
	return programBytes, nil
}

func prepareSeccompProgram(opts SeccompOptions) (*preparedSeccompProgram, error) {
	normalized := normalizeSeccompOptions(opts)
	if normalized.disabled {
		return nil, nil
	}
	if err := validateSeccompOptions(opts); err != nil {
		return nil, err
	}

	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("create seccomp filter: %w", err)
	}
	defer filter.Release()

	for _, spec := range seccompProfileRules(normalized.profile) {
		if err := addSeccompRule(filter, spec); err != nil {
			return nil, err
		}
	}
	for _, rule := range normalized.rules {
		if err := addSeccompRule(filter, seccompRuleSpec{rule: rule}); err != nil {
			return nil, err
		}
	}

	file, cleanup, err := newSeccompProgramFile()
	if err != nil {
		return nil, err
	}
	if err := filter.ExportBPF(file); err != nil {
		_ = file.Close()
		_ = cleanup()
		return nil, fmt.Errorf("export seccomp program: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		_ = cleanup()
		return nil, fmt.Errorf("rewind seccomp program: %w", err)
	}

	return &preparedSeccompProgram{
		file:    file,
		cleanup: cleanup,
	}, nil
}

func addSeccompRule(filter *seccomp.ScmpFilter, spec seccompRuleSpec) error {
	call, err := seccomp.GetSyscallFromName(strings.TrimSpace(spec.rule.Syscall))
	if err != nil {
		if spec.optional {
			return nil
		}
		return fmt.Errorf("resolve seccomp syscall %q: %w", spec.rule.Syscall, err)
	}

	action, err := seccompActionForRule(spec.rule)
	if err != nil {
		return err
	}
	conditions, err := seccompConditionsForRule(spec.rule)
	if err != nil {
		return err
	}

	if len(conditions) == 0 {
		if err := filter.AddRule(call, action); err != nil {
			return fmt.Errorf("add seccomp rule for %q: %w", spec.rule.Syscall, err)
		}
		return nil
	}
	if err := filter.AddRuleConditional(call, action, conditions); err != nil {
		return fmt.Errorf("add seccomp conditional rule for %q: %w", spec.rule.Syscall, err)
	}
	return nil
}

func seccompActionForRule(rule SeccompRule) (seccomp.ScmpAction, error) {
	switch normalizeSeccompAction(rule.Action) {
	case SeccompActionErrno:
		errno := rule.Errno
		if errno == 0 {
			errno = int(unix.EPERM)
		}
		return seccomp.ActErrno.SetReturnCode(int16(errno)), nil
	case SeccompActionTrap:
		return seccomp.ActTrap, nil
	case SeccompActionKillProcess:
		return seccomp.ActKillProcess, nil
	default:
		return seccomp.ActInvalid, fmt.Errorf("sandbox seccomp action %q is not supported", rule.Action)
	}
}

func seccompConditionsForRule(rule SeccompRule) ([]seccomp.ScmpCondition, error) {
	if len(rule.Conditions) == 0 {
		return nil, nil
	}

	conditions := make([]seccomp.ScmpCondition, 0, len(rule.Conditions))
	for _, condition := range rule.Conditions {
		op, err := seccompCompareOpForCondition(condition.Operation)
		if err != nil {
			return nil, err
		}

		var compiled seccomp.ScmpCondition
		if op == seccomp.CompareMaskedEqual {
			compiled, err = seccomp.MakeCondition(condition.Argument, op, condition.Mask, condition.Value)
		} else {
			compiled, err = seccomp.MakeCondition(condition.Argument, op, condition.Value)
		}
		if err != nil {
			return nil, fmt.Errorf("build seccomp condition for %q: %w", rule.Syscall, err)
		}
		conditions = append(conditions, compiled)
	}
	return conditions, nil
}

func seccompCompareOpForCondition(op SeccompCompareOp) (seccomp.ScmpCompareOp, error) {
	switch normalizeSeccompCompareOp(op) {
	case SeccompCompareNotEqual:
		return seccomp.CompareNotEqual, nil
	case SeccompCompareLessThan:
		return seccomp.CompareLess, nil
	case SeccompCompareLessOrEqual:
		return seccomp.CompareLessOrEqual, nil
	case SeccompCompareEqual:
		return seccomp.CompareEqual, nil
	case SeccompCompareGreaterOrEqual:
		return seccomp.CompareGreaterEqual, nil
	case SeccompCompareGreaterThan:
		return seccomp.CompareGreater, nil
	case SeccompCompareMaskedEqual:
		return seccomp.CompareMaskedEqual, nil
	default:
		return seccomp.CompareInvalid, fmt.Errorf("sandbox seccomp compare op %q is not supported", op)
	}
}

func newSeccompProgramFile() (*os.File, func() error, error) {
	fd, err := unix.MemfdCreate("bbox-seccomp", unix.MFD_CLOEXEC)
	if err == nil {
		file := os.NewFile(uintptr(fd), "bbox-seccomp")
		if file == nil {
			_ = unix.Close(fd)
			return nil, nil, errors.New("create seccomp memfd handle")
		}
		return file, func() error { return nil }, nil
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
		return nil, nil, fmt.Errorf("create seccomp memfd: %w", err)
	}

	file, err := os.CreateTemp("", "bbox-seccomp-*.bpf")
	if err != nil {
		return nil, nil, fmt.Errorf("create seccomp temp file: %w", err)
	}
	path := file.Name()
	return file, func() error { return os.Remove(path) }, nil
}

var baselineSeccompRuleSpecs = func() []seccompRuleSpec {
	rules := []seccompRuleSpec{
		{rule: SeccompRule{
			Syscall: "ioctl",
			Conditions: []SeccompCondition{
				{
					Argument:  1,
					Operation: SeccompCompareEqual,
					Value:     uint64(unix.TIOCSTI),
				},
			},
		}},
		denyRequiredSyscall("mount"),
		denyRequiredSyscall("umount2"),
		denyRequiredSyscall("pivot_root"),
		denyRequiredSyscall("unshare"),
		denyRequiredSyscall("setns"),
		denyRequiredSyscall("bpf"),
		denyRequiredSyscall("ioperm"),
		denyRequiredSyscall("iopl"),
		denyRequiredSyscall("reboot"),
		denyRequiredSyscall("swapon"),
		denyRequiredSyscall("swapoff"),
		denyRequiredSyscall("syslog"),
		denyRequiredSyscall("add_key"),
		denyRequiredSyscall("request_key"),
		denyRequiredSyscall("keyctl"),
		denyOptionalSyscall("open_by_handle_at"),
		denyOptionalSyscall("name_to_handle_at"),
		denyOptionalSyscall("move_mount"),
		denyOptionalSyscall("open_tree"),
		denyOptionalSyscall("fsopen"),
		denyOptionalSyscall("fsconfig"),
		denyOptionalSyscall("fsmount"),
		denyOptionalSyscall("fspick"),
		denyOptionalSyscall("mount_setattr"),
		denyOptionalSyscall("perf_event_open"),
		denyOptionalSyscall("userfaultfd"),
		denyOptionalSyscall("fanotify_init"),
		denyOptionalSyscall("init_module"),
		denyOptionalSyscall("finit_module"),
		denyOptionalSyscall("delete_module"),
		denyOptionalSyscall("kexec_load"),
		denyOptionalSyscall("kexec_file_load"),
		denyRequiredSyscall("ptrace"),
		denyOptionalSyscall("process_vm_writev"),
		denyOptionalSyscall("kcmp"),
		denyOptionalSyscall("pidfd_getfd"),
		// Return ENOSYS so libc and other runtimes can fall back to clone(2),
		// where we can still block namespace creation by flag.
		denyOptionalSyscallErrno("clone3", int(unix.ENOSYS)),
	}

	namespaceCloneFlags := []uint64{
		uint64(unix.CLONE_NEWCGROUP),
		uint64(unix.CLONE_NEWIPC),
		uint64(unix.CLONE_NEWNET),
		uint64(unix.CLONE_NEWNS),
		uint64(unix.CLONE_NEWPID),
		uint64(unix.CLONE_NEWTIME),
		uint64(unix.CLONE_NEWUSER),
		uint64(unix.CLONE_NEWUTS),
	}
	for _, flag := range namespaceCloneFlags {
		rules = append(rules, seccompRuleSpec{
			rule: SeccompRule{
				Syscall: "clone",
				Conditions: []SeccompCondition{
					{
						Argument:  0,
						Operation: SeccompCompareMaskedEqual,
						Mask:      flag,
						Value:     flag,
					},
				},
			},
		})
	}

	return rules
}()

var restrictedSeccompRuleSpecs = []seccompRuleSpec{
	denyRequiredSyscall("seccomp"),
	denyOptionalSyscall("process_vm_readv"),
	{rule: SeccompRule{
		Syscall: "prctl",
		Conditions: []SeccompCondition{
			{
				Argument:  0,
				Operation: SeccompCompareEqual,
				Value:     uint64(unix.PR_SET_SECCOMP),
			},
		},
	}},
}

func denyRequiredSyscall(name string) seccompRuleSpec {
	return seccompRuleSpec{rule: DenySyscall(name)}
}

func denyOptionalSyscall(name string) seccompRuleSpec {
	return seccompRuleSpec{rule: DenySyscall(name), optional: true}
}

func denyOptionalSyscallErrno(name string, errno int) seccompRuleSpec {
	return seccompRuleSpec{
		rule: SeccompRule{
			Syscall: name,
			Action:  SeccompActionErrno,
			Errno:   errno,
		},
		optional: true,
	}
}
