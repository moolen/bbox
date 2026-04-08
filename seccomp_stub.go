//go:build !linux

package bbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type SeccompProfile string

const (
	SeccompProfileBaseline   SeccompProfile = "baseline"
	SeccompProfileRestricted SeccompProfile = "restricted"
	SeccompProfileCustom     SeccompProfile = "custom"
)

type SeccompAction string

const (
	SeccompActionErrno       SeccompAction = "errno"
	SeccompActionTrap        SeccompAction = "trap"
	SeccompActionKillProcess SeccompAction = "kill-process"
)

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

type SeccompCondition struct {
	Argument  uint
	Operation SeccompCompareOp
	Value     uint64
	Mask      uint64
}

type SeccompRule struct {
	Syscall    string
	Action     SeccompAction
	Errno      int
	Conditions []SeccompCondition
}

type SeccompOptions struct {
	Disabled bool
	Profile  SeccompProfile
	Rules    []SeccompRule
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
	if !opts.DockerBuild.Enabled {
		return opts.Seccomp
	}
	if opts.Seccomp.Disabled || opts.Seccomp.Profile != "" || len(opts.Seccomp.Rules) > 0 {
		return opts.Seccomp
	}
	return SeccompOptions{Disabled: true}
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

func DenySyscall(syscall string) SeccompRule {
	return SeccompRule{
		Syscall: syscall,
		Action:  SeccompActionErrno,
		Errno:   1,
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
	return nil
}

func compileSeccompProgram(opts SeccompOptions) ([]byte, error) {
	if err := validateSeccompOptions(opts); err != nil {
		return nil, err
	}
	if isZeroSeccompOptions(opts) {
		return nil, nil
	}
	return nil, errors.New("seccomp is only supported on linux")
}

func prepareSeccompProgram(opts SeccompOptions) (*preparedSeccompProgram, error) {
	if _, err := compileSeccompProgram(opts); err != nil {
		return nil, err
	}
	return nil, nil
}

func writeSeccompProgram(_ io.Writer, opts SeccompOptions) error {
	if _, err := compileSeccompProgram(opts); err != nil {
		return err
	}
	return nil
}
