package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

type cliOptions struct {
	configPath          string
	name                string
	workDir             string
	binaries            []string
	mounts              []string
	env                 []string
	clearEnv            bool
	clearEnvSet         bool
	trafficMode         string
	policyMode          string
	maxRequestBodyBytes int64
	maxBodySizeSet      bool
	printPolicy         bool
	reportPolicy        bool
	reportAccess        bool
	reportRequests      bool
	accessLog           string
	flagOverrides       cliFlagOverrides
}

type commandDeps struct {
	stdout  io.Writer
	stderr  io.Writer
	getwd   func() (string, error)
	environ func() []string
	run     func(runConfig) error
}

func newRootCommand(deps commandDeps) *cobra.Command {
	if deps.stdout == nil {
		deps.stdout = io.Discard
	}
	if deps.stderr == nil {
		deps.stderr = io.Discard
	}
	if deps.getwd == nil {
		deps.getwd = os.Getwd
	}
	if deps.environ == nil {
		deps.environ = os.Environ
	}
	if deps.run == nil {
		deps.run = runSandbox
	}

	var opts cliOptions

	cmd := &cobra.Command{
		Use:           "bbox [flags] -- command [args...]",
		Short:         "Run a command inside a bbox sandbox",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeRootCommand(cmd, args, deps, opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.configPath, "config", "", "path to bbox config file")
	flags.StringVar(&opts.name, "name", "", "sandbox name")
	flags.StringVar(&opts.workDir, "workdir", "", "working directory inside the sandbox")
	flags.StringArrayVar(&opts.binaries, "bin", nil, "extra binary to stage into the sandbox")
	flags.StringArrayVar(&opts.mounts, "mount", nil, "mount spec in key=value form")
	flags.StringArrayVar(&opts.env, "env", nil, "environment entry in KEY=VALUE form")
	flags.BoolVar(&opts.clearEnv, "clear-env", false, "do not inherit the host environment")
	flags.StringVar(&opts.trafficMode, "traffic-mode", "proxy", "traffic mode: proxy or transparent")
	flags.StringVar(&opts.policyMode, "policy-mode", "enforce", "policy mode: enforce or audit")
	flags.Int64Var(&opts.maxRequestBodyBytes, "max-request-body-bytes", 64<<10, "maximum request body inspection size for MITM")
	flags.BoolVar(&opts.printPolicy, "print-policy", false, "print the effective policy before execution")

	flags.BoolVar(&opts.reportPolicy, "report-policy-violations", true, "render a policy-violations summary after execution")
	flags.BoolVar(&opts.reportAccess, "report-access-summary", true, "render a host access summary after execution")
	flags.BoolVar(&opts.reportRequests, "report-request-summary", true, "render a request summary after execution")
	flags.StringVar(&opts.accessLog, "access-log", "json", "access log mode: json or off")

	return cmd
}
