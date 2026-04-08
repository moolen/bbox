package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

type cliOptions struct {
	name                string
	workDir             string
	binaries            []string
	mountRO             []string
	mountRW             []string
	env                 []string
	clearEnv            bool
	clearEnvSet         bool
	trafficMode         string
	maxRequestBodyBytes int64
	maxBodySizeSet      bool
	printPolicy         bool
	reportPolicy        bool
	reportAccess        bool
	reportRequests      bool
	accessLog           string
	audit               bool
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
			if cmd.Flags().ArgsLenAtDash() < 0 || len(args) == 0 {
				return fmt.Errorf("payload command required after --")
			}

			cwd, err := deps.getwd()
			if err != nil {
				return fmt.Errorf("resolve current working directory: %w", err)
			}

			opts.flagOverrides = cliFlagOverrides{}
			if cmd.Flags().Changed("traffic-mode") {
				opts.flagOverrides.TrafficMode = &opts.trafficMode
			}
			if cmd.Flags().Changed("max-request-body-bytes") {
				opts.maxBodySizeSet = true
			}
			if cmd.Flags().Changed("clear-env") {
				opts.clearEnvSet = true
			}
			if cmd.Flags().Changed("report-policy-violations") {
				opts.flagOverrides.ReportPolicy = &opts.reportPolicy
			}
			if cmd.Flags().Changed("report-access-summary") {
				opts.flagOverrides.ReportAccessSummary = &opts.reportAccess
			}
			if cmd.Flags().Changed("report-request-summary") {
				opts.flagOverrides.ReportRequestSummary = &opts.reportRequests
			}
			if cmd.Flags().Changed("access-log") {
				opts.flagOverrides.AccessLog = &opts.accessLog
			}

			cfg, err := buildConfig(opts, args, cwd, deps.environ())
			if err != nil {
				return err
			}
			cfg.stdout = deps.stdout
			cfg.stderr = deps.stderr
			if cfg.printPolicy {
				if err := printPolicy(deps.stdout, cfg); err != nil {
					return err
				}
			}
			return deps.run(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.name, "name", "", "sandbox name")
	flags.StringVar(&opts.workDir, "workdir", "", "working directory inside the sandbox")
	flags.StringArrayVar(&opts.binaries, "bin", nil, "extra binary to stage into the sandbox")
	flags.StringArrayVar(&opts.mountRO, "mount-ro", nil, "read-only bind mount in src:dst form")
	flags.StringArrayVar(&opts.mountRW, "mount-rw", nil, "read-write bind mount in src:dst form")
	flags.StringArrayVar(&opts.env, "env", nil, "environment entry in KEY=VALUE form")
	flags.BoolVar(&opts.clearEnv, "clear-env", false, "do not inherit the host environment")
	flags.StringVar(&opts.trafficMode, "traffic-mode", "proxy", "traffic mode: proxy or transparent")
	flags.Int64Var(&opts.maxRequestBodyBytes, "max-request-body-bytes", 64<<10, "maximum request body inspection size for MITM")
	flags.BoolVar(&opts.printPolicy, "print-policy", false, "print the effective policy before execution")

	flags.BoolVar(&opts.reportPolicy, "report-policy-violations", true, "render a policy-violations summary after execution")
	flags.BoolVar(&opts.reportAccess, "report-access-summary", true, "render a host access summary after execution")
	flags.BoolVar(&opts.reportRequests, "report-request-summary", true, "render a request summary after execution")
	flags.StringVar(&opts.accessLog, "access-log", "json", "access log mode: json or off")
	flags.BoolVar(&opts.audit, "audit", false, "force audit reporting summaries on")

	return cmd
}
