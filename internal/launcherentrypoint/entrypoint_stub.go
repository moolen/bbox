//go:build !linux

package launcherentrypoint

import (
	"flag"
	"fmt"
	"os"
)

var execLauncherFromFD = func(fd int, argv, env []string) error {
	return fmt.Errorf("internal launcher is only supported on linux")
}

type launcherFlags struct {
	launcherFD int
}

func parseFlags(args []string) (launcherFlags, []string, error) {
	var parsed launcherFlags
	fs := flag.NewFlagSet("bbox-internal-launcher", flag.ContinueOnError)
	fs.IntVar(&parsed.launcherFD, "launcher-fd", 3, "file descriptor carrying the embedded launcher image")
	if err := fs.Parse(args); err != nil {
		return parsed, nil, err
	}
	if parsed.launcherFD < 0 {
		return parsed, nil, fmt.Errorf("launcher fd must be non-negative")
	}
	launcherArgv := fs.Args()
	if len(launcherArgv) == 0 {
		return parsed, nil, fmt.Errorf("launcher argv is required after --")
	}
	return parsed, launcherArgv, nil
}

func Run(args []string) error {
	parsed, launcherArgv, err := parseFlags(args)
	if err != nil {
		return err
	}
	return execLauncherFromFD(parsed.launcherFD, launcherArgv, os.Environ())
}
