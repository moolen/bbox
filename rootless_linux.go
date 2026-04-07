//go:build linux

package bbox

import (
	"os"
	"os/exec"
)

const defaultBuilderCgroupPath = "/sys/fs/cgroup"

type bwrapCommandConfig struct {
	runtimeBinary      string
	root               string
	proxyListenAddr    string
	mitm               MITMOptions
	opts               SandboxOptions
	mode               TrafficMode
	payloadSeccompPath string
	bridgeFD           int
	seccompFD          int
	extraFiles         []*os.File
	dockerSocketMount  *dockerSocketMount
	maxRequestBody     int64
}

func buildLinuxSandboxCommand(cfg bwrapCommandConfig) (*exec.Cmd, error) {
	tooling, err := resolveDockerBuildSupport(cfg.opts.DockerBuild)
	if err != nil {
		return nil, err
	}

	mounts := append([]Mount(nil), cfg.opts.Mounts...)
	if tooling != nil {
		mounts = appendBuilderMounts(mounts)
	}

	bwrapArgs := buildBwrapArgs(bwrapArgsConfig{
		root:                  cfg.root,
		helperPath:            defaultSandboxBBoxPath,
		proxyListenAddr:       cfg.proxyListenAddr,
		mitm:                  cfg.mitm,
		unshareUser:           os.Geteuid() != 0 && tooling == nil,
		capSysAdmin:           tooling != nil,
		maxRequestBodyBytes:   cfg.maxRequestBody,
		mounts:                mounts,
		dockerSocketMount:     cfg.dockerSocketMount,
		trafficMode:           cfg.mode,
		payloadSeccompBPFPath: cfg.payloadSeccompPath,
		bridgeFD:              cfg.bridgeFD,
		seccompFD:             cfg.seccompFD,
	})

	var cmd *exec.Cmd
	if tooling != nil {
		args := append([]string{"unshare", "bwrap"}, bwrapArgs...)
		cmd = exec.Command(tooling.podmanPath, args...)
	} else {
		cmd = exec.Command("bwrap", bwrapArgs...)
	}
	cmd.ExtraFiles = cfg.extraFiles
	return cmd, nil
}

func appendBuilderMounts(mounts []Mount) []Mount {
	info, err := os.Stat(defaultBuilderCgroupPath)
	if err != nil || !info.IsDir() {
		return mounts
	}
	for _, mount := range mounts {
		if targetsOverlap(mount.Target, defaultBuilderCgroupPath) {
			return mounts
		}
	}
	return append(mounts, Mount{
		Source:   defaultBuilderCgroupPath,
		Target:   defaultBuilderCgroupPath,
		ReadOnly: true,
	})
}
