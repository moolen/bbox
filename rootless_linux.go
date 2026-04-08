//go:build linux

package bbox

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/moolen/bbox/internal/sandboxroot"
)

const defaultBuilderCgroupPath = "/sys/fs/cgroup"

type bwrapCommandConfig struct {
	runtimeBinary      string
	root               string
	proxyListenAddr    string
	mitm               MITMOptions
	opts               SandboxOptions
	builder            *sandboxroot.BuilderTooling
	mode               TrafficMode
	payloadSeccompPath string
	bridgeFD           int
	seccompFD          int
	extraFiles         []*os.File
	dockerSocketMount  *dockerSocketMount
	maxRequestBody     int64
}

func buildLinuxSandboxCommand(cfg bwrapCommandConfig) (*exec.Cmd, error) {
	tooling := cfg.builder
	if tooling == nil {
		var err error
		tooling, err = sandboxroot.ResolveDockerBuildSupport(toSandboxrootDockerBuildOptions(cfg.opts.DockerBuild))
		if err != nil {
			return nil, err
		}
	}

	mounts := append([]Mount(nil), cfg.opts.Mounts...)
	if tooling != nil {
		mounts = appendBuilderMounts(mounts)
	}
	runtimeMounts, err := prepareRuntimeMounts(cfg.root, mounts)
	if err != nil {
		return nil, fmt.Errorf("prepare runtime mounts: %w", err)
	}

	bwrapArgs := buildBwrapArgs(bwrapArgsConfig{
		root:                  cfg.root,
		helperPath:            sandboxroot.DefaultSandboxBBoxPath,
		proxyListenAddr:       cfg.proxyListenAddr,
		mitm:                  cfg.mitm,
		unshareUser:           os.Geteuid() != 0 && tooling == nil,
		capSysAdmin:           tooling != nil,
		maxRequestBodyBytes:   cfg.maxRequestBody,
		mounts:                runtimeMounts,
		dockerSocketMount:     cfg.dockerSocketMount,
		trafficMode:           cfg.mode,
		payloadSeccompBPFPath: cfg.payloadSeccompPath,
		bridgeFD:              cfg.bridgeFD,
		seccompFD:             cfg.seccompFD,
	})

	var cmd *exec.Cmd
	if tooling != nil {
		args := append([]string{"unshare", "bwrap"}, bwrapArgs...)
		cmd = exec.Command(tooling.PodmanPath, args...)
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
		Type:     MountTypeBind,
		Source:   defaultBuilderCgroupPath,
		Target:   defaultBuilderCgroupPath,
		ReadOnly: true,
	})
}
