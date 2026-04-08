//go:build !linux

package bbox

import (
	"context"
	"fmt"
)

func (m *ProxyManager) newLinuxSandboxRuntime(_ context.Context, _ string, _ SandboxOptions, _ TrafficMode, _ *dockerSocketMount) (*sandboxRuntimeBootstrap, error) {
	return nil, fmt.Errorf("linux sandbox runtime is not supported on %s", sandboxPlatform)
}
