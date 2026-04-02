package bbox

import (
	"context"
	"os"
	"reflect"
	"testing"
)

type fakeSandboxRuntime struct {
	runResult  *RunResult
	runErr     error
	proxyAddr  string
	closeErr   error
	runCalls   int
	closeCalls int
	lastCtx    context.Context
	lastArgv   []string
	lastOpts   RunOptions
}

func (r *fakeSandboxRuntime) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	r.runCalls++
	r.lastCtx = ctx
	r.lastArgv = append([]string(nil), argv...)
	r.lastOpts = opts
	return r.runResult, r.runErr
}

func (r *fakeSandboxRuntime) Close() error {
	r.closeCalls++
	return r.closeErr
}

func (r *fakeSandboxRuntime) ProxyAddr() string {
	return r.proxyAddr
}

func TestSandboxRunDelegatesToRuntime(t *testing.T) {
	runtime := &fakeSandboxRuntime{
		runResult: &RunResult{ExitCode: 7, Stdout: []byte("ok")},
	}
	ctx := context.WithValue(context.Background(), struct{}{}, "value")
	sandbox := &Sandbox{
		runtime:   runtime,
		baseEnv:   []string{"BASE=1", "PATH=/base/bin"},
		workDir:   "/workspace",
		proxyAddr: "127.0.0.1:40123",
	}

	result, err := sandbox.Run(ctx, []string{"echo", "hi"}, RunOptions{
		Env:     []string{"PATH=/custom/bin", "EXTRA=1"},
		WorkDir: "",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result != runtime.runResult {
		t.Fatalf("Run() result = %#v, want %#v", result, runtime.runResult)
	}
	if runtime.runCalls != 1 {
		t.Fatalf("runtime Run() calls = %d, want 1", runtime.runCalls)
	}
	if runtime.lastCtx != ctx {
		t.Fatal("runtime Run() received unexpected context")
	}
	if !reflect.DeepEqual(runtime.lastArgv, []string{"echo", "hi"}) {
		t.Fatalf("runtime Run() argv = %#v", runtime.lastArgv)
	}

	wantOpts := RunOptions{
		Env:         []string{"BASE=1", "PATH=/custom/bin", "EXTRA=1"},
		WorkDir:     "/workspace",
		Interactive: false,
	}
	if !reflect.DeepEqual(runtime.lastOpts, wantOpts) {
		t.Fatalf("runtime Run() opts = %#v, want %#v", runtime.lastOpts, wantOpts)
	}
}

func TestSandboxCloseDelegatesToRuntimeAndUnregistersOnce(t *testing.T) {
	manager := newProxyManager(nil)
	root := t.TempDir()
	runtime := &fakeSandboxRuntime{}
	sandbox := &Sandbox{
		manager:    manager,
		id:         "sandbox-a",
		root:       root,
		runtime:    runtime,
		registered: true,
	}

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("registerSandbox() error = %v", err)
	}
	if err := manager.attachSandbox("sandbox-a", sandbox); err != nil {
		t.Fatalf("attachSandbox() error = %v", err)
	}

	if err := sandbox.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if runtime.closeCalls != 1 {
		t.Fatalf("runtime Close() calls = %d, want 1", runtime.closeCalls)
	}
	if _, ok := manager.policyForSandbox("sandbox-a"); ok {
		t.Fatal("sandbox policy remained registered after Close()")
	}
	if _, ok := manager.registry.Sandbox("sandbox-a"); ok {
		t.Fatal("sandbox remained attached after Close()")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("sandbox root still exists after Close(): err = %v", err)
	}

	if err := sandbox.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if runtime.closeCalls != 1 {
		t.Fatalf("runtime Close() calls after second close = %d, want 1", runtime.closeCalls)
	}
}
