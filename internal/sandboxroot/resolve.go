package sandboxroot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ResolveBinary(nameOrPath string) (string, error) {
	if nameOrPath == "" {
		return "", fmt.Errorf("binary path is required")
	}

	if strings.Contains(nameOrPath, string(filepath.Separator)) {
		absPath, err := filepath.Abs(nameOrPath)
		if err != nil {
			return "", fmt.Errorf("resolve absolute binary path %q: %w", nameOrPath, err)
		}
		if _, err := os.Stat(absPath); err != nil {
			return "", fmt.Errorf("binary %q: %w", absPath, err)
		}
		return absPath, nil
	}

	resolved, err := exec.LookPath(nameOrPath)
	if err != nil {
		return "", fmt.Errorf("resolve binary %q: %w", nameOrPath, err)
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve absolute binary path %q: %w", resolved, err)
	}
	return absPath, nil
}

func ParseLddOutput(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if parts := strings.SplitN(line, "=>", 2); len(parts) == 2 {
			path := strings.Fields(strings.TrimSpace(parts[1]))
			if len(path) > 0 && strings.HasPrefix(path[0], "/") {
				paths = append(paths, path[0])
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "/") {
			paths = append(paths, fields[0])
		}
	}
	return paths
}

func RuntimeFilesForBinary(binaryPath string) ([]string, error) {
	output, err := exec.Command("ldd", binaryPath).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "not a dynamic executable") {
			return nil, nil
		}
		return nil, fmt.Errorf("ldd %s: %w: %s", binaryPath, err, strings.TrimSpace(string(output)))
	}
	return ParseLddOutput(string(output)), nil
}

func FilesForCommand(commandPath string) ([]string, error) {
	return filesForCommandRecursive(commandPath, map[string]struct{}{})
}

func filesForCommandRecursive(commandPath string, seen map[string]struct{}) ([]string, error) {
	commandPath = filepath.Clean(commandPath)
	if _, ok := seen[commandPath]; ok {
		return nil, nil
	}
	seen[commandPath] = struct{}{}

	files := []string{commandPath}

	runtimeFiles, err := RuntimeFilesForBinary(commandPath)
	if err != nil {
		return nil, err
	}
	files = append(files, runtimeFiles...)

	interpreters, err := scriptInterpreterChain(commandPath)
	if err != nil {
		return nil, err
	}
	for _, interpreter := range interpreters {
		interpreterFiles, err := filesForCommandRecursive(interpreter, seen)
		if err != nil {
			return nil, err
		}
		files = append(files, interpreterFiles...)
	}

	return files, nil
}

func scriptInterpreterChain(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read potential script %q: %w", path, err)
	}

	line, _, _ := strings.Cut(string(content), "\n")
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return nil, nil
	}

	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return nil, fmt.Errorf("script %q has an empty shebang", path)
	}

	interpreter := fields[0]
	if !filepath.IsAbs(interpreter) {
		return nil, fmt.Errorf("script %q uses non-absolute shebang interpreter %q", path, interpreter)
	}

	chain := []string{interpreter}
	if filepath.Base(interpreter) == "env" {
		if target, ok := envShebangTarget(fields[1:]); ok {
			resolved, err := ResolveBinary(target)
			if err != nil {
				return nil, fmt.Errorf("resolve env shebang target %q for %q: %w", target, path, err)
			}
			chain = append(chain, resolved)
		}
	}

	return chain, nil
}

func envShebangTarget(args []string) (string, bool) {
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg, true
	}
	return "", false
}
