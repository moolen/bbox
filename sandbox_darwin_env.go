package bbox

import "strings"

func sanitizeDarwinEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := splitEnv(entry)
		if !ok {
			continue
		}
		if strings.HasPrefix(key, "DYLD_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
