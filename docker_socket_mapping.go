package bbox

import (
	"regexp"
	"strings"
)

var dockerAPIVersionPrefixRe = regexp.MustCompile(`^/v[0-9]+(?:\.[0-9]+)?(?:/|$)`)

type dockerRequestMeta struct {
	Method    string
	Path      string
	Operation DockerOperation
}

func normalizeDockerAPIPath(path string) string {
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		return "/"
	}
	if idx := strings.Index(normalized, "?"); idx >= 0 {
		normalized = normalized[:idx]
	}
	if normalized == "" {
		return "/"
	}
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}

	normalized = dockerAPIVersionPrefixRe.ReplaceAllString(normalized, "/")
	if normalized == "" {
		return "/"
	}
	return normalized
}

func mapDockerRequest(method, path string) dockerRequestMeta {
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	normalizedPath := normalizeDockerAPIPath(path)

	meta := dockerRequestMeta{
		Method:    normalizedMethod,
		Path:      normalizedPath,
		Operation: DockerOperation("unknown"),
	}

	switch {
	case normalizedMethod == "POST" && normalizedPath == "/images/create":
		meta.Operation = DockerOperation("image_pull")
	case normalizedMethod == "GET" &&
		strings.HasPrefix(normalizedPath, "/images/") &&
		strings.HasSuffix(normalizedPath, "/json") &&
		pathSegmentCount(normalizedPath) >= 3:
		meta.Operation = DockerOperation("image_inspect")
	case normalizedMethod == "POST" && normalizedPath == "/build":
		meta.Operation = DockerOperation("build")
	case normalizedMethod == "POST" && matchPathPattern(normalizedPath, "/containers/*/exec"):
		meta.Operation = DockerOperation("exec_create")
	case normalizedMethod == "POST" && matchPathPattern(normalizedPath, "/exec/*/start"):
		meta.Operation = DockerOperation("exec_start")
	case normalizedMethod == "GET" && matchPathPattern(normalizedPath, "/containers/*/archive"):
		meta.Operation = DockerOperation("archive_read")
	}

	return meta
}

func isPayloadAwareOperation(op DockerOperation) bool {
	switch normalizeDockerOperation(string(op)) {
	case DockerOperation("build"), DockerOperation("exec_create"), DockerOperation("exec_start"):
		return true
	default:
		return false
	}
}

func isStreamingDockerOperation(op DockerOperation) bool {
	switch normalizeDockerOperation(string(op)) {
	case DockerOperation("image_pull"), DockerOperation("build"), DockerOperation("exec_start"):
		return true
	default:
		return false
	}
}

func matchPathPattern(path, pattern string) bool {
	pathSegments := splitPathSegments(path)
	patternSegments := splitPathSegments(pattern)
	if len(pathSegments) != len(patternSegments) {
		return false
	}
	for idx := range pathSegments {
		if patternSegments[idx] == "*" {
			if pathSegments[idx] == "" {
				return false
			}
			continue
		}
		if pathSegments[idx] != patternSegments[idx] {
			return false
		}
	}
	return true
}

func pathSegmentCount(path string) int {
	return len(splitPathSegments(path))
}

func splitPathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
