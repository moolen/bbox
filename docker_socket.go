package bbox

import "strings"

type dockerSocketRequest struct {
	Method    string
	Path      string
	Operation DockerOperation
}

func normalizeDockerOperation(op string) DockerOperation {
	return DockerOperation(strings.ToLower(strings.TrimSpace(op)))
}
