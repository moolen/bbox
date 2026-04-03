package bbox

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

type dockerBuildRequest struct {
	Dockerfile string
	Remote     string
	Tags       []string
	BodyKind   string
}

func inspectDockerBuildRequest(req *http.Request, body []byte) (dockerBuildRequest, error) {
	if req == nil {
		return dockerBuildRequest{}, fmt.Errorf("build request is required")
	}

	query := req.URL.Query()
	buildReq := dockerBuildRequest{
		Dockerfile: normalizeDockerBuildPath(query.Get("dockerfile")),
		Remote:     strings.TrimSpace(query.Get("remote")),
		Tags:       normalizeDockerBuildTags(query["t"]),
	}

	if buildReq.Dockerfile == "" {
		return dockerBuildRequest{}, fmt.Errorf("build dockerfile path cannot be empty")
	}

	if buildReq.Remote != "" {
		if err := setDockerBuildBodyKind(&buildReq, "remote"); err != nil {
			return dockerBuildRequest{}, err
		}
	}

	exportKind, err := detectDockerBuildExport(query)
	if err != nil {
		return dockerBuildRequest{}, err
	}
	if exportKind != "" {
		if err := setDockerBuildBodyKind(&buildReq, exportKind); err != nil {
			return dockerBuildRequest{}, err
		}
	}

	hasTarBody, err := validateDockerBuildContextBody(req, body, buildReq.Dockerfile)
	if err != nil {
		return dockerBuildRequest{}, err
	}
	if hasTarBody {
		if err := setDockerBuildBodyKind(&buildReq, "tar"); err != nil {
			return dockerBuildRequest{}, err
		}
	}
	if buildReq.BodyKind == "" {
		return dockerBuildRequest{}, fmt.Errorf("unsupported docker build request body")
	}

	return buildReq, nil
}

func normalizeDockerBuildTags(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	tags := make([]string, 0, len(values))
	for _, value := range values {
		tag := strings.TrimSpace(value)
		if tag == "" {
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

func normalizeDockerBuildPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "Dockerfile"
	}

	cleaned := path.Clean(strings.ReplaceAll(trimmed, "\\", "/"))
	switch {
	case cleaned == ".", cleaned == "":
		return ""
	case strings.HasPrefix(cleaned, "/"):
		return ""
	case cleaned == "..":
		return ""
	case strings.HasPrefix(cleaned, "../"):
		return ""
	default:
		return cleaned
	}
}

func setDockerBuildBodyKind(buildReq *dockerBuildRequest, bodyKind string) error {
	if buildReq == nil || bodyKind == "" {
		return nil
	}
	if buildReq.BodyKind == "" {
		buildReq.BodyKind = bodyKind
		return nil
	}
	if buildReq.BodyKind == bodyKind {
		return nil
	}
	return fmt.Errorf("conflicting docker build context signals: %s and %s", buildReq.BodyKind, bodyKind)
}

func detectDockerBuildExport(query map[string][]string) (string, error) {
	if values, ok := query["push"]; ok {
		push, err := parseDockerBuildPush(values)
		if err != nil {
			return "", err
		}
		if push {
			return "export", nil
		}
	}

	if values, ok := query["output"]; ok {
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return "", fmt.Errorf("docker build output parameter cannot be empty")
			}
		}
		return "export", nil
	}

	if values, ok := query["outputs"]; ok {
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				return "", fmt.Errorf("docker build outputs parameter cannot be empty")
			}
			var decoded []map[string]any
			if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
				return "", fmt.Errorf("parse docker build outputs: %w", err)
			}
			if len(decoded) == 0 {
				return "", fmt.Errorf("docker build outputs parameter cannot be empty")
			}
		}
		return "export", nil
	}

	return "", nil
}

func parseDockerBuildPush(values []string) (bool, error) {
	sawTruthy := false
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "t", "true", "yes":
			sawTruthy = true
		case "0", "f", "false", "no":
			continue
		case "":
			return false, fmt.Errorf("docker build push parameter cannot be empty")
		default:
			return false, fmt.Errorf("docker build push parameter %q is ambiguous", value)
		}
	}
	return sawTruthy, nil
}

func validateDockerBuildContextBody(req *http.Request, body []byte, dockerfilePath string) (bool, error) {
	if len(body) == 0 {
		return false, nil
	}

	contentType := strings.TrimSpace(req.Header.Get("Content-Type"))
	if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/x-tar") {
		return false, fmt.Errorf("unsupported docker build content type %q", contentType)
	}

	tr := tar.NewReader(bytes.NewReader(body))
	foundDockerfile := false
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return false, fmt.Errorf("read docker build context tar: %w", err)
		}
		if normalizeDockerBuildPath(header.Name) == dockerfilePath {
			foundDockerfile = true
		}
	}

	if !foundDockerfile {
		return false, fmt.Errorf("docker build context missing dockerfile %q", dockerfilePath)
	}

	return true, nil
}
