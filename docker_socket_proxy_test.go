package bbox

import (
	"archive/tar"
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestEvaluateDockerBuildRejectsRemoteContextParameters(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"build"},
				Build: &DockerBuildMatch{
					Context: DockerBuildContextMatchLocalOnly,
					DockerfilePaths: []string{
						"^Dockerfile$",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1.52/build?remote=https://example.com/context.tar.gz", bytes.NewReader(buildContextTar(t, "Dockerfile")))
	req.Header.Set("Content-Type", "application/x-tar")

	buildReq, err := inspectDockerBuildRequest(req, buildContextTar(t, "Dockerfile"))
	if err != nil {
		t.Fatalf("inspect build request: %v", err)
	}

	got := compiled.evaluate(dockerSocketRequest{
		Method:    req.Method,
		Path:      req.URL.Path,
		Operation: DockerOperation("build"),
		Build:     &buildReq,
	})
	if got != DockerRuleActionDeny {
		t.Fatalf("expected remote context build to be denied, got %q", got)
	}
}

func TestEvaluateDockerBuildRejectsRegistryExporters(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"build"},
				Build: &DockerBuildMatch{
					Context: DockerBuildContextMatchLocalOnly,
					DockerfilePaths: []string{
						"^Dockerfile$",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/v1.52/build?outputs=%5B%7B%22type%22%3A%22registry%22%2C%22name%22%3A%22ghcr.io%2Facme%2Fdemo%3Alatest%22%7D%5D", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	buildReq, err := inspectDockerBuildRequest(req, body)
	if err != nil {
		t.Fatalf("inspect build request: %v", err)
	}

	got := compiled.evaluate(dockerSocketRequest{
		Method:    req.Method,
		Path:      req.URL.Path,
		Operation: DockerOperation("build"),
		Build:     &buildReq,
	})
	if got != DockerRuleActionDeny {
		t.Fatalf("expected registry exporter build to be denied, got %q", got)
	}
}

func TestEvaluateDockerBuildAllowsLocalTarContextWithApprovedDockerfile(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"build"},
				Build: &DockerBuildMatch{
					Context: DockerBuildContextMatchLocalOnly,
					DockerfilePaths: []string{
						"^Dockerfile$",
						"^docker/.*$",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	body := buildContextTar(t, "docker/app.Dockerfile")
	req := httptest.NewRequest("POST", "/v1.52/build?dockerfile=docker%2Fapp.Dockerfile&t=acme%2Fdemo%3Alatest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	buildReq, err := inspectDockerBuildRequest(req, body)
	if err != nil {
		t.Fatalf("inspect build request: %v", err)
	}

	got := compiled.evaluate(dockerSocketRequest{
		Method:    req.Method,
		Path:      req.URL.Path,
		Operation: DockerOperation("build"),
		Build:     &buildReq,
	})
	if got != DockerRuleActionAllow {
		t.Fatalf("expected local tar build to be allowed, got %q", got)
	}
}

func buildContextTar(t *testing.T, dockerfilePath string) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: dockerfilePath,
		Mode: 0o644,
		Size: int64(len("FROM scratch\n")),
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write([]byte("FROM scratch\n")); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}
