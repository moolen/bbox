package bbox

import (
	"archive/tar"
	"bytes"
	"net/http/httptest"
	"strings"
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

	req := httptest.NewRequest("POST", "/v1.52/build?remote=https://example.com/context.tar.gz", nil)

	buildReq, err := inspectDockerBuildRequest(req, nil)
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

	req := httptest.NewRequest("POST", "/v1.52/build?outputs=%5B%7B%22type%22%3A%22registry%22%2C%22name%22%3A%22ghcr.io%2Facme%2Fdemo%3Alatest%22%7D%5D", nil)

	buildReq, err := inspectDockerBuildRequest(req, nil)
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
	req.Header.Set("Content-Type", "Application/X-Tar")

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

func TestEvaluateDockerBuildRejectsDockerfilePathTraversal(t *testing.T) {
	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/build?dockerfile=../Dockerfile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	_, err := inspectDockerBuildRequest(req, body)
	if err == nil {
		t.Fatal("expected dockerfile path traversal to fail")
	}
	if err.Error() != "build dockerfile path cannot be empty" {
		t.Fatalf("expected dockerfile path error, got %q", err.Error())
	}
}

func TestEvaluateDockerBuildRejectsMissingDockerfileInTar(t *testing.T) {
	body := buildContextTar(t, "docker/Otherfile")
	req := httptest.NewRequest("POST", "/build", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	_, err := inspectDockerBuildRequest(req, body)
	if err == nil {
		t.Fatal("expected missing dockerfile in tar to fail")
	}
	if err.Error() != "docker build context missing dockerfile \"Dockerfile\"" {
		t.Fatalf("expected missing dockerfile error, got %q", err.Error())
	}
}

func TestEvaluateDockerBuildRejectsNonTarContentType(t *testing.T) {
	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/build", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	_, err := inspectDockerBuildRequest(req, body)
	if err == nil {
		t.Fatal("expected non-tar content type to fail")
	}
	if err.Error() != "unsupported docker build content type \"application/json\"" {
		t.Fatalf("expected content type error, got %q", err.Error())
	}
}

func TestEvaluateDockerBuildRejectsMalformedOutputsJSON(t *testing.T) {
	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/build?outputs=%5B", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	_, err := inspectDockerBuildRequest(req, body)
	if err == nil {
		t.Fatal("expected malformed outputs JSON to fail")
	}
	if !strings.HasPrefix(err.Error(), "parse docker build outputs:") {
		t.Fatalf("expected outputs parse error, got %q", err.Error())
	}
}

func TestEvaluateDockerBuildRejectsAmbiguousPushParameter(t *testing.T) {
	for _, rawQuery := range []string{"push", "push="} {
		t.Run(rawQuery, func(t *testing.T) {
			body := buildContextTar(t, "Dockerfile")
			req := httptest.NewRequest("POST", "/build?"+rawQuery, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/x-tar")

			_, err := inspectDockerBuildRequest(req, body)
			if err == nil {
				t.Fatal("expected ambiguous push parameter to fail")
			}
			if err.Error() != "docker build push parameter cannot be empty" {
				t.Fatalf("expected push ambiguity error, got %q", err.Error())
			}
		})
	}
}

func TestEvaluateDockerBuildAllowsPushZeroForLocalTarContext(t *testing.T) {
	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/build?push=0", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	buildReq, err := inspectDockerBuildRequest(req, body)
	if err != nil {
		t.Fatalf("inspect build request: %v", err)
	}
	if buildReq.BodyKind != "tar" {
		t.Fatalf("expected push=0 to preserve tar body semantics, got %q", buildReq.BodyKind)
	}
}

func TestEvaluateDockerBuildRejectsAmbiguousMultiValuePushParameter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		query   string
		wantErr string
	}{
		{
			name:    "truthy and empty",
			query:   "push=1&push=",
			wantErr: "docker build push parameter cannot be empty",
		},
		{
			name:    "truthy and ambiguous",
			query:   "push=1&push=maybe",
			wantErr: "docker build push parameter \"maybe\" is ambiguous",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := buildContextTar(t, "Dockerfile")
			req := httptest.NewRequest("POST", "/build?"+tc.query, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/x-tar")

			_, err := inspectDockerBuildRequest(req, body)
			if err == nil {
				t.Fatal("expected multi-valued push parameter to fail")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("expected multi-valued push error %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestEvaluateDockerBuildAllowsFalseyMultiValuePushParameter(t *testing.T) {
	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/build?push=0&push=false", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	buildReq, err := inspectDockerBuildRequest(req, body)
	if err != nil {
		t.Fatalf("inspect build request: %v", err)
	}
	if buildReq.BodyKind != "tar" {
		t.Fatalf("expected falsey multi-valued push to preserve tar body semantics, got %q", buildReq.BodyKind)
	}
}

func TestEvaluateDockerBuildRejectsConflictingRemoteAndTarContextSignals(t *testing.T) {
	body := buildContextTar(t, "Dockerfile")
	req := httptest.NewRequest("POST", "/build?remote=https://example.com/context.tar.gz", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-tar")

	_, err := inspectDockerBuildRequest(req, body)
	if err == nil {
		t.Fatal("expected conflicting remote and tar signals to fail")
	}
	if err.Error() != "conflicting docker build context signals: remote and tar" {
		t.Fatalf("expected conflicting signal error, got %q", err.Error())
	}
}

func TestEvaluateDockerBuildHTTPPathMatchDoesNotBypassBuildGuards(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"build"},
				HTTP: &DockerHTTPMatch{
					Methods:      []string{"POST"},
					PathPatterns: []string{"^/build$"},
				},
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

	req := httptest.NewRequest("POST", "/build?remote=https://example.com/context.tar.gz", nil)

	buildReq, err := inspectDockerBuildRequest(req, nil)
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
		t.Fatalf("expected remote context build to be denied even when the HTTP path matches, got %q", got)
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
