package bbox

import "testing"

func TestNormalizeDockerAPIPathStripsVersionPrefix(t *testing.T) {
	t.Parallel()

	got := normalizeDockerAPIPath("/v1.52/images/create")
	if got != "/images/create" {
		t.Fatalf("expected version prefix stripped, got %q", got)
	}
}

func TestNormalizeDockerAPIPathStripsQueryString(t *testing.T) {
	t.Parallel()

	got := normalizeDockerAPIPath("/v1.52/images/create?fromImage=alpine")
	if got != "/images/create" {
		t.Fatalf("expected query string stripped, got %q", got)
	}
}

func TestNormalizeDockerAPIPathNormalizesTrailingSlash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "/v1.52/build/", want: "/build"},
		{in: "/v1.52/images/library/alpine/json/", want: "/images/library/alpine/json"},
		{in: "/", want: "/"},
	}
	for _, tt := range tests {
		got := normalizeDockerAPIPath(tt.in)
		if got != tt.want {
			t.Fatalf("normalize %q: got %q want %q", tt.in, got, tt.want)
		}
	}
}

func TestMapDockerRequestMapsPhaseOneOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		wantMethod string
		path       string
		wantPath   string
		wantOp     DockerOperation
		streaming  bool
		payload    bool
	}{
		{
			name:       "image pull",
			method:     "POST",
			wantMethod: "POST",
			path:       "/v1.52/images/create",
			wantPath:   "/images/create",
			wantOp:     DockerOperation("image_pull"),
			streaming:  true,
		},
		{
			name:       "image inspect",
			method:     "GET",
			wantMethod: "GET",
			path:       "/v1.52/images/library/alpine/json",
			wantPath:   "/images/library/alpine/json",
			wantOp:     DockerOperation("image_inspect"),
		},
		{
			name:       "build",
			method:     "post",
			wantMethod: "POST",
			path:       "/v1.52/build",
			wantPath:   "/build",
			wantOp:     DockerOperation("build"),
			streaming:  true,
			payload:    true,
		},
		{
			name:       "exec create",
			method:     "POST",
			wantMethod: "POST",
			path:       "/v1.52/containers/foo/exec",
			wantPath:   "/containers/foo/exec",
			wantOp:     DockerOperation("exec_create"),
			payload:    true,
		},
		{
			name:       "exec start",
			method:     "POST",
			wantMethod: "POST",
			path:       "/v1.52/exec/bar/start",
			wantPath:   "/exec/bar/start",
			wantOp:     DockerOperation("exec_start"),
			streaming:  true,
			payload:    true,
		},
		{
			name:       "archive read",
			method:     "GET",
			wantMethod: "GET",
			path:       "/v1.52/containers/foo/archive/",
			wantPath:   "/containers/foo/archive",
			wantOp:     DockerOperation("archive_read"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapDockerRequest(tt.method, tt.path)
			if got.Method != tt.wantMethod {
				t.Fatalf("method mismatch: got %q want %q", got.Method, tt.wantMethod)
			}
			if got.Path != tt.wantPath {
				t.Fatalf("normalized path mismatch: got %q want %q", got.Path, tt.wantPath)
			}
			if got.Operation != tt.wantOp {
				t.Fatalf("operation mismatch: got %q want %q", got.Operation, tt.wantOp)
			}
			if isStreamingDockerOperation(got.Operation) != tt.streaming {
				t.Fatalf("streaming mismatch for %q: got %v want %v", got.Operation, isStreamingDockerOperation(got.Operation), tt.streaming)
			}
			if isPayloadAwareOperation(got.Operation) != tt.payload {
				t.Fatalf("payload-aware mismatch for %q: got %v want %v", got.Operation, isPayloadAwareOperation(got.Operation), tt.payload)
			}
		})
	}
}

func TestMapDockerRequestMarksUnknownEndpoints(t *testing.T) {
	t.Parallel()

	got := mapDockerRequest("DELETE", "/v1.52/sessions/foo")
	if got.Operation != DockerOperation("unknown") {
		t.Fatalf("expected unknown operation, got %q", got.Operation)
	}
	if got.Path != "/sessions/foo" {
		t.Fatalf("expected normalized path, got %q", got.Path)
	}
}
