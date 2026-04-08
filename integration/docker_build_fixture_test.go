package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/moolen/bbox"
)

const alpineMinirootfsVersion = "3.18.9"

var (
	alpineMinirootfsOnce sync.Once
	alpineMinirootfsPath string
	alpineMinirootfsErr  error
)

type dockerBuildFixture struct {
	repoDir        string
	sandboxRepoDir string
	outputPath     string
}

func TestDockerBuildMatrixFixtureUsesLocalRootfsBase(t *testing.T) {
	fixture := writeDockerBuildMatrixFixture(t)

	dockerfilePath := filepath.Join(fixture.repoDir, "Dockerfile")
	dockerfile, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read fixture Dockerfile: %v", err)
	}
	contents := string(dockerfile)
	if !strings.Contains(contents, "FROM scratch AS alpine-base") {
		t.Fatalf("expected local scratch-based alpine stage, dockerfile=%q", contents)
	}
	if !strings.Contains(contents, "ADD alpine-minirootfs.tar.gz /") {
		t.Fatalf("expected local minirootfs archive to be added, dockerfile=%q", contents)
	}
	if strings.Contains(contents, "FROM alpine:") {
		t.Fatalf("expected fixture to avoid registry-backed alpine image, dockerfile=%q", contents)
	}
	if _, err := os.Stat(filepath.Join(fixture.repoDir, "alpine-minirootfs.tar.gz")); err != nil {
		t.Fatalf("expected staged alpine minirootfs archive: %v", err)
	}
}

func writeDockerBuildMatrixFixture(t *testing.T) dockerBuildFixture {
	t.Helper()

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("create fixture repo: %v", err)
	}
	stageAlpineMinirootfs(t, filepath.Join(repoDir, "alpine-minirootfs.tar.gz"))

	dockerfile := strings.Join([]string{
		"FROM scratch AS alpine-base",
		"ADD alpine-minirootfs.tar.gz /",
		"",
		"FROM alpine-base AS curl-tools-base",
		"RUN apk add --no-cache ca-certificates curl wget",
		"",
		"FROM curl-tools-base AS node-tools-base",
		"RUN apk add --no-cache nodejs npm",
		"",
		"FROM node-tools-base AS python-tools-base",
		"RUN apk add --no-cache python3 py3-pip",
		"",
		"FROM python-tools-base AS go-tools-base",
		"RUN apk add --no-cache go",
		"",
		"FROM curl-tools-base AS curl-stage",
		"RUN mkdir -p /out && curl -fsSL https://registry.npmjs.org/is-number/latest -o /out/curl.json",
		"",
		"FROM curl-tools-base AS wget-stage",
		"RUN mkdir -p /out && wget -qO /out/wget.json https://registry.npmjs.org/is-number/latest",
		"",
		"FROM node-tools-base AS node-stage",
		"RUN mkdir -p /out && npm view is-number version > /out/npm-version.txt",
		"",
		"FROM python-tools-base AS python-stage",
		"RUN mkdir -p /out && python3 -m pip download --no-deps --dest /out idna==3.7",
		"",
		"FROM go-tools-base AS go-stage",
		"WORKDIR /src",
		"COPY go.mod ./",
		"RUN mkdir -p /out && go mod download && go list -m all > /out/go-modules.txt",
		"",
		"FROM alpine-base AS java-maven-stage",
		"WORKDIR /src",
		"COPY Main.java ./",
		"COPY pom.xml ./",
		"COPY --from=go-stage /out/go-modules.txt /tmp/bbox-go-modules.txt",
		"RUN apk add --no-cache ca-certificates openjdk17-jdk maven",
		"RUN javac Main.java && mkdir -p /out && java Main",
		"RUN mkdir -p /out && mvn -B -q dependency:list -DincludeScope=compile -DoutputFile=/out/maven-deps.txt",
		"",
		"FROM alpine-base",
		"RUN apk add --no-cache ca-certificates",
		"COPY --from=curl-stage /out /artifacts/curl",
		"COPY --from=wget-stage /out /artifacts/wget",
		"COPY --from=node-stage /out /artifacts/node",
		"COPY --from=python-stage /out /artifacts/python",
		"COPY --from=go-stage /out /artifacts/go",
		"COPY --from=java-maven-stage /out /artifacts/java-maven",
		"RUN grep -q '\"name\":\"is-number\"' /artifacts/curl/curl.json",
		"RUN grep -q '\"name\":\"is-number\"' /artifacts/wget/wget.json",
		"RUN test -s /artifacts/node/npm-version.txt",
		"RUN ls /artifacts/python/* >/dev/null",
		"RUN test -s /artifacts/go/go-modules.txt",
		"RUN grep -q '\"name\":\"is-number\"' /artifacts/java-maven/java-response.json",
		"RUN grep -q 'org.apache.commons:commons-lang3:jar:3.17.0:compile' /artifacts/java-maven/maven-deps.txt",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(repoDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write fixture Dockerfile: %v", err)
	}

	goMod := strings.Join([]string{
		"module fixture",
		"",
		"go 1.20",
		"",
		"require rsc.io/quote v1.5.2",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}

	javaSource := strings.Join([]string{
		"import java.net.URI;",
		"import java.net.http.HttpClient;",
		"import java.net.http.HttpRequest;",
		"import java.net.http.HttpResponse;",
		"import java.nio.file.Files;",
		"import java.nio.file.Path;",
		"",
		"public class Main {",
		"  public static void main(String[] args) throws Exception {",
		"    HttpClient client = HttpClient.newHttpClient();",
		"    HttpRequest request = HttpRequest.newBuilder(URI.create(\"https://registry.npmjs.org/is-number/latest\")).GET().build();",
		"    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());",
		"    if (response.statusCode() != 200) {",
		"      throw new IllegalStateException(\"unexpected status: \" + response.statusCode());",
		"    }",
		"    Path outDir = Path.of(\"/out\");",
		"    Files.createDirectories(outDir);",
		"    Files.writeString(outDir.resolve(\"java-response.json\"), response.body());",
		"  }",
		"}",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(repoDir, "Main.java"), []byte(javaSource), 0o644); err != nil {
		t.Fatalf("write fixture Main.java: %v", err)
	}

	pomXML := strings.Join([]string{
		"<project xmlns=\"http://maven.apache.org/POM/4.0.0\"",
		"         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"",
		"         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">",
		"  <modelVersion>4.0.0</modelVersion>",
		"  <groupId>bbox.fixture</groupId>",
		"  <artifactId>java-maven-proxy-fixture</artifactId>",
		"  <version>1.0.0</version>",
		"  <dependencies>",
		"    <dependency>",
		"      <groupId>org.apache.commons</groupId>",
		"      <artifactId>commons-lang3</artifactId>",
		"      <version>3.17.0</version>",
		"    </dependency>",
		"  </dependencies>",
		"</project>",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(repoDir, "pom.xml"), []byte(pomXML), 0o644); err != nil {
		t.Fatalf("write fixture pom.xml: %v", err)
	}

	return dockerBuildFixture{
		repoDir:        repoDir,
		sandboxRepoDir: "/workspace/docker-build-fixture",
		outputPath:     filepath.Join(repoDir, ".bbox-docker-build.oci.tar"),
	}
}

func stageAlpineMinirootfs(t *testing.T, destPath string) {
	t.Helper()

	sourcePath := requireAlpineMinirootfs(t)
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open cached alpine minirootfs %s: %v", sourcePath, err)
	}
	defer source.Close()

	dest, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("create staged alpine minirootfs %s: %v", destPath, err)
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		t.Fatalf("copy alpine minirootfs to fixture context: %v", err)
	}
}

func requireAlpineMinirootfs(t *testing.T) string {
	t.Helper()

	alpineMinirootfsOnce.Do(func() {
		alpineMinirootfsPath, alpineMinirootfsErr = downloadAlpineMinirootfs()
	})
	if alpineMinirootfsErr != nil {
		t.Fatalf("download alpine minirootfs: %v", alpineMinirootfsErr)
	}
	return alpineMinirootfsPath
}

func downloadAlpineMinirootfs() (string, error) {
	arch, err := alpineMinirootfsArch(runtime.GOARCH)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(
		"https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/%s/alpine-minirootfs-%s-%s.tar.gz",
		arch,
		alpineMinirootfsVersion,
		arch,
	)
	response, err := (&http.Client{}).Get(url)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: unexpected status %s", url, response.Status)
	}

	dir, err := os.MkdirTemp("", "bbox-alpine-minirootfs-")
	if err != nil {
		return "", fmt.Errorf("create alpine minirootfs cache dir: %w", err)
	}
	path := filepath.Join(dir, "alpine-minirootfs.tar.gz")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("create cached alpine minirootfs %s: %w", path, err)
	}
	defer file.Close()

	if _, err := io.Copy(file, response.Body); err != nil {
		return "", fmt.Errorf("write cached alpine minirootfs %s: %w", path, err)
	}
	return path, nil
}

func alpineMinirootfsArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported alpine minirootfs architecture %q", goarch)
	}
}

func writeDockerBuildProxyFailClosedFixture(t *testing.T) dockerBuildFixture {
	t.Helper()

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("create negative fixture repo: %v", err)
	}

	sourcePath := filepath.Join(repoDir, "main.go")
	source := strings.Join([]string{
		"package main",
		"",
		"import (",
		`  "fmt"`,
		`  "net"`,
		`  "os"`,
		`  "time"`,
		")",
		"",
		"func main() {",
		`  conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)`,
		"  if err != nil {",
		`    fmt.Fprintf(os.Stderr, "raw-client-direct-connect-failed: %v\n", err)`,
		"    os.Exit(1)",
		"  }",
		"  _ = conn.Close()",
		`  fmt.Println("raw-client-unexpected-direct-connect-success")`,
		"}",
		"",
	}, "\n")
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write negative fixture main.go: %v", err)
	}

	binaryPath := filepath.Join(repoDir, "raw-client")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, sourcePath)
	buildCmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
	)
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build negative fixture client: %v\n%s", err, string(buildOutput))
	}

	dockerfile := strings.Join([]string{
		"FROM scratch",
		"COPY raw-client /raw-client",
		"RUN [\"/raw-client\"]",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(repoDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write negative fixture Dockerfile: %v", err)
	}

	return dockerBuildFixture{
		repoDir:        repoDir,
		sandboxRepoDir: "/workspace/docker-build-fixture-fail-closed",
		outputPath:     filepath.Join(repoDir, ".bbox-docker-build.oci.tar"),
	}
}

func dockerBuildMatrixNetworkPolicy() bbox.NetworkPolicy {
	hosts := []string{
		`^dl-cdn[.]alpinelinux[.]org$`,
		`^files[.]pythonhosted[.]org$`,
		`^proxy[.]golang[.]org$`,
		`^pypi[.]org$`,
		`^repo1[.]maven[.]org$`,
		`^repo[.]maven[.]apache[.]org$`,
		`^registry[.]npmjs[.]org$`,
		`^storage[.]googleapis[.]com$`,
		`^sum[.]golang[.]org$`,
	}

	rules := make([]bbox.PolicyRule, 0, len(hosts)*2)
	for _, host := range hosts {
		rules = append(rules, bbox.PolicyRule{HostPatterns: []string{host}})
		rules = append(rules, bbox.PolicyRule{
			HostPatterns: []string{host},
			ConnectPorts: []string{"443"},
		})
	}
	return bbox.NetworkPolicy{Rules: rules}
}
