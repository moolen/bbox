package dockerbuild

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

func rewriteDockerfileWithTrustBundle(content []byte, opts trustInjectionOptions) ([]byte, error) {
	result, err := parser.Parse(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	if result == nil || result.AST == nil {
		return append([]byte(nil), content...), nil
	}

	perRunSnippet := trustBundlePerRunInjectionSnippet(opts)
	stageBootstrapSnippet := trustStageBootstrapSnippet(opts)
	if perRunSnippet == "" && stageBootstrapSnippet == "" {
		return append([]byte(nil), content...), nil
	}

	injectBeforeLine := make(map[int]struct{})
	injectStageBootstrapBeforeLine := make(map[int]struct{})
	currentStageSawRun := false
	for _, child := range result.AST.Children {
		instruction := strings.ToLower(strings.TrimSpace(child.Value))
		if instruction == "from" {
			currentStageSawRun = false
		}
		if instruction == "run" && child.StartLine > 0 {
			if perRunSnippet != "" {
				injectBeforeLine[child.StartLine] = struct{}{}
			}
			if stageBootstrapSnippet != "" && !currentStageSawRun {
				injectStageBootstrapBeforeLine[child.StartLine] = struct{}{}
			}
			currentStageSawRun = true
		}
	}
	if len(injectBeforeLine) == 0 && len(injectStageBootstrapBeforeLine) == 0 {
		return append([]byte(nil), content...), nil
	}

	lines := strings.SplitAfter(string(content), "\n")
	if len(lines) == 0 {
		lines = []string{string(content)}
	}

	var out strings.Builder
	for i, line := range lines {
		lineNo := i + 1
		if _, ok := injectStageBootstrapBeforeLine[lineNo]; ok {
			out.WriteString(stageBootstrapSnippet)
		}
		if _, ok := injectBeforeLine[lineNo]; ok {
			out.WriteString(perRunSnippet)
		}
		out.WriteString(line)
	}

	return []byte(out.String()), nil
}

func trustBundleInjectionSnippet(opts ...trustInjectionOptions) string {
	return trustStageBootstrapSnippet(opts...) + trustBundlePerRunInjectionSnippet(opts...)
}

func javaTruststoreOptions(truststore generatedTruststore) []string {
	if strings.TrimSpace(truststore.Path) == "" ||
		strings.TrimSpace(truststore.Type) == "" ||
		strings.TrimSpace(truststore.Password) == "" {
		return nil
	}
	return []string{
		"-Djavax.net.ssl.trustStore=" + injectedJavaTruststorePath,
		"-Djavax.net.ssl.trustStoreType=" + truststore.Type,
		"-Djavax.net.ssl.trustStorePassword=" + truststore.Password,
	}
}

func trustBundlePerRunInjectionSnippet(opts ...trustInjectionOptions) string {
	injection := trustInjectionOptions{}
	if len(opts) == 0 {
		injection.pemPath = injectedTrustBundlePrimaryPath
	} else {
		injection = opts[0]
	}
	if strings.TrimSpace(injection.pemPath) == "" {
		return ""
	}

	var b strings.Builder
	for _, dest := range injectedTrustBundleDestinations {
		fmt.Fprintf(&b, "COPY --from=%s /%s %s\n", bboxTrustContextName, bboxTrustBundleFileName, dest)
	}
	fmt.Fprintf(&b, "ENV SSL_CERT_FILE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV NODE_EXTRA_CA_CERTS=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV NPM_CONFIG_CAFILE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV CURL_CA_BUNDLE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV REQUESTS_CA_BUNDLE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV PIP_CERT=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV GIT_SSL_CAINFO=%s\n", injection.pemPath)
	return b.String()
}

func trustStageBootstrapSnippet(opts ...trustInjectionOptions) string {
	injection := trustInjectionOptions{}
	if len(opts) > 0 {
		injection = opts[0]
	}

	var b strings.Builder
	if strings.TrimSpace(injection.javaTruststorePath) != "" {
		fmt.Fprintf(&b, "COPY --from=%s /%s %s\n", bboxTrustContextName, bboxJavaTruststoreFileName, injection.javaTruststorePath)
	}
	if len(injection.javaToolOptions) > 0 {
		fmt.Fprintf(
			&b,
			"ENV JAVA_TOOL_OPTIONS %s ${JAVA_TOOL_OPTIONS}\n",
			strings.Join(injection.javaToolOptions, " "),
		)
	}
	if strings.TrimSpace(injection.mavenSettingsPath) != "" {
		fmt.Fprintf(&b, "COPY --from=%s /%s %s\n", bboxTrustContextName, bboxMavenSettingsFileName, injection.mavenSettingsPath)
		fmt.Fprintf(&b, "ENV MAVEN_ARGS --settings %s ${MAVEN_ARGS}\n", injection.mavenSettingsPath)
	}
	return b.String()
}
