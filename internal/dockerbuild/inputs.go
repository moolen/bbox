package dockerbuild

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	bboxTrustBundleEnvKey   = "BBOX_TRUST_BUNDLE_PATH"
	bboxProxyArgsOnlyEnvKey = "BBOX_DOCKER_BUILD_PROXY_ARGS_ONLY"
	bboxTrustContextName    = "bbox_mitm_trust"
	bboxTrustBundleFileName = "bbox-trust-bundle.pem"
)

var injectedTrustBundleDestinations = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
}

const injectedTrustBundlePrimaryPath = "/etc/ssl/certs/ca-certificates.crt"
const injectedJavaTruststorePath = "/etc/ssl/certs/bbox-truststore.p12"
const injectedMavenSettingsPath = "/etc/maven/bbox-settings.xml"

type buildInputs struct {
	ContextDir     string
	DockerfileDir  string
	DockerfileName string
	ExtraLocals    []string
	FrontendOpts   []string
	CleanupPaths   []string
	TrustBundle    string
	Truststore     generatedTruststore
	JavaToolOpts   []string
	MavenSettings  string
}

type trustInjectionOptions struct {
	pemPath            string
	javaTruststorePath string
	javaToolOptions    []string
	mavenSettingsPath  string
}

func prepareBuildInputs(contextAbs string, dockerfileAbs string, env []string) (buildInputs, error) {
	inputs := buildInputs{
		ContextDir:     contextAbs,
		DockerfileDir:  filepath.Dir(dockerfileAbs),
		DockerfileName: filepath.Base(dockerfileAbs),
	}

	if _, err := os.Stat(dockerfileAbs); err != nil {
		if os.IsNotExist(err) {
			return inputs, nil
		}
		return buildInputs{}, fmt.Errorf("stat dockerfile %s: %w", dockerfileAbs, err)
	}

	original, err := os.ReadFile(dockerfileAbs)
	if err != nil {
		return buildInputs{}, fmt.Errorf("read dockerfile %s: %w", dockerfileAbs, err)
	}
	proxyCfg, err := proxyConfigFromEnv(env)
	if err != nil {
		return buildInputs{}, fmt.Errorf("parse proxy config from env: %w", err)
	}
	trustBundlePath, hasTrustBundle := resolveTrustBundlePath(env)

	previewInjection := trustInjectionOptions{}
	if hasTrustBundle {
		previewInjection.pemPath = injectedTrustBundlePrimaryPath
	}
	if proxyOpts := javaProxyOptions(proxyCfg); len(proxyOpts) > 0 {
		previewInjection.javaToolOptions = append(previewInjection.javaToolOptions, proxyOpts...)
	}
	if proxyCfg.Enabled() {
		previewInjection.mavenSettingsPath = injectedMavenSettingsPath
	}
	previewRewritten, err := rewriteDockerfileWithTrustBundle(original, previewInjection)
	if err != nil {
		return buildInputs{}, fmt.Errorf("rewrite dockerfile %s for trust injection: %w", dockerfileAbs, err)
	}
	if bytes.Equal(previewRewritten, original) {
		return inputs, nil
	}

	stageDir, err := os.MkdirTemp("", "bbox-build-inputs-")
	if err != nil {
		return buildInputs{}, fmt.Errorf("create build input staging dir: %w", err)
	}

	rewrittenPath := filepath.Join(stageDir, filepath.Base(dockerfileAbs))
	if hasTrustBundle {
		trustBundle, err := os.ReadFile(trustBundlePath)
		if err != nil {
			_ = os.RemoveAll(stageDir)
			return buildInputs{}, fmt.Errorf("read trust bundle %s: %w", trustBundlePath, err)
		}
		if err := os.WriteFile(filepath.Join(stageDir, bboxTrustBundleFileName), trustBundle, 0o644); err != nil {
			_ = os.RemoveAll(stageDir)
			return buildInputs{}, fmt.Errorf("write staged trust bundle: %w", err)
		}
		inputs.TrustBundle = filepath.Join(stageDir, bboxTrustBundleFileName)
		if len(trustBundle) > 0 {
			truststore, err := writePKCS12Truststore(stageDir, trustBundle)
			if err != nil {
				_ = os.RemoveAll(stageDir)
				return buildInputs{}, fmt.Errorf("write staged JVM truststore: %w", err)
			}
			inputs.Truststore = truststore
		}
	}
	if proxyCfg.Enabled() {
		settingsXML, err := renderMavenSettings(proxyCfg)
		if err != nil {
			_ = os.RemoveAll(stageDir)
			return buildInputs{}, fmt.Errorf("render Maven settings: %w", err)
		}
		settingsPath := filepath.Join(stageDir, bboxMavenSettingsFileName)
		if err := os.WriteFile(settingsPath, settingsXML, 0o644); err != nil {
			_ = os.RemoveAll(stageDir)
			return buildInputs{}, fmt.Errorf("write staged Maven settings: %w", err)
		}
		inputs.MavenSettings = settingsPath
	}
	inputs.JavaToolOpts = append(inputs.JavaToolOpts, javaProxyOptions(proxyCfg)...)
	if truststoreOpts := javaTruststoreOptions(inputs.Truststore); len(truststoreOpts) > 0 {
		inputs.JavaToolOpts = append(truststoreOpts, inputs.JavaToolOpts...)
	}

	trustInjection := trustInjectionOptionsFromStagedAssets(inputs)
	rewritten, err := rewriteDockerfileWithTrustBundle(original, trustInjection)
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return buildInputs{}, fmt.Errorf("rewrite dockerfile %s for trust injection: %w", dockerfileAbs, err)
	}
	if err := os.WriteFile(rewrittenPath, rewritten, 0o644); err != nil {
		_ = os.RemoveAll(stageDir)
		return buildInputs{}, fmt.Errorf("write rewritten dockerfile %s: %w", rewrittenPath, err)
	}

	inputs.DockerfileDir = stageDir
	inputs.DockerfileName = filepath.Base(rewrittenPath)
	inputs.ExtraLocals = append(inputs.ExtraLocals, bboxTrustContextName+"="+stageDir)
	inputs.FrontendOpts = append(inputs.FrontendOpts, "context:"+bboxTrustContextName+"=local:"+bboxTrustContextName)
	inputs.CleanupPaths = append(inputs.CleanupPaths, stageDir)
	return inputs, nil
}

func trustInjectionOptionsFromStagedAssets(inputs buildInputs) trustInjectionOptions {
	opts := trustInjectionOptions{}
	if strings.TrimSpace(inputs.TrustBundle) != "" {
		if _, err := os.Stat(inputs.TrustBundle); err == nil {
			opts.pemPath = injectedTrustBundlePrimaryPath
		}
	}
	if strings.TrimSpace(inputs.Truststore.Path) != "" &&
		strings.TrimSpace(inputs.Truststore.Type) != "" &&
		strings.TrimSpace(inputs.Truststore.Password) != "" {
		if _, err := os.Stat(inputs.Truststore.Path); err == nil {
			opts.javaTruststorePath = injectedJavaTruststorePath
		}
	}
	if len(inputs.JavaToolOpts) > 0 {
		opts.javaToolOptions = append(opts.javaToolOptions, inputs.JavaToolOpts...)
	}
	if strings.TrimSpace(inputs.MavenSettings) != "" {
		if _, err := os.Stat(inputs.MavenSettings); err == nil {
			opts.mavenSettingsPath = injectedMavenSettingsPath
		}
	}
	return opts
}

func resolveTrustBundlePath(env []string) (string, bool) {
	if value, ok := lookupEnvValue(env, bboxTrustBundleEnvKey); ok {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", false
		}
		if _, err := os.Stat(value); err == nil {
			return value, true
		}
		return "", false
	}

	const defaultTrustBundlePath = "/etc/ssl/certs/ca-certificates.crt"
	if _, err := os.Stat(defaultTrustBundlePath); err == nil {
		return defaultTrustBundlePath, true
	}
	return "", false
}

func cleanupPaths(paths []string) {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		_ = os.RemoveAll(path)
	}
}
