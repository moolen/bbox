package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moolen/bbox"
)

func parseCLIMountSpec(spec string) (bbox.Mount, error) {
	var cfg cliMountConfig
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "read-only" {
			cfg.ReadOnly = true
			continue
		}

		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return bbox.Mount{}, fmt.Errorf("invalid mount field %q in %q, want key=value", part, spec)
		}
		key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
		value = strings.TrimSpace(value)

		switch key {
		case "type":
			cfg.Type = value
		case "source":
			cfg.Source = value
		case "target":
			cfg.Target = value
		case "read_only":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return bbox.Mount{}, fmt.Errorf("invalid read_only value %q in %q", value, spec)
			}
			cfg.ReadOnly = parsed
		case "mode":
			parsed, err := strconv.ParseUint(value, 0, 32)
			if err != nil {
				return bbox.Mount{}, fmt.Errorf("invalid mode value %q in %q", value, spec)
			}
			cfg.Mode = uint32(parsed)
		default:
			return bbox.Mount{}, fmt.Errorf("unknown mount key %q in %q", key, spec)
		}
	}

	return toBBoxMount(cfg)
}

func resolveConfigMount(m cliMountConfig, baseDir string) cliMountConfig {
	resolved := m
	if strings.EqualFold(strings.TrimSpace(m.Type), string(bbox.MountTypeBind)) {
		resolved.Source = resolveConfigPath(m.Source, baseDir)
	}
	resolved.Target = resolveConfigPath(m.Target, baseDir)
	return resolved
}

func toBBoxMount(m cliMountConfig) (bbox.Mount, error) {
	mountType := strings.ToLower(strings.TrimSpace(m.Type))
	target := strings.TrimSpace(m.Target)
	source := strings.TrimSpace(m.Source)
	mode := m.Mode

	switch mountType {
	case string(bbox.MountTypeBind):
		if target == "" {
			return bbox.Mount{}, fmt.Errorf("bind mount target is required")
		}
		if source == "" {
			return bbox.Mount{}, fmt.Errorf("bind mount source is required")
		}
		if !filepath.IsAbs(target) {
			return bbox.Mount{}, fmt.Errorf("bind mount target %q must be absolute", target)
		}
		if !filepath.IsAbs(source) {
			return bbox.Mount{}, fmt.Errorf("bind mount source %q must be absolute", source)
		}
		if mode != 0 {
			return bbox.Mount{}, fmt.Errorf("bind mount mode is not supported")
		}
		return bbox.Mount{
			Type:     bbox.MountTypeBind,
			Source:   filepath.Clean(source),
			Target:   filepath.Clean(target),
			ReadOnly: m.ReadOnly,
		}, nil
	case string(bbox.MountTypeEmptyDir):
		if target == "" {
			return bbox.Mount{}, fmt.Errorf("empty_dir mount target is required")
		}
		if source != "" {
			return bbox.Mount{}, fmt.Errorf("empty_dir mount must not set source")
		}
		if !filepath.IsAbs(target) {
			return bbox.Mount{}, fmt.Errorf("empty_dir mount target %q must be absolute", target)
		}
		if mode == 0 {
			mode = 0o755
		}
		return bbox.Mount{
			Type:   bbox.MountTypeEmptyDir,
			Target: filepath.Clean(target),
			Mode:   mode,
		}, nil
	default:
		return bbox.Mount{}, fmt.Errorf("unknown mount type %q", m.Type)
	}
}

func toCLIMountConfig(m bbox.Mount) cliMountConfig {
	return cliMountConfig{
		Type:     string(m.Type),
		Source:   m.Source,
		Target:   m.Target,
		ReadOnly: m.ReadOnly,
		Mode:     m.Mode,
	}
}
