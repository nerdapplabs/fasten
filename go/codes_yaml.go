package fasten

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Catalog YAML loader (P1-11).
//
// Optional feature — adopters who stay on programmatic Register() never
// touch this code path. yaml.v3 is a small dep (~150 KB); paid by every
// Go fasten install but only meaningfully imported when Load() is called.
//
// API:
//
//	fasten.Load("fleet.codes.yaml")    // initial load (returns error)
//	fasten.MustLoad("fleet.codes.yaml") // panics on error
//	fasten.Reload()                    // atomic + fault-tolerant
//
// Reload re-reads every previously-loaded path. If parsing or validation
// fails, the previous catalog stays active and the error is returned.
// Reload is NOT additive — codes removed from the yaml become unknown
// after the swap. Stored audit rows referencing them remain readable
// (the wire `code` field is a free string).
//
// Codes registered programmatically (via fasten.Register) are tracked
// separately and survive Reload.

var (
	yamlMu    sync.Mutex
	yamlPaths []string
	// yamlCodes records which codes came from yaml (vs. programmatic).
	// Reload uses this to drop codes the new yaml file no longer declares
	// while preserving programmatic registrations.
	yamlCodes = map[Code]bool{}
)

type yamlFile struct {
	Domain  string                   `yaml:"domain"`
	Emitter string                   `yaml:"emitter"`
	Codes   map[string]yamlCodeEntry `yaml:"codes"`
}

type yamlCodeEntry struct {
	Domain         string `yaml:"domain"`
	Category       string `yaml:"category"`
	Action         string `yaml:"action"`
	Severity       string `yaml:"severity"`
	Description    string `yaml:"description"`
	Emitter        string `yaml:"emitter"`
	RetentionClass string `yaml:"retention_class"`
	HighVolume     bool   `yaml:"high_volume"`
}

// Load reads a yaml catalog file into the registry.
//
// Errors raise loudly (return error) — designed for startup, restart-safe.
// Use Reload() to refresh later without restarting the process.
func Load(path string) error {
	fresh, err := buildFromYAMLPaths([]string{path})
	if err != nil {
		return err
	}

	yamlMu.Lock()
	defer yamlMu.Unlock()
	regMu.Lock()
	defer regMu.Unlock()

	// Reject collisions with programmatic registrations.
	for code := range fresh {
		if _, exists := _registry[code]; exists && !yamlCodes[code] {
			return fmt.Errorf(
				"fasten.Load: %s:%s — duplicate code (already registered programmatically)",
				path, code,
			)
		}
	}
	for code, meta := range fresh {
		_registry[code] = meta
		yamlCodes[code] = true
	}
	for _, p := range yamlPaths {
		if p == path {
			return nil // already tracked
		}
	}
	yamlPaths = append(yamlPaths, path)
	return nil
}

// MustLoad is like Load but panics on error. Convenient for init().
func MustLoad(path string) {
	if err := Load(path); err != nil {
		panic(err)
	}
}

// Reload re-reads every previously-loaded path and atomically swaps the registry.
//
// Atomic + fault-tolerant: parse + validate fully into a fresh map; any
// error returns without touching the live registry. On success, swap
// under a lock — concurrent Emit readers see either old or new, never
// partial state.
//
// Reload is NOT additive: codes removed from the yaml file become unknown
// (Emit raises). Programmatic Register() codes (not in any yaml file)
// survive the swap.
func Reload() error {
	yamlMu.Lock()
	paths := append([]string{}, yamlPaths...)
	yamlMu.Unlock()

	if len(paths) == 0 {
		return nil
	}

	fresh, err := buildFromYAMLPaths(paths)
	if err != nil {
		return err
	}

	regMu.Lock()
	defer regMu.Unlock()
	yamlMu.Lock()
	defer yamlMu.Unlock()

	// Preserve programmatic codes (not in current or previous yaml set).
	programmatic := map[Code]Meta{}
	for code, meta := range _registry {
		if !yamlCodes[code] {
			programmatic[code] = meta
		}
	}

	newRegistry := make(map[Code]Meta, len(programmatic)+len(fresh))
	for code, meta := range programmatic {
		newRegistry[code] = meta
	}
	for code, meta := range fresh {
		newRegistry[code] = meta
	}

	_registry = newRegistry
	yamlCodes = make(map[Code]bool, len(fresh))
	for code := range fresh {
		yamlCodes[code] = true
	}
	return nil
}

// buildFromYAMLPaths parses + validates every path; returns the fresh
// registry or the first error. Caller's live registry is untouched.
func buildFromYAMLPaths(paths []string) (map[Code]Meta, error) {
	fresh := map[Code]Meta{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("fasten: reading %s: %w", path, err)
		}
		var f yamlFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("fasten: parsing %s: %w", path, err)
		}
		if f.Domain == "" {
			return nil, fmt.Errorf("fasten: %s — top-level 'domain' is required", path)
		}
		for codeStr, raw := range f.Codes {
			if !codeKeyRe.MatchString(codeStr) {
				return nil, fmt.Errorf(
					"fasten: %s:%s — code key must be UPPER_SNAKE_CASE",
					path, codeStr,
				)
			}
			if _, ok := fresh[Code(codeStr)]; ok {
				return nil, fmt.Errorf("fasten: %s:%s — duplicate code in yaml", path, codeStr)
			}

			sev, err := parseSeverityYAML(raw.Severity)
			if err != nil {
				return nil, fmt.Errorf("fasten: %s:%s — %w", path, codeStr, err)
			}
			rc, err := parseRetentionYAML(raw.RetentionClass)
			if err != nil {
				return nil, fmt.Errorf("fasten: %s:%s — %w", path, codeStr, err)
			}
			if raw.Domain != "" && raw.Domain != f.Domain {
				return nil, fmt.Errorf(
					"fasten: %s:%s — domain=%q disagrees with file-level domain=%q",
					path, codeStr, raw.Domain, f.Domain,
				)
			}
			emitter := raw.Emitter
			if emitter == "" {
				emitter = f.Emitter
			}
			fresh[Code(codeStr)] = Meta{
				ID:             Code(codeStr),
				Domain:         Domain(f.Domain),
				Category:       raw.Category,
				Action:         raw.Action,
				Severity:       sev,
				Description:    raw.Description,
				Emitter:        emitter,
				RetentionClass: rc,
				HighVolume:     raw.HighVolume,
			}
		}
	}
	return fresh, nil
}

func parseSeverityYAML(s string) (Severity, error) {
	if s == "" {
		return SevInfo, nil
	}
	switch s {
	case "debug":
		return SevDebug, nil
	case "info":
		return SevInfo, nil
	case "warn":
		return SevWarn, nil
	case "error":
		return SevError, nil
	case "critical":
		return SevCritical, nil
	}
	return "", fmt.Errorf("severity=%q is not one of {debug,info,warn,error,critical}", s)
}

func parseRetentionYAML(s string) (RetentionClass, error) {
	if s == "" {
		return RetMedium, nil
	}
	switch s {
	case "short":
		return RetShort, nil
	case "medium":
		return RetMedium, nil
	case "long":
		return RetLong, nil
	}
	return "", fmt.Errorf("retention_class=%q is not one of {short,medium,long}", s)
}
