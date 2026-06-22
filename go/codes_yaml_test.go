package fasten

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fleetYAML = `
domain: fleet
emitter: fleet-service
codes:
  FLEET_NODE_REGISTERED:
    category: node.lifecycle
    action: registered
    severity: info
    description: Node claimed and registered
  FLEET_DEPLOY_FAILED:
    category: deploy
    action: failed
    severity: error
    retention_class: long
    description: Deployment failed on node
`

// resetYAMLState clears yaml-loader state between tests.
func resetYAMLState(t *testing.T) {
	t.Helper()
	yamlMu.Lock()
	yamlPaths = nil
	yamlCodes = map[Code]bool{}
	yamlMu.Unlock()
	clearBothRegistries()
	t.Cleanup(func() {
		yamlMu.Lock()
		yamlPaths = nil
		yamlCodes = map[Code]bool{}
		yamlMu.Unlock()
		clearBothRegistries()
	})
}

func writeYAML(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.codes.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writeYAML: %v", err)
	}
	return path
}

func TestLoad_RoundTrip(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, fleetYAML)
	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	m, ok := metaOf("FLEET_NODE_REGISTERED")
	if !ok {
		t.Fatal("FLEET_NODE_REGISTERED not in registry")
	}
	if m.Domain != "fleet" || m.Action != "registered" || m.Severity != SevInfo {
		t.Fatalf("unexpected meta: %+v", m)
	}
	m2, _ := metaOf("FLEET_DEPLOY_FAILED")
	if m2.Severity != SevError || m2.RetentionClass != RetLong {
		t.Fatalf("unexpected meta: %+v", m2)
	}
}

func TestLoad_InvalidSeverity(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, `
domain: x
codes:
  BAD_CODE:
    severity: huge
`)
	err := Load(path)
	if err == nil || !strings.Contains(err.Error(), `severity="huge"`) {
		t.Fatalf("expected severity error, got %v", err)
	}
}

func TestLoad_LowercaseKey(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, `
domain: x
codes:
  lowercase_bad:
    severity: info
`)
	err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "UPPER_SNAKE_CASE") {
		t.Fatalf("expected key-shape error, got %v", err)
	}
}

func TestReload_RemovesCodes(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, fleetYAML)
	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := metaOf("FLEET_DEPLOY_FAILED"); !ok {
		t.Fatal("FLEET_DEPLOY_FAILED missing pre-reload")
	}

	// Rewrite the file: drop FLEET_DEPLOY_FAILED.
	trimmed := `
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    category: node.lifecycle
    action: registered
    severity: info
    description: x
`
	if err := os.WriteFile(path, []byte(trimmed), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := metaOf("FLEET_DEPLOY_FAILED"); ok {
		t.Fatal("FLEET_DEPLOY_FAILED should be gone after reload")
	}
	if _, ok := metaOf("FLEET_NODE_REGISTERED"); !ok {
		t.Fatal("FLEET_NODE_REGISTERED missing after reload")
	}
}

func TestReload_FaultTolerant(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, fleetYAML)
	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Snapshot known-good registry contents
	regMu.RLock()
	snapshot := make(map[Code]Meta, len(_registry))
	for k, v := range _registry {
		snapshot[k] = v
	}
	regMu.RUnlock()

	// Corrupt the yaml — invalid severity
	if err := os.WriteFile(path, []byte(`
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    severity: completely_bogus
`), 0o644); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}
	if err := Reload(); err == nil {
		t.Fatal("expected reload to error on bad severity")
	}

	// Live registry must be unchanged.
	regMu.RLock()
	defer regMu.RUnlock()
	if len(_registry) != len(snapshot) {
		t.Fatalf("registry mutated by failed reload: before=%d after=%d", len(snapshot), len(_registry))
	}
	for k, v := range snapshot {
		if got, ok := _registry[k]; !ok || got.Severity != v.Severity {
			t.Fatalf("registry mutated by failed reload: key=%s", k)
		}
	}
}

func TestReload_PreservesProgrammatic(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, fleetYAML)
	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Add a programmatic code (different domain, not in yaml)
	if err := Register("extra", map[Code]Meta{
		"EXTRA_PROG_CODE": {Domain: "extra", Category: "x", Action: "x",
			Severity: SevInfo, Description: "x", Emitter: "t"},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Modify yaml + reload
	if err := os.WriteFile(path, []byte(`
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    severity: info
    description: x
`), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if _, ok := metaOf("EXTRA_PROG_CODE"); !ok {
		t.Fatal("programmatic EXTRA_PROG_CODE lost across reload")
	}
	if _, ok := metaOf("FLEET_NODE_REGISTERED"); !ok {
		t.Fatal("FLEET_NODE_REGISTERED lost across reload")
	}
	if _, ok := metaOf("FLEET_DEPLOY_FAILED"); ok {
		t.Fatal("FLEET_DEPLOY_FAILED should be removed by reload")
	}
}

func TestReload_NoOpWithoutLoad(t *testing.T) {
	resetYAMLState(t)
	if err := Reload(); err != nil {
		t.Fatalf("Reload with no prior Load should be no-op, got %v", err)
	}
}
