// Reader server example: mounts /api/v1/logs behind the bundled
// bearer-token middleware and a tenant-scope hook.
//
// What it shows:
//
//   - fasten.NewReader with WithTenantScope and EnforceTenantIsolation,
//     so ?tenant_id=other can't read another tenant's rows.
//   - fasten.RequireBearer as a simple auth gate reading FASTEN_READER_TOKEN,
//     for callers without their own auth stack.
//   - The tenant-scope hook runs after the bearer check, so an
//     unauthenticated caller never reaches it.
//
// Run:
//
//	cd go/examples/reader
//	FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 \
//	FASTEN_READER_TOKEN=s3cret \
//	  go run server.go
//
//	# unauthenticated: 401
//	curl -i http://localhost:8080/api/v1/logs/audit
//
//	# tenant-a's rows only, regardless of ?tenant_id=
//	curl -H 'Authorization: Bearer s3cret' \
//	     -H 'X-Tenant: tenant-a' \
//	     'http://localhost:8080/api/v1/logs/audit?tenant_id=tenant-b'
package main

import (
	"database/sql"
	"log"
	"net/http"

	fasten "github.com/nerdapplabs/fasten/go"
	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "./demo-audit.db")
	if err != nil {
		log.Fatal(err)
	}
	store, err := fasten.NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		log.Fatal(err)
	}
	if err := fasten.Init(fasten.Config{AuditStore: store}); err != nil {
		log.Fatal(err)
	}

	// For the demo the tenant comes from X-Tenant. A real deployment would
	// take it from the decoded JWT or session.
	tenantFromHeader := func(r *http.Request) (string, bool) {
		t := r.Header.Get("X-Tenant")
		if t == "" {
			return "", false
		}
		return t, true
	}

	reader := fasten.NewReader(
		fasten.WithTenantScope(tenantFromHeader),
		fasten.EnforceTenantIsolation(),
	)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/logs/", http.StripPrefix(
		"/api/v1/logs",
		fasten.RequireBearer("FASTEN_READER_TOKEN")(reader),
	))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
