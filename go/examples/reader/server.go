// Reader server example — mounts /api/v1/logs behind the bundled
// bearer-token middleware and a tenant-scope hook.
//
// What it shows:
//
//   - fasten.NewReader wired with WithTenantScope + EnforceTenantIsolation
//     so cross-tenant reads (?tenant_id=other) are impossible even when
//     the caller manipulates the query string (P1-44).
//   - fasten.RequireBearer as a drop-in auth gate reading FASTEN_READER_TOKEN
//     — the opinionated default so a caller without an auth stack still
//     gets a real gate rather than shipping public /audit (P1-45).
//   - The tenant-scope hook is called AFTER the bearer check, so an
//     unauthenticated caller never reaches the scope resolver.
//
// Run:
//
//	cd go/examples/reader
//	FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 \
//	FASTEN_READER_TOKEN=s3cret \
//	  go run server.go
//
//	# unauthenticated → 401
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

	// tenantFromHeader is the opinionated default for this demo: the
	// authenticated caller carries their tenant in X-Tenant. In real
	// deployments this comes from the JWT / session decoded upstream
	// (before RequireBearer, or inside a chained middleware).
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
