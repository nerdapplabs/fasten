// Minimal net/http service wired to fasten.
//
// What it shows in ~70 lines:
//
//   - fasten.Init() reading env vars (FASTEN_SERVICE_ID, FASTEN_NODE_ID).
//   - One audit code (USER_CREATED) registered at startup.
//   - fasten.RequestID middleware mints / honours X-Request-ID per
//     request and stashes it in the context for downstream Emit / Log.
//   - POST /users emits an audit row with the in-context request_id.
//   - GET  /users/<id> emits a read-side audit row + a structured sys log.
//   - On Ctrl-C, fasten.Flush() drains pending audit rows.
//
// Run:
//
//	cd go/examples
//	FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 go run server.go
//	curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
//	curl http://localhost:8080/users/u-42
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	fasten "github.com/nerdapplabs/fasten-go"
	_ "modernc.org/sqlite"
)

func main() {
	fasten.MustRegister("user", map[fasten.Code]fasten.Meta{
		"USER_CREATED": {
			Domain: "user", Category: "account", Action: "create",
			Severity: fasten.SevInfo, Description: "New user account",
			Emitter: "demo-svc", RetentionClass: fasten.RetLong,
		},
		"USER_VIEWED": {
			Domain: "user", Category: "account", Action: "view",
			Severity: fasten.SevInfo, Description: "User profile read",
			Emitter: "demo-svc", RetentionClass: fasten.RetShort,
		},
	})

	db, err := sql.Open("sqlite", "./demo-audit.db")
	if err != nil {
		log.Fatal(err)
	}
	store, err := fasten.NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		log.Fatal(err)
	}
	if err := fasten.Init(fasten.Config{
		AuditStore: store,
	}); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/users", createUser)
	mux.HandleFunc("/users/", readUser)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})

	srv := &http.Server{Addr: ":8080", Handler: fasten.RequestID(mux)}

	// Graceful shutdown: drain pending audit rows before exit.
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Println("shutting down — flushing audit queue")
		fasten.Flush(5 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Println("listening on :8080")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	userID := "u-" + body.Email[:min(4, len(body.Email))]
	fasten.Emit(r.Context(), "USER_CREATED",
		fasten.Target(userID),
		fasten.Actor("admin", "user"),
		fasten.WithDetail(map[string]any{"email": body.Email}),
	)
	json.NewEncoder(w).Encode(map[string]string{"user_id": userID})
}

func readUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimPrefix(r.URL.Path, "/users/")
	fasten.Emit(r.Context(), "USER_VIEWED",
		fasten.Target(userID),
		fasten.Actor("admin", "user"),
	)
	fasten.LogInfo(r.Context(), "user_lookup", "user_id", userID)
	json.NewEncoder(w).Encode(map[string]any{"user_id": userID, "exists": true})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
