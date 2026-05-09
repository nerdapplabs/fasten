// Go smoke: register, init, LogInfo (sys), Emit (audit) with PII detail.
package main

import (
	"context"
	"log"

	fasten "github.com/nerdapplabs/fasten/go"
)

func main() {
	if err := fasten.Register("user", map[fasten.Code]fasten.Meta{
		"USER_CREATED": {
			ID: "USER_CREATED", Domain: "user", Category: "account",
			Action: "create", Severity: fasten.SevInfo,
			Description: "New user account created", Emitter: "auth-service",
			RetentionClass: fasten.RetentionLong,
		},
	}); err != nil {
		log.Fatal(err)
	}

	if err := fasten.Init(fasten.Config{
		ServiceID: "itest-go", NodeID: "host-itest",
	}); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// 1. sys row
	fasten.LogInfo(ctx, "startup_ok", "lang", "go")

	// 2. audit row with PII detail — Emit() applies RedactDetail before
	//    writing to stdout / inserting into store.
	if _, err := fasten.Emit(ctx, "USER_CREATED",
		fasten.Target("u-42"),
		fasten.Actor("admin", "user"),
		fasten.WithDetail(map[string]any{
			"email":          "alice@acme.com",
			"api_key":        "sk-secret-abc",
			"customer_token": "tok-substring-test", // substring match on 'token'
			"nested":         map[string]any{"token": "xyz", "preserved": "ok"},
		}),
	); err != nil {
		log.Fatal(err)
	}
}
