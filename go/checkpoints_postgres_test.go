//go:build integration

package fasten

import (
	"database/sql"
	"testing"
)

func TestCheckpointsPostgres(t *testing.T) {
	runCheckpointStoreCases(t, func(t *testing.T) (cpStore, *sql.DB, string) {
		db := pgDB(t)
		table := uniqueTable("checkpoints")
		t.Cleanup(func() { dropTable(t, db, table) })
		s, err := NewPostgresStore(db, table)
		if err != nil {
			t.Fatal(err)
		}
		return s, db, table
	})
}
