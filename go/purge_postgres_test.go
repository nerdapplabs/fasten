//go:build integration

package fasten

import "testing"

func TestPurgePostgres(t *testing.T) {
	runPurgeCases(t, func(t *testing.T) purgeStore {
		db := pgDB(t)
		table := uniqueTable("purge")
		t.Cleanup(func() { dropTable(t, db, table) })
		s, err := NewPostgresStore(db, table)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
