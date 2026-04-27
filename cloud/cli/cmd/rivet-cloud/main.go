// rivet-cloud — CLI for the rivet Cloud audit data plane.
//
// v0.1 scaffold: subcommand structure + flag wiring + help text.
// Real subcommand bodies land in v0.2 once the rivet Cloud HTTP API
// stabilises.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.1.0-alpha"

func main() {
	root := &cobra.Command{
		Use:     "rivet-cloud",
		Short:   "Query and export audit data from rivet Cloud",
		Version: version,
	}

	root.AddCommand(loginCmd())
	root.AddCommand(queryCmd())
	root.AddCommand(exportCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(whoamiCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ── login ────────────────────────────────────────────────────────────────

func loginCmd() *cobra.Command {
	var endpoint string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate to rivet Cloud (OIDC device flow)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented("login (OIDC device flow against " + endpoint + ")")
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "https://api.rivet-cloud.dev", "rivet Cloud API base URL")
	return cmd
}

// ── query ────────────────────────────────────────────────────────────────

func queryCmd() *cobra.Command {
	var requestID, code, domain, siteID, since, until string
	var limit int
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query audit rows",
		Example: `  rivet-cloud query --request-id a1b2c3d4
  rivet-cloud query --code USER_CREATED --since 7d
  rivet-cloud query --site-id site-A --domain user --limit 50`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented("query (filters compose to /api/v1/audit/query)")
		},
	}
	cmd.Flags().StringVar(&requestID, "request-id", "", "filter by correlation id (cross-service trail)")
	cmd.Flags().StringVar(&code, "code", "", "filter by audit code (e.g. USER_CREATED)")
	cmd.Flags().StringVar(&domain, "domain", "", "filter by domain (user / commerce / agent / …)")
	cmd.Flags().StringVar(&siteID, "site-id", "", "filter by site (multi-tenant scope)")
	cmd.Flags().StringVar(&since, "since", "", "lower time bound (RFC3339 or relative: 7d, 24h, 30m)")
	cmd.Flags().StringVar(&until, "until", "", "upper time bound")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows to return")
	return cmd
}

// ── export ───────────────────────────────────────────────────────────────

func exportCmd() *cobra.Command {
	var siteID, format, output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Bulk-export audit rows to file",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented("export (streaming JSON / CSV / Parquet to " + output + ")")
		},
	}
	cmd.Flags().StringVar(&siteID, "site-id", "", "site scope (required for multi-tenant tenants)")
	cmd.Flags().StringVar(&format, "format", "json", "output format: json | csv | parquet")
	cmd.Flags().StringVarP(&output, "output", "o", "-", "output path (- for stdout)")
	return cmd
}

// ── report ───────────────────────────────────────────────────────────────

func reportCmd() *cobra.Command {
	var regulation, month, output string
	cmd := &cobra.Command{
		Use:     "report",
		Short:   "Generate a signed compliance report (v1+)",
		Example: `  rivet-cloud report --regulation hipaa --month 2026-04`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented("report (HIPAA / SOC2 / GDPR / GMP / ISO 26262 — v1)")
		},
	}
	cmd.Flags().StringVar(&regulation, "regulation", "", "hipaa | soc2 | gdpr | iso26262 | gmp | fssc | sox")
	cmd.Flags().StringVar(&month, "month", "", "reporting period — YYYY-MM")
	cmd.Flags().StringVarP(&output, "output", "o", "report.pdf", "output PDF path")
	return cmd
}

// ── whoami ───────────────────────────────────────────────────────────────

func whoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current authenticated tenant + token expiry",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented("whoami (read ~/.rivet-cloud/token.json)")
		},
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

func errNotImplemented(what string) error {
	return fmt.Errorf("not implemented in v0.1 scaffold: %s", what)
}
