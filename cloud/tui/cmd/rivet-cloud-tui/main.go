// rivet-cloud-tui — terminal UI for the rivet Cloud audit feed.
//
// v0.1 scaffold — Bubble Tea root model with a single live-feed view.
// Real-time row tailing via long-poll against /api/v1/audit/stream lands
// in v0.2.
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── styles ─────────────────────────────────────────────────────────────

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#3b82f6"))
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).BorderTop(true).BorderStyle(lipgloss.NormalBorder())
)

// ── model ──────────────────────────────────────────────────────────────

type model struct {
	rows   []string // placeholder — real rows are typed audit rows in v0.2
	filter string
	width  int
}

func initialModel() model {
	return model{
		rows:   []string{"(awaiting rows — connect with --endpoint to start tailing)"},
		filter: "",
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "/":
			// v0.2 — open filter input
		case "enter":
			// v0.2 — open inspect detail
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
	}
	return m, nil
}

func (m model) View() string {
	header := titleStyle.Render("rivet-cloud-tui  ·  live audit feed")
	body := ""
	for _, row := range m.rows {
		body += row + "\n"
	}
	footer := mutedStyle.Render("/ search   j/k navigate   enter inspect   q quit")

	return fmt.Sprintf("%s\n\n%s\n%s",
		header, body, statusStyle.Width(m.width).Render(footer))
}

// ── main ───────────────────────────────────────────────────────────────

func main() {
	if _, err := tea.NewProgram(initialModel(), tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
