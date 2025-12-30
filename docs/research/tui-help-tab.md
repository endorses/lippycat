# TUI Help Tab - Research

## Overview

This document researches adding a Help tab to the TUI that displays embedded markdown documentation with search functionality. The Help tab would provide in-app access to:

1. TUI keybindings and navigation
2. CLI command reference (man page equivalent)
3. Common workflows and troubleshooting

## Goals

- **Self-contained**: Help embedded at build time via `go:embed`
- **Searchable**: Users can search within help content
- **Rendered**: Markdown rendered nicely (headers, bold, code blocks)
- **Discoverable**: Accessible via tab navigation and `?` shortcut

## Current TUI Architecture

### Tab System

**Location:** `internal/pkg/tui/components/tabs.go`

Tabs are managed as a simple array with an active index:

```go
type Tabs struct {
    tabs   []Tab
    active int
    width  int
    theme  themes.Theme
}

type Tab struct {
    Label string
    Icon  string
}
```

**Current tabs (4):**
| Index | Label | Icon | Purpose |
|-------|-------|------|---------|
| 0 | Live Capture | 📡 | Packet list / calls view |
| 1 | Nodes | 🔗 | Remote node management |
| 2 | Statistics | 📊 | Aggregated statistics |
| 3 | Settings | 🔧 | Configuration |

Tab switching uses modulo arithmetic in `keyboard_navigation.go`:
- `Tab` / `Shift+Tab` - Next/previous
- `Alt+1` through `Alt+4` - Direct jump

### Viewport Usage Pattern

The project uses `github.com/charmbracelet/bubbles/viewport` for scrollable content. Established pattern from `StatisticsView` and `DetailsPanel`:

```go
type SomeView struct {
    viewport viewport.Model
    width    int
    height   int
    theme    themes.Theme
    ready    bool
}

func (v *SomeView) SetSize(width, height int) {
    if !v.ready {
        v.viewport = viewport.New(width, height)
        v.ready = true
    } else {
        v.viewport.Width = width
        v.viewport.Height = height
    }
}

func (v *SomeView) Update(msg tea.Msg) tea.Cmd {
    var cmd tea.Cmd
    v.viewport, cmd = v.viewport.Update(msg)
    return cmd
}

func (v *SomeView) View() string {
    return borderStyle.Render(v.viewport.View())
}
```

### View Rendering

**Location:** `internal/pkg/tui/view_renderer.go`

Content is routed by active tab:

```go
switch m.uiState.Tabs.GetActive() {
case 0: mainContent = m.renderCaptureTab(contentHeight)
case 1: mainContent = m.uiState.NodesView.View()
case 2: mainContent = m.uiState.StatisticsView.View()
case 3: mainContent = m.uiState.SettingsView.View()
// case 4: mainContent = m.uiState.HelpView.View()
}
```

### Footer Keybindings

**Location:** `internal/pkg/tui/components/footer.go`

Footer displays context-aware keybindings per tab:

```go
func (f *Footer) getTabKeybinds(tabIndex int) []TabKeybind {
    switch tabIndex {
    case 0: return []TabKeybind{{Key: "/", Description: "filter"}, ...}
    // etc.
    }
}
```

## Markdown Rendering Library

### Glamour

[Glamour](https://github.com/charmbracelet/glamour) is Charmbracelet's markdown rendering library, designed to work with Lipgloss and Bubbletea.

**Key features:**
- Stylesheet-based rendering (dark/light/auto themes)
- ANSI color support (TrueColor, ANSI256, ANSI)
- Code block syntax highlighting via Chroma
- Emoji rendering
- Table support

**Basic usage:**

```go
import "github.com/charmbracelet/glamour"

out, err := glamour.Render(markdownContent, "dark")
// or with auto-detection:
out, err := glamour.RenderWithEnvironmentConfig(markdownContent)
```

**Integration with viewport:**

```go
rendered, _ := glamour.Render(markdown, "dark")
v.viewport.SetContent(rendered)
```

**Considerations:**
- Adds dependency: `github.com/charmbracelet/glamour`
- Transitive deps: goldmark, chroma (syntax highlighting)
- Binary size impact: ~2-3 MB (rough estimate)
- Already using Charmbracelet ecosystem (lipgloss, bubbletea, bubbles)

## Content Embedding

### go:embed Approach

```go
import "embed"

//go:embed help/*.md
var helpFS embed.FS

func loadHelp(name string) (string, error) {
    data, err := helpFS.ReadFile("help/" + name + ".md")
    return string(data), err
}
```

**File structure:**
```
internal/pkg/tui/
├── help/
│   ├── keybindings.md
│   ├── commands.md
│   ├── workflows.md
│   └── troubleshooting.md
├── components/
│   └── helpview.go
```

**Advantages:**
- Single binary, no external files
- Version-consistent documentation
- No filesystem access required

**Disadvantages:**
- Increases binary size (proportional to doc size)
- Requires rebuild to update docs

### Content Size Estimate

| Section | Estimated Size |
|---------|---------------|
| Keybindings | ~3 KB |
| CLI Commands (28 commands) | ~25 KB |
| Workflows | ~5 KB |
| Troubleshooting | ~3 KB |
| **Total** | ~36 KB |

Compressed in binary: ~15-20 KB additional size (negligible).

## Search Implementation

### Approach A: Simple Substring Search

```go
type HelpView struct {
    viewport    viewport.Model
    content     string           // Full rendered content
    rawContent  string           // Unrendered markdown
    searchQuery string
    searchMode  bool
    matches     []int            // Line numbers with matches
    currentMatch int
}

func (h *HelpView) search(query string) {
    h.matches = nil
    lines := strings.Split(h.rawContent, "\n")
    for i, line := range lines {
        if strings.Contains(strings.ToLower(line), strings.ToLower(query)) {
            h.matches = append(h.matches, i)
        }
    }
    if len(h.matches) > 0 {
        h.jumpToMatch(0)
    }
}

func (h *HelpView) jumpToMatch(index int) {
    h.currentMatch = index
    h.viewport.SetYOffset(h.matches[index])
}
```

**Keybindings:**
| Key | Action |
|-----|--------|
| `/` | Enter search mode |
| `Enter` | Execute search |
| `n` | Next match |
| `N` | Previous match |
| `Esc` | Exit search mode |

### Approach B: Fuzzy Search

Use `github.com/sahilm/fuzzy` for fuzzy matching:

```go
import "github.com/sahilm/fuzzy"

matches := fuzzy.Find(query, lines)
for _, match := range matches {
    h.matches = append(h.matches, match.Index)
}
```

**Trade-offs:**
- More forgiving for typos
- Additional dependency
- May return unexpected matches

**Recommendation:** Start with Approach A (simple substring). Fuzzy can be added later if needed.

## Help Content Structure

### Proposed Sections

#### 1. Keybindings (`keybindings.md`)

```markdown
# Keybindings

## Global
| Key | Action |
|-----|--------|
| Tab | Next tab |
| Shift+Tab | Previous tab |
| Alt+1-5 | Jump to tab |
| ? | Help |
| q | Quit |

## Capture Tab
| Key | Action |
|-----|--------|
| / | Filter packets |
| d | Toggle details panel |
| w | Save to PCAP |
| Space | Pause/resume capture |
...
```

#### 2. Commands (`commands.md`)

```markdown
# CLI Commands

## sniff
Capture packets from interface or file.

### Usage
lc sniff [flags]
lc sniff voip [flags]

### Flags
| Flag | Description | Default |
|------|-------------|---------|
| -i, --interface | Interface to monitor | any |
| -f, --filter | BPF filter | |
| -r, --read-file | Read from PCAP | |
...

## tap
Standalone capture with processor capabilities.
...
```

#### 3. Workflows (`workflows.md`)

```markdown
# Common Workflows

## Capture VoIP Traffic
1. Start capture: `sudo lc sniff voip -i eth0 --sipuser alice`
2. Make a call
3. Press `Ctrl+C` to stop

## Distributed Capture
1. Start processor: `lc process --listen :50051`
2. Start hunter: `sudo lc hunt --processor localhost:50051`
3. Monitor: `lc watch remote --nodes-file nodes.yaml`
...
```

### Navigation

Help sections could be:
- **Single document**: One long scrollable document with sections
- **Multiple documents**: Tab through sections within help tab
- **Searchable index**: Topic-based navigation

**Recommendation:** Start with single document. Split later if it grows too large.

## CLI Commands Inventory

Commands that need help documentation (28 total):

### Main Commands (11)
| Command | Description |
|---------|-------------|
| `sniff` | CLI packet capture |
| `sniff voip` | VoIP capture with SIP/RTP |
| `tap` | Standalone capture with processor |
| `tap voip` | VoIP tap with per-call PCAP |
| `watch` | TUI monitoring (default: live) |
| `watch live` | Live capture TUI |
| `watch file` | PCAP file analysis TUI |
| `watch remote` | Remote node monitoring |
| `hunt` | Hunter node (edge capture) |
| `hunt voip` | VoIP hunter with buffering |
| `process` | Processor node |

### Utility Commands (10)
| Command | Description |
|---------|-------------|
| `list` | List resources |
| `list interfaces` | List network interfaces |
| `show` | Display diagnostics |
| `show health` | TCP assembler health |
| `show metrics` | TCP metrics |
| `show alerts` | Active alerts |
| `show buffers` | Buffer statistics |
| `show streams` | Stream metrics |
| `show config` | Configuration |
| `show summary` | System summary |

### Filter Commands (7)
| Command | Description |
|---------|-------------|
| `set filter` | Create/update filter |
| `rm filter` | Remove filter |
| `list filters` | List remote filters |
| `show filter` | Show filter details |

## Implementation Components

### New Files

| File | Purpose |
|------|---------|
| `internal/pkg/tui/components/helpview.go` | Help view component |
| `internal/pkg/tui/help/keybindings.md` | Keybinding reference |
| `internal/pkg/tui/help/commands.md` | CLI command reference |
| `internal/pkg/tui/help/workflows.md` | Common workflows |

### Modified Files

| File | Changes |
|------|---------|
| `internal/pkg/tui/store/ui_state.go` | Add `HelpView` field |
| `internal/pkg/tui/components/tabs.go` | Add Help tab (index 4) |
| `internal/pkg/tui/keyboard_navigation.go` | Update `totalTabs` to 5, add `?` shortcut |
| `internal/pkg/tui/keyboard_handler.go` | Route `?` to help tab |
| `internal/pkg/tui/view_renderer.go` | Add case 4 for Help rendering |
| `internal/pkg/tui/update_handlers.go` | Add `SetSize` call for HelpView |
| `internal/pkg/tui/components/footer.go` | Add Help tab keybindings |
| `go.mod` | Add glamour dependency |

## Open Questions

1. **Search highlight**: Should matches be highlighted in the rendered output? (Requires post-processing rendered output)

2. **Section navigation**: Single document with scrolling, or multiple documents with section selector?

3. **Help icon**: What icon for Help tab? Candidates: `❓`, `📖`, `ℹ️`

4. **Global `?` shortcut**: Should `?` work from any tab, or only when not in an input mode?

5. **Dynamic content**: Should help show current keybindings based on active filters/modes, or static reference?

## Dependencies

| Dependency | Purpose | Impact |
|------------|---------|--------|
| `github.com/charmbracelet/glamour` | Markdown rendering | ~2-3 MB binary size |

Already using: `bubbletea`, `bubbles`, `lipgloss` (same ecosystem).

## References

- [Glamour GitHub](https://github.com/charmbracelet/glamour)
- [Glamour Go Docs](https://pkg.go.dev/github.com/charmbracelet/glamour)
- [Glow (CLI markdown viewer)](https://github.com/charmbracelet/glow) - Reference implementation
- `internal/pkg/tui/CLAUDE.md` - TUI architecture documentation
