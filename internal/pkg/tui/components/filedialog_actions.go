//go:build tui || all

package components

import (
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// ModalOptions describes both painting and hit targets in content coordinates.
func (fd *FileDialog) ModalOptions() ModalRenderOptions {
	if fd.overwrite.IsActive() {
		return fd.overwrite.ModalOptions()
	}
	opts := ModalRenderOptions{ID: "file-dialog", Title: fd.title(), Width: fd.width, Height: fd.height, Theme: fd.theme, State: &fd.modalState}
	opts.Actions = fd.actions()
	width := ModalContentWidth(opts)
	var lines []string
	var targets []ModalTarget
	add := func(id, text string, focus bool) {
		y := len(lines)
		lines = append(lines, ansi.Truncate(text, width, "…"))
		if id != "" {
			targets = append(targets, ModalTarget{ID: id, Bounds: image.Rect(0, y, width, y+1), Focusable: focus})
		}
	}
	crumbs, crumbTargets := fd.breadcrumbs(width)
	add("", crumbs, false)
	targets = append(targets, crumbTargets...)
	add("filter", "Filter: "+fd.filterInput.View(), true)
	listY := len(lines)
	targets = append(targets, ModalTarget{ID: "files", Bounds: image.Rect(0, listY, width, listY+fd.listHeight), Focusable: true})
	for row := 0; row < fd.listHeight; row++ {
		index := fd.viewOffset + row
		if index >= len(fd.filteredFiles) {
			if row == 0 {
				add("", "No files found.", false)
			} else {
				add("", "", false)
			}
			continue
		}
		entry := fd.filteredFiles[index]
		name := entry.Name()
		if entry.IsDir() {
			name += string(os.PathSeparator)
		}
		prefix := "  "
		if index == fd.cursor {
			prefix = "> "
		}
		line := prefix + name
		if fd.showDetails {
			if info, err := entry.Info(); err == nil {
				line = fmt.Sprintf("%s%-16s %03o %7s %s", prefix, info.ModTime().Format("2006-01-02 15:04"), info.Mode().Perm(), formatSize(info.Size()), name)
			}
		}
		line = ansi.Truncate(line, width, "…")
		if index == fd.cursor {
			line = lipgloss.NewStyle().Foreground(fd.theme.Background).Background(fd.theme.SelectionBg).Render(line)
		}
		add("entry:"+strconv.Itoa(index), line, false)
	}
	if fd.config.Type == FileDialogTypeSave {
		add("filename", "Filename: "+fd.filename.View(), true)
	}
	if fd.mode == ModeCreateFolder {
		add("folder", "New folder: "+fd.folderInput.View(), true)
	}
	if fd.errorMessage != "" {
		add("", "⚠ "+fd.errorMessage, false)
	}
	// Preserve the familiar save-mode Tab path: list -> filename -> search.
	ordered := make([]ModalTarget, 0, len(targets))
	for _, id := range []string{"files", "filename", "filter", "folder"} {
		for _, target := range targets {
			if target.ID == id {
				ordered = append(ordered, target)
			}
		}
	}
	for _, target := range targets {
		if !target.Focusable {
			ordered = append(ordered, target)
		}
	}
	opts.Targets = ordered
	opts.Content = strings.Join(lines, "\n")
	opts.Footer = "↑/↓ Navigate · ←/→ Change directory · Tab Focus"
	return opts
}

func (fd *FileDialog) actions() []ModalAction {
	_, selected := fd.getCurrentEntry()
	primary := ModalAction{ID: "accept", Label: "Open", Kind: ButtonPrimary, Disabled: !selected}
	if fd.mode == ModeNavigation {
		primary.Shortcut = "Enter"
	}
	if fd.mode != ModeNavigation {
		primary.Shortcut = ""
	}
	if fd.config.Type == FileDialogTypeSave {
		primary.Label = "Save"
		if fd.mode == ModeFilename {
			primary.Shortcut = "Enter"
		}
		primary.Disabled = fd.validateFilename() != nil
		if fd.mode != ModeFilename {
			primary.Shortcut = ""
		}
	}
	folderShortcut, detailsShortcut := "", ""
	if fd.mode == ModeNavigation {
		folderShortcut = "n"
		detailsShortcut = "d"
	}
	detailsLabel := "Show details"
	if fd.showDetails {
		detailsLabel = "Hide details"
	}
	actions := []ModalAction{primary,
		{ID: "up", Label: "Up", Disabled: filepath.Dir(fd.currentDir) == fd.currentDir},
		{ID: "new-folder", Label: "New folder", Shortcut: folderShortcut},
		{ID: "details", Label: detailsLabel, Shortcut: detailsShortcut},
	}
	if fd.mode == ModeFilter {
		actions = append(actions, ModalAction{ID: "apply-filter", Label: "Apply filter", Shortcut: "Enter"})
	}
	if fd.config.Type == FileDialogTypeSave && fd.packetMarks > 0 {
		actions = append(actions, ModalAction{ID: "clear-marks", Label: "Clear marks"})
	}
	if fd.filterInput.Value() != "" {
		actions = append(actions, ModalAction{ID: "clear-filter", Label: "Clear filter"})
	}
	if fd.mode == ModeCreateFolder {
		actions = append(actions, ModalAction{ID: "create-folder", Label: "Create folder", Shortcut: "Enter", Kind: ButtonPrimary, Disabled: strings.TrimSpace(fd.folderInput.Value()) == ""})
	}
	if fd.mode != ModeNavigation {
		actions = append(actions, ModalAction{ID: "cancel-edit", Label: "Cancel edit", Shortcut: "Esc"})
	}
	actions = append(actions, ModalAction{ID: "cancel", Label: "Cancel", Shortcut: func() string {
		if fd.mode == ModeNavigation {
			return "Esc"
		}
		return ""
	}()})
	return actions
}

func (fd *FileDialog) breadcrumbs(width int) (string, []ModalTarget) {
	root := filepath.VolumeName(fd.currentDir) + string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(fd.currentDir, root), string(os.PathSeparator))
	labels := []string{root}
	paths := []string{root}
	path := root
	for _, part := range parts {
		if part != "" {
			path = filepath.Join(path, part)
			labels = append(labels, part)
			paths = append(paths, path)
		}
	}
	// Keep root and nearest ancestors in view; Up remains available for every omitted component.
	for len(labels) > 2 && ansi.StringWidth(strings.Join(labels, " › ")) > width {
		labels = append(labels[:1], labels[2:]...)
		paths = append(paths[:1], paths[2:]...)
		if labels[0] == root {
			labels[0] = root + " …"
		}
	}
	var targets []ModalTarget
	x := 0
	for i, label := range labels {
		if i > 0 {
			x += 3
		}
		w := min(ansi.StringWidth(label), max(0, width-x))
		if w > 0 {
			targets = append(targets, ModalTarget{ID: "path:" + paths[i], Bounds: image.Rect(x, 0, x+w, 1)})
		}
		x += ansi.StringWidth(label)
	}
	return ansi.Truncate(strings.Join(labels, " › "), width, "…"), targets
}

func (fd *FileDialog) HandleModalFocus(id string) tea.Cmd {
	if fd.overwrite.IsActive() {
		return fd.overwrite.HandleModalFocus(id)
	}
	fd.filename.Blur()
	fd.filterInput.Blur()
	fd.folderInput.Blur()
	switch id {
	case "filename":
		fd.mode = ModeFilename
		return fd.filename.Focus()
	case "filter":
		fd.mode = ModeFilter
		return fd.filterInput.Focus()
	case "folder":
		fd.mode = ModeCreateFolder
		return fd.folderInput.Focus()
	case "files":
		fd.mode = ModeNavigation
	}
	return nil
}

func (fd *FileDialog) HandleModalAction(id string) tea.Cmd {
	defer fd.prepareLayout()
	if !strings.HasPrefix(id, "entry:") {
		fd.modalState.ResetClicks()
	}
	if fd.overwrite.IsActive() {
		return fd.mapOverwrite(fd.overwrite.HandleModalAction(id))
	}
	switch id {
	case "accept":
		if fd.config.Type == FileDialogTypeSave {
			return fd.acceptFile()
		}
		return fd.activateEntry()
	case "cancel":
		return fd.Dismiss()
	case "up":
		fd.goToParent()
	case "new-folder":
		fd.folderInput.SetValue("")
		fd.modalState.Focus = "folder"
		return fd.HandleModalFocus("folder")
	case "details":
		fd.showDetails = !fd.showDetails
	case "apply-filter":
		fd.applyFilters()
		fd.modalState.Focus = "files"
		return fd.HandleModalFocus("files")
	case "clear-filter":
		fd.filterInput.SetValue("")
		fd.applyFilters()
	case "clear-marks":
		if fd.config.Type != FileDialogTypeSave || fd.packetMarks == 0 {
			return nil
		}
		fd.SetPacketMarks(0)
		fd.modalState.Focus = "files"
		fd.HandleModalFocus("files")
		return func() tea.Msg { return ClearPacketMarksMsg{} }
	case "create-folder":
		return fd.createFolder()
	case "cancel-edit":
		fd.errorMessage = ""
		fd.modalState.Focus = "files"
		return fd.HandleModalFocus("files")
	default:
		if strings.HasPrefix(id, "path:") {
			fd.changeDirectory(strings.TrimPrefix(id, "path:"))
			return nil
		}
		if strings.HasPrefix(id, "entry:") {
			index, err := strconv.Atoi(strings.TrimPrefix(id, "entry:"))
			if err != nil || index < 0 || index >= len(fd.filteredFiles) {
				return nil
			}
			return fd.selectEntry(index, time.Now())
		}
	}
	return nil
}

func (fd *FileDialog) selectEntry(index int, now time.Time) tea.Cmd {
	fd.cursor = index
	entry := fd.filteredFiles[index]
	double := fd.modalState.DoubleClick(filepath.Join(fd.currentDir, entry.Name()), now)
	fd.modalState.Focus = "files"
	fd.HandleModalFocus("files")
	if fd.config.Type == FileDialogTypeSave && !entry.IsDir() {
		fd.filename.SetValue(entry.Name())
		if double {
			fd.modalState.Focus = "filename"
			return fd.HandleModalFocus("filename")
		}
		return nil
	}
	if double {
		return fd.activateEntry()
	}
	return nil
}

func (fd *FileDialog) ScrollModal(delta int) tea.Cmd {
	fd.modalState.ResetClicks()
	fd.viewOffset = max(0, min(fd.viewOffset+delta, max(0, len(fd.filteredFiles)-fd.listHeight)))
	return nil
}

func (fd *FileDialog) changeDirectory(path string) {
	path, err := filepath.Abs(path)
	if err != nil {
		fd.errorMessage = fmt.Sprintf("Cannot resolve directory: %v", err)
		return
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		fd.errorMessage = fmt.Sprintf("Cannot read directory: %v", err)
		return
	}
	fd.currentDir = path
	fd.allFiles = entries
	fd.cursor = 0
	fd.viewOffset = 0
	fd.filterInput.SetValue("")
	fd.applyFilters()
	fd.errorMessage = ""
	fd.modalState.ResetClicks()
}

func (fd *FileDialog) activateEntry() tea.Cmd {
	entry, ok := fd.getCurrentEntry()
	if !ok {
		return nil
	}
	if entry.IsDir() {
		fd.enterDirectory(entry.Name())
		return nil
	}
	if fd.config.Type == FileDialogTypeSave {
		fd.filename.SetValue(entry.Name())
		fd.modalState.Focus = "filename"
		return fd.HandleModalFocus("filename")
	}
	return fd.finishSelection(filepath.Join(fd.currentDir, entry.Name()), false)
}

func (fd *FileDialog) acceptFile() tea.Cmd {
	if err := fd.validateFilename(); err != nil {
		fd.errorMessage = err.Error()
		return nil
	}
	path := fd.ensurePcapExtension(fd.GetFullPath())
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			fd.errorMessage = "The destination is a directory"
			return nil
		}
		fd.overwritePath = path
		fd.modalState.ResetClicks()
		return fd.overwrite.Show(ConfirmDialogOptions{Type: ConfirmDialogWarning, Title: "Replace existing file?", Message: "A file already exists at this destination.", Details: []string{path}, ConfirmText: "Replace", CancelText: "Keep editing"})
	}
	if !os.IsNotExist(err) {
		fd.errorMessage = fmt.Sprintf("Cannot check destination: %v", err)
		return nil
	}
	return fd.finishSelection(path, false)
}

func (fd *FileDialog) finishSelection(path string, overwriteConfirmed bool) tea.Cmd {
	fd.Deactivate()
	return func() tea.Msg { return FileSelectedMsg{Paths: []string{path}, OverwriteConfirmed: overwriteConfirmed} }
}

// Confirmation commands only construct an immediate result; consume that result
// inside this owner so unrelated confirmation handlers never receive it.
func (fd *FileDialog) mapOverwrite(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	result, ok := cmd().(ConfirmDialogResult)
	if !ok {
		return nil
	}
	path := fd.overwritePath
	fd.overwritePath = ""
	if result.Confirmed {
		return fd.finishSelection(path, true)
	}
	return nil
}

// prepareLayout reserves room for the current action rows and fields. It runs
// on state changes, never from rendering.
func (fd *FileDialog) prepareLayout() {
	if fd.width <= 0 || fd.height <= 0 {
		return
	}
	opts := ModalRenderOptions{Title: fd.title(), Width: fd.width, Height: fd.height, Theme: fd.theme, Actions: fd.actions(), Content: strings.Repeat("\n", 100), Footer: "↑/↓ Navigate · ←/→ Change directory · Tab Focus"}
	inputWidth := max(1, ModalContentWidth(opts)-12)
	fd.filename.Width = inputWidth
	fd.filterInput.Width = inputWidth
	fd.folderInput.Width = inputWidth
	available := LayoutModal(opts).ContentHeight
	fields := 2
	if fd.config.Type == FileDialogTypeSave {
		fields++
	}
	if fd.mode == ModeCreateFolder {
		fields++
	}
	if fd.errorMessage != "" {
		fields++
	}
	fd.listHeight = max(1, min(20, available-fields))
	fd.viewOffset = max(0, min(fd.viewOffset, max(0, len(fd.filteredFiles)-fd.listHeight)))
}

func (fd *FileDialog) ScrollModalAt(delta, x, y int) tea.Cmd {
	if fd.overwrite.IsActive() {
		return nil
	}
	if y >= 2 && y < 2+fd.listHeight {
		return fd.ScrollModal(delta)
	}
	layout := LayoutModal(fd.ModalOptions())
	fd.modalState.ResetClicks()
	fd.modalState.Scroll = max(0, min(layout.ContentOffset+delta, layout.FullContentHeight-layout.ContentHeight))
	return nil
}

// ModalShortcut keeps explicit control shortcuts usable while a button has focus.
func (fd *FileDialog) ModalShortcut(key tea.KeyMsg) (tea.Cmd, bool) {
	if !fd.overwrite.IsActive() && key.String() == "/" {
		fd.modalState.Focus = "filter"
		return fd.HandleModalFocus("filter"), true
	}
	return nil, false
}
