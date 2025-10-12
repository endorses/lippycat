//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// FileDialogType represents the dialog type (save/open)
type FileDialogType int

const (
	FileDialogTypeSave FileDialogType = iota
	FileDialogTypeOpen
)

// FileDialogInputMode represents the current input mode
type FileDialogInputMode int

const (
	ModeNavigation   FileDialogInputMode = iota // Navigating directories
	ModeFilename                                // Editing filename
	ModeFilter                                  // Filtering files
	ModeCreateFolder                            // Creating new folder
)

// FileDialogConfig holds configuration for the file dialog
type FileDialogConfig struct {
	Type            FileDialogType
	Title           string
	InitialPath     string
	DefaultFilename string
	AllowedTypes    []string // File extensions to show (e.g., [".pcap", ".pcapng"])
	AllowMultiple   bool     // Allow selecting multiple files (open mode only)
}

// FileDialog provides a generic file dialog combining directory navigation and filename input
type FileDialog struct {
	active       bool
	config       FileDialogConfig
	filename     textinput.Model
	filterInput  textinput.Model
	folderInput  textinput.Model
	mode         FileDialogInputMode
	theme        themes.Theme
	width        int
	height       int
	errorMessage string

	// Custom file list management (replacing bubbles/filepicker display)
	currentDir    string
	allFiles      []os.DirEntry // All files in current directory
	filteredFiles []os.DirEntry // Files after applying filters
	cursor        int           // Current cursor position
	viewOffset    int           // Scroll offset for display
	listHeight    int           // Number of files to display
	showDetails   bool          // Show size and permissions

	// Selection state
	selectedFiles []string // Selected files (for multiple selection)
}

// FileSelectedMsg is sent when a file path is confirmed
type FileSelectedMsg struct {
	Paths []string // Support multiple files
}

// Helper to get single path (for backwards compatibility)
func (msg FileSelectedMsg) Path() string {
	if len(msg.Paths) > 0 {
		return msg.Paths[0]
	}
	return ""
}

// NewFileDialog creates a new generic file dialog
func NewFileDialog(config FileDialogConfig) FileDialog {
	// Expand home directory if needed
	initialPath := config.InitialPath
	if strings.HasPrefix(initialPath, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			initialPath = filepath.Join(home, initialPath[1:])
		}
	}

	// Ensure path is absolute
	if !filepath.IsAbs(initialPath) {
		if abs, err := filepath.Abs(initialPath); err == nil {
			initialPath = abs
		}
	}

	// Create directory if it doesn't exist
	if _, err := os.Stat(initialPath); os.IsNotExist(err) {
		// Try parent directory
		parent := filepath.Dir(initialPath)
		if _, err := os.Stat(parent); err == nil {
			initialPath = parent
		} else {
			// Fall back to current directory or home
			if cwd, err := os.Getwd(); err == nil {
				initialPath = cwd
			} else if home, err := os.UserHomeDir(); err == nil {
				initialPath = home
			}
		}
	}

	// Update config with resolved path
	config.InitialPath = initialPath

	// Set default title if not provided
	if config.Title == "" {
		if config.Type == FileDialogTypeSave {
			config.Title = "Save File"
		} else {
			config.Title = "Open File"
		}
	}

	// Set default filename for save mode
	if config.Type == FileDialogTypeSave && config.DefaultFilename == "" {
		config.DefaultFilename = generateDefaultFilename()
	}

	// Create filename input (for save mode)
	filenameInput := textinput.New()
	filenameInput.Placeholder = "filename.pcap"
	filenameInput.CharLimit = 255
	filenameInput.Width = 50
	if config.DefaultFilename != "" {
		filenameInput.SetValue(config.DefaultFilename)
	}

	// Create filter input
	filterInput := textinput.New()
	filterInput.Placeholder = "Filter files..."
	filterInput.CharLimit = 100
	filterInput.Width = 50

	// Create folder input
	folderInput := textinput.New()
	folderInput.Placeholder = "New folder name..."
	folderInput.CharLimit = 255
	folderInput.Width = 50

	return FileDialog{
		active:        false,
		config:        config,
		filename:      filenameInput,
		filterInput:   filterInput,
		folderInput:   folderInput,
		mode:          ModeNavigation,
		theme:         themes.Solarized(),
		currentDir:    initialPath,
		allFiles:      make([]os.DirEntry, 0),
		filteredFiles: make([]os.DirEntry, 0),
		cursor:        0,
		viewOffset:    0,
		listHeight:    15,
		showDetails:   true, // Show details by default
		selectedFiles: make([]string, 0),
	}
}

// NewSaveFileDialog creates a file dialog for saving files
func NewSaveFileDialog(initialPath, defaultFilename string, allowedTypes []string) FileDialog {
	return NewFileDialog(FileDialogConfig{
		Type:            FileDialogTypeSave,
		Title:           "Save Packets to File",
		InitialPath:     initialPath,
		DefaultFilename: defaultFilename,
		AllowedTypes:    allowedTypes,
	})
}

// NewOpenFileDialog creates a file dialog for opening files
func NewOpenFileDialog(initialPath string, allowedTypes []string, allowMultiple bool) FileDialog {
	return NewFileDialog(FileDialogConfig{
		Type:          FileDialogTypeOpen,
		Title:         "Open File",
		InitialPath:   initialPath,
		AllowedTypes:  allowedTypes,
		AllowMultiple: allowMultiple,
	})
}

// generateDefaultFilename creates a timestamp-based filename
func generateDefaultFilename() string {
	return fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
}

// SetTheme sets the color theme
func (fd *FileDialog) SetTheme(theme themes.Theme) {
	fd.theme = theme
}

// SetSize sets the dimensions
func (fd *FileDialog) SetSize(width, height int) {
	fd.width = width
	fd.height = height

	// Use a fixed list height for consistent modal size
	// The list will scroll if there are more files than fit
	fd.listHeight = 15
}

// matchesAllowedType checks if a file matches the allowed types
func (fd *FileDialog) matchesAllowedType(name string) bool {
	// If no types specified, allow all
	if len(fd.config.AllowedTypes) == 0 {
		return true
	}

	ext := filepath.Ext(name)
	for _, allowed := range fd.config.AllowedTypes {
		if ext == allowed {
			return true
		}
	}
	return false
}

// matchesFilter checks if a file/directory name matches the current filter
func (fd *FileDialog) matchesFilter(name string) bool {
	filterText := fd.filterInput.Value()
	// No filter active - show all
	if filterText == "" {
		return true
	}

	// Case-insensitive substring match
	return strings.Contains(strings.ToLower(name), strings.ToLower(filterText))
}

// shouldShowEntry determines if a directory entry should be shown
func (fd *FileDialog) shouldShowEntry(entry os.DirEntry) bool {
	name := entry.Name()

	// Always show directories
	if entry.IsDir() {
		return fd.matchesFilter(name)
	}

	// For files, check both type filter and text filter
	return fd.matchesAllowedType(name) && fd.matchesFilter(name)
}

// readDirectory reads the current directory and applies filtering
func (fd *FileDialog) readDirectory() error {
	entries, err := os.ReadDir(fd.currentDir)
	if err != nil {
		return err
	}

	// Store all files
	fd.allFiles = entries

	// Apply filtering
	fd.applyFilters()

	// Reset cursor if needed
	if fd.cursor >= len(fd.filteredFiles) {
		fd.cursor = len(fd.filteredFiles) - 1
	}
	if fd.cursor < 0 {
		fd.cursor = 0
	}

	return nil
}

// applyFilters applies file type and text filters to the file list
func (fd *FileDialog) applyFilters() {
	filtered := make([]os.DirEntry, 0)
	for _, entry := range fd.allFiles {
		if fd.shouldShowEntry(entry) {
			filtered = append(filtered, entry)
		}
	}
	fd.filteredFiles = filtered
}

// Activate shows the file dialog and returns initialization command
func (fd *FileDialog) Activate() tea.Cmd {
	fd.active = true
	fd.mode = ModeNavigation
	fd.errorMessage = ""
	fd.cursor = 0
	fd.viewOffset = 0
	fd.selectedFiles = make([]string, 0)

	// Reset filename to default (save mode only)
	if fd.config.Type == FileDialogTypeSave {
		fd.filename.SetValue(fd.config.DefaultFilename)
		fd.filename.Blur()
	}

	// Clear filter input
	fd.filterInput.SetValue("")
	fd.filterInput.Blur()

	// Clear folder input
	fd.folderInput.SetValue("")
	fd.folderInput.Blur()

	// Read the directory
	fd.readDirectory()

	return nil
}

// Deactivate hides the file dialog
func (fd *FileDialog) Deactivate() {
	fd.active = false
	fd.filename.Blur()
	fd.filterInput.Blur()
	fd.folderInput.Blur()
}

// Navigation methods

func (fd *FileDialog) cursorUp() {
	if fd.cursor > 0 {
		fd.cursor--
		fd.adjustViewOffset()
	}
}

func (fd *FileDialog) cursorDown() {
	if fd.cursor < len(fd.filteredFiles)-1 {
		fd.cursor++
		fd.adjustViewOffset()
	}
}

func (fd *FileDialog) pageUp() {
	fd.cursor -= fd.listHeight
	if fd.cursor < 0 {
		fd.cursor = 0
	}
	fd.adjustViewOffset()
}

func (fd *FileDialog) pageDown() {
	fd.cursor += fd.listHeight
	if fd.cursor >= len(fd.filteredFiles) {
		fd.cursor = len(fd.filteredFiles) - 1
	}
	fd.adjustViewOffset()
}

func (fd *FileDialog) gotoTop() {
	fd.cursor = 0
	fd.adjustViewOffset()
}

func (fd *FileDialog) gotoBottom() {
	fd.cursor = len(fd.filteredFiles) - 1
	if fd.cursor < 0 {
		fd.cursor = 0
	}
	fd.adjustViewOffset()
}

// adjustViewOffset ensures the cursor is visible in the viewport
func (fd *FileDialog) adjustViewOffset() {
	// Scroll down if cursor is below viewport
	if fd.cursor >= fd.viewOffset+fd.listHeight {
		fd.viewOffset = fd.cursor - fd.listHeight + 1
	}
	// Scroll up if cursor is above viewport
	if fd.cursor < fd.viewOffset {
		fd.viewOffset = fd.cursor
	}
	// Clamp viewOffset
	if fd.viewOffset < 0 {
		fd.viewOffset = 0
	}
}

// enterDirectory changes to a directory
func (fd *FileDialog) enterDirectory(dir string) {
	newPath := filepath.Join(fd.currentDir, dir)
	if absPath, err := filepath.Abs(newPath); err == nil {
		fd.currentDir = absPath
		fd.cursor = 0
		fd.viewOffset = 0
		// Clear filter when entering a directory
		fd.filterInput.SetValue("")
		fd.readDirectory()
	}
}

// goToParent goes to the parent directory
func (fd *FileDialog) goToParent() {
	parent := filepath.Dir(fd.currentDir)
	if parent != fd.currentDir { // Not at root
		fd.currentDir = parent
		fd.cursor = 0
		fd.viewOffset = 0
		fd.readDirectory()
	}
}

// IsActive returns whether the dialog is visible
func (fd *FileDialog) IsActive() bool {
	return fd.active
}

// GetFullPath returns the complete file path (directory + filename)
func (fd *FileDialog) GetFullPath() string {
	return filepath.Join(fd.currentDir, fd.filename.Value())
}

// SetDefaultFilename updates the default filename
func (fd *FileDialog) SetDefaultFilename(name string) {
	fd.config.DefaultFilename = name
	if fd.active && fd.config.Type == FileDialogTypeSave {
		fd.filename.SetValue(name)
	}
}

// getCurrentEntry returns the currently selected entry
func (fd *FileDialog) getCurrentEntry() (os.DirEntry, bool) {
	if len(fd.filteredFiles) == 0 || fd.cursor < 0 || fd.cursor >= len(fd.filteredFiles) {
		return nil, false
	}
	return fd.filteredFiles[fd.cursor], true
}

// Update handles messages
func (fd *FileDialog) Update(msg tea.Msg) tea.Cmd {
	if !fd.active {
		return nil
	}

	// Handle different modes
	switch fd.mode {
	case ModeFilter:
		// Filter input mode
		return fd.handleFilterMode(msg)

	case ModeFilename:
		// Filename editing mode (save mode only)
		return fd.handleFilenameMode(msg)

	case ModeCreateFolder:
		// Create folder mode
		return fd.handleCreateFolderMode(msg)

	case ModeNavigation:
		// Navigation mode
		return fd.handleNavigationMode(msg)
	}

	return nil
}

// handleFilterMode handles messages in filter input mode
func (fd *FileDialog) handleFilterMode(msg tea.Msg) tea.Cmd {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			// Exit filter mode
			fd.mode = ModeNavigation
			fd.filterInput.Blur()
			// Clear filter if it's empty
			if fd.filterInput.Value() == "" {
				fd.applyFilters()
			}
			return nil

		case "tab":
			// Exit filter mode and focus filename input (save mode only)
			fd.filterInput.Blur()
			if fd.config.Type == FileDialogTypeSave {
				fd.mode = ModeFilename
				fd.filename.Focus()
			} else {
				fd.mode = ModeNavigation
			}
			return nil

		case "enter":
			// Apply filter and return to navigation
			fd.mode = ModeNavigation
			fd.filterInput.Blur()
			fd.applyFilters()
			return nil

		case "up":
			// Navigate up in file list (stay in filter mode)
			fd.cursorUp()
			return nil

		case "down":
			// Navigate down in file list (stay in filter mode)
			fd.cursorDown()
			return nil

		case "left":
			// Navigate to parent directory (stay in filter mode, clear filter)
			fd.filterInput.SetValue("")
			fd.applyFilters()
			fd.goToParent()
			return nil

		case "right":
			// Enter directory if cursor is on a directory (stay in filter mode, clear filter)
			if len(fd.filteredFiles) > 0 && fd.cursor < len(fd.filteredFiles) {
				entry := fd.filteredFiles[fd.cursor]
				if entry.IsDir() {
					fd.filterInput.SetValue("")
					fd.applyFilters()
					fd.enterDirectory(entry.Name())
				}
			}
			return nil
		}
	}

	// Update filter input and reapply filters in real-time
	var cmd tea.Cmd
	fd.filterInput, cmd = fd.filterInput.Update(msg)
	fd.applyFilters()
	return cmd
}

// handleFilenameMode handles messages in filename editing mode
func (fd *FileDialog) handleFilenameMode(msg tea.Msg) tea.Cmd {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			// Exit filename mode
			fd.mode = ModeNavigation
			fd.filename.Blur()
			return nil

		case "tab":
			// Switch to navigation
			fd.mode = ModeNavigation
			fd.filename.Blur()
			return nil

		case "enter":
			// Confirm save
			fullPath := fd.GetFullPath()

			// Validate filename
			if err := fd.validateFilename(); err != nil {
				fd.errorMessage = err.Error()
				return nil
			}

			// Ensure .pcap extension (or other configured extension)
			fullPath = fd.ensurePcapExtension(fullPath)

			// Check if file exists
			if _, err := os.Stat(fullPath); err == nil {
				fd.errorMessage = "File exists. Press Enter again to overwrite, Esc to cancel."
			}

			fd.Deactivate()
			return func() tea.Msg {
				return FileSelectedMsg{Paths: []string{fullPath}}
			}
		}
	}

	// Update filename input
	var cmd tea.Cmd
	fd.filename, cmd = fd.filename.Update(msg)
	return cmd
}

// handleCreateFolderMode handles messages in folder creation mode
func (fd *FileDialog) handleCreateFolderMode(msg tea.Msg) tea.Cmd {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			// Cancel folder creation
			fd.mode = ModeNavigation
			fd.folderInput.Blur()
			fd.errorMessage = ""
			return nil

		case "enter":
			// Create the folder
			folderName := strings.TrimSpace(fd.folderInput.Value())

			// Validate folder name
			if folderName == "" {
				fd.errorMessage = "Folder name cannot be empty"
				return nil
			}

			// Check for invalid characters
			invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
			for _, char := range invalidChars {
				if strings.Contains(folderName, char) {
					fd.errorMessage = fmt.Sprintf("Folder name contains invalid character: %s", char)
					return nil
				}
			}

			// Create the folder
			newPath := filepath.Join(fd.currentDir, folderName)
			if err := os.MkdirAll(newPath, 0755); err != nil {
				fd.errorMessage = fmt.Sprintf("Failed to create folder: %s", err.Error())
				return nil
			}

			// Success - return to navigation mode and refresh directory
			fd.mode = ModeNavigation
			fd.folderInput.Blur()
			fd.errorMessage = ""
			fd.readDirectory()

			// Move cursor to the newly created folder
			for i, entry := range fd.filteredFiles {
				if entry.Name() == folderName {
					fd.cursor = i
					fd.adjustViewOffset()
					break
				}
			}

			return nil
		}
	}

	// Update folder input
	var cmd tea.Cmd
	fd.folderInput, cmd = fd.folderInput.Update(msg)
	return cmd
}

// handleNavigationMode handles messages in navigation mode
func (fd *FileDialog) handleNavigationMode(msg tea.Msg) tea.Cmd {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc", "q":
			// Close dialog
			fd.Deactivate()
			return nil

		case "/":
			// Enter filter mode
			fd.mode = ModeFilter
			fd.filterInput.Focus()
			return nil

		case "n":
			// Enter create folder mode
			fd.mode = ModeCreateFolder
			fd.folderInput.SetValue("")
			fd.folderInput.Focus()
			return nil

		case "d":
			// Toggle details display
			fd.showDetails = !fd.showDetails
			return nil

		case "tab":
			// Enter filename mode (save mode only)
			if fd.config.Type == FileDialogTypeSave {
				fd.mode = ModeFilename
				fd.filename.Focus()
			}
			return nil

		// Navigation keys
		case "up", "k":
			fd.cursorUp()
		case "down", "j":
			fd.cursorDown()
		case "pgup", "K":
			fd.pageUp()
		case "pgdown", "J":
			fd.pageDown()
		case "home", "g":
			fd.gotoTop()
		case "end", "G":
			fd.gotoBottom()

		case "left", "h":
			// Go to parent directory
			fd.goToParent()

		case "right", "l", "enter":
			// Enter directory or select file
			entry, ok := fd.getCurrentEntry()
			if !ok {
				return nil
			}

			if entry.IsDir() {
				// Enter directory
				fd.enterDirectory(entry.Name())
			} else if fd.config.Type == FileDialogTypeOpen {
				// Select file in open mode
				fullPath := filepath.Join(fd.currentDir, entry.Name())
				fd.Deactivate()
				return func() tea.Msg {
					return FileSelectedMsg{Paths: []string{fullPath}}
				}
			}
		}

		// Clear error when navigating
		if fd.errorMessage != "" {
			fd.errorMessage = ""
		}
	}

	return nil
}

// View renders the file dialog
func (fd *FileDialog) View() string {
	if !fd.active {
		return ""
	}

	var content strings.Builder

	// Current directory
	dirStyle := lipgloss.NewStyle().
		Foreground(fd.theme.InfoColor).
		Bold(true)
	content.WriteString(dirStyle.Render("Directory: " + fd.currentDir))
	content.WriteString("\n\n")

	// File list
	content.WriteString(fd.renderFileList())
	content.WriteString("\n\n")

	// Filter input (if in filter mode)
	if fd.mode == ModeFilter {
		labelStyle := lipgloss.NewStyle().
			Foreground(fd.theme.Foreground).
			Bold(true)
		inputStyle := lipgloss.NewStyle().
			Foreground(fd.theme.Foreground)

		content.WriteString(labelStyle.Render("Filter: "))
		content.WriteString(inputStyle.Render(fd.filterInput.View()))
		content.WriteString("\n")
	}

	// Folder input (if in create folder mode)
	if fd.mode == ModeCreateFolder {
		labelStyle := lipgloss.NewStyle().
			Foreground(fd.theme.Foreground).
			Bold(true)
		inputStyle := lipgloss.NewStyle().
			Foreground(fd.theme.Foreground)

		content.WriteString(labelStyle.Render("New folder: "))
		content.WriteString(inputStyle.Render(fd.folderInput.View()))
		content.WriteString("\n")
	}

	// Filename input (save mode only)
	if fd.config.Type == FileDialogTypeSave {
		labelStyle := lipgloss.NewStyle().
			Foreground(fd.theme.Foreground).
			Bold(true)

		inputStyle := lipgloss.NewStyle()
		if fd.mode == ModeFilename {
			inputStyle = inputStyle.
				Foreground(fd.theme.Foreground).
				Padding(0, 1)
		} else {
			inputStyle = inputStyle.
				Foreground(fd.theme.Foreground).
				Padding(0, 1)
		}

		content.WriteString(labelStyle.Render("Filename: "))
		content.WriteString(inputStyle.Render(fd.filename.View()))
		content.WriteString("\n")

		// Full path preview
		pathPreviewStyle := lipgloss.NewStyle().
			Foreground(fd.theme.StatusBarFg).
			Italic(true)
		content.WriteString(pathPreviewStyle.Render("→ " + fd.GetFullPath()))
	}

	// Error message (if any)
	if fd.errorMessage != "" {
		content.WriteString("\n\n")
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true)
		content.WriteString(errorStyle.Render("⚠ " + fd.errorMessage))
	}

	// Footer based on mode
	footer := fd.getFooter()

	// Use unified modal rendering
	return RenderModal(ModalRenderOptions{
		Title:   fd.config.Title,
		Content: content.String(),
		Footer:  footer,
		Width:   fd.width,
		Height:  fd.height,
		Theme:   fd.theme,
	})
}

// renderFileList renders the custom file list with filtering
func (fd *FileDialog) renderFileList() string {
	if len(fd.filteredFiles) == 0 {
		// Render "No files found" message with fixed height padding
		emptyStyle := lipgloss.NewStyle().
			Foreground(fd.theme.StatusBarFg).
			Italic(true)
		var listBuilder strings.Builder
		listBuilder.WriteString(emptyStyle.Render("No files found."))
		listBuilder.WriteString("\n")

		// Pad remaining lines for fixed height
		for i := 1; i < fd.listHeight; i++ {
			listBuilder.WriteString("\n")
		}
		return listBuilder.String()
	}

	var listBuilder strings.Builder

	// Render visible entries (always render exactly fd.listHeight lines for fixed height)
	start := fd.viewOffset
	for i := start; i < start+fd.listHeight; i++ {
		// Check if we have an entry to display
		if i >= len(fd.filteredFiles) {
			// Pad with empty lines for fixed height
			listBuilder.WriteString("\n")
			continue
		}

		entry := fd.filteredFiles[i]
		name := entry.Name()

		// Get file info for size/perms (only if showing details)
		var sizeStr string
		var permStr string
		if fd.showDetails {
			info, err := entry.Info()
			if err == nil {
				if entry.IsDir() {
					sizeStr = "DIR   "
				} else {
					sizeStr = formatSize(info.Size())
				}
				permStr = info.Mode().String()
			}
		}

		// Build the line
		cursor := " "
		if i == fd.cursor {
			cursor = ">"
		}

		// Check if this line is selected
		isSelected := i == fd.cursor

		var line string
		if fd.showDetails {
			// With details
			if isSelected {
				// Selected: don't apply any color styling to name, let highlight handle it
				line = fmt.Sprintf("%s %s  %s %s", cursor, permStr, sizeStr, name)
			} else if entry.IsDir() {
				// Non-selected directory: blue
				dirStyle := lipgloss.NewStyle().
					Foreground(fd.theme.InfoColor).
					Bold(true)
				line = fmt.Sprintf("%s %s  %s %s", cursor, permStr, sizeStr, dirStyle.Render(name))
			} else {
				// Non-selected file: grey
				fileStyle := lipgloss.NewStyle().
					Foreground(fd.theme.Foreground)
				line = fmt.Sprintf("%s %s  %s %s", cursor, permStr, sizeStr, fileStyle.Render(name))
			}
		} else {
			// Without details - just name
			if isSelected {
				// Selected: don't apply any color styling to name, let highlight handle it
				line = fmt.Sprintf("%s %s", cursor, name)
			} else if entry.IsDir() {
				// Non-selected directory: blue
				dirStyle := lipgloss.NewStyle().
					Foreground(fd.theme.InfoColor).
					Bold(true)
				line = fmt.Sprintf("%s %s", cursor, dirStyle.Render(name))
			} else {
				// Non-selected file: grey
				fileStyle := lipgloss.NewStyle().
					Foreground(fd.theme.Foreground)
				line = fmt.Sprintf("%s %s", cursor, fileStyle.Render(name))
			}
		}

		// Apply selection styling: cyan background + terminal bg color as foreground
		if isSelected {
			highlightStyle := lipgloss.NewStyle().
				Foreground(fd.theme.Background). // Terminal bg color as text color
				Background(fd.theme.SelectionBg) // Cyan background
			line = highlightStyle.Render(line)
		}

		listBuilder.WriteString(line)
		listBuilder.WriteString("\n")
	}

	return listBuilder.String()
}

// formatSize formats file size in human-readable format with consistent width
func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%4dB ", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%4.1f%cB", float64(size)/float64(div), "kMGTPE"[exp])
}

// getFooter returns the appropriate footer text based on mode
func (fd *FileDialog) getFooter() string {
	switch fd.mode {
	case ModeFilter:
		if fd.config.Type == FileDialogTypeSave {
			return "↑/↓: Navigate | ←/→: Change Dir | Tab: Edit Filename | Enter: Apply | Esc: Cancel"
		}
		return "↑/↓: Navigate | ←/→: Change Dir | Enter: Apply | Esc: Cancel"

	case ModeFilename:
		return "Enter: Save | Tab/Esc: Cancel"

	case ModeCreateFolder:
		return "Enter: Create Folder | Esc: Cancel"

	case ModeNavigation:
		if fd.config.Type == FileDialogTypeSave {
			return "↑/↓/hjkl: Navigate | Enter: Open Dir | /: Filter | n: New Folder | d: Toggle Details | Tab: Edit Filename | q/Esc: Cancel"
		}
		return "↑/↓/hjkl: Navigate | Enter: Select | /: Filter | n: New Folder | d: Toggle Details | q/Esc: Cancel"
	}

	return ""
}

// validateFilename checks if the filename is valid
func (fd *FileDialog) validateFilename() error {
	filename := strings.TrimSpace(fd.filename.Value())

	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Check for invalid characters
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		if strings.Contains(filename, char) {
			return fmt.Errorf("filename contains invalid character: %s", char)
		}
	}

	// Check for reserved names (Windows)
	reserved := []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
		"COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
		"LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
	baseFilename := strings.ToUpper(strings.TrimSuffix(filename, filepath.Ext(filename)))
	for _, name := range reserved {
		if baseFilename == name {
			return fmt.Errorf("filename is reserved: %s", name)
		}
	}

	return nil
}

// ensurePcapExtension adds .pcap extension if missing
func (fd *FileDialog) ensurePcapExtension(path string) string {
	ext := filepath.Ext(path)
	if ext != ".pcap" && ext != ".pcapng" {
		return path + ".pcap"
	}
	return path
}

// GetDirectory returns the current directory
func (fd *FileDialog) GetDirectory() string {
	return fd.currentDir
}

// GetFilename returns the current filename
func (fd *FileDialog) GetFilename() string {
	return fd.filename.Value()
}
