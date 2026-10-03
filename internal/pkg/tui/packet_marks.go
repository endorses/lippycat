//go:build tui || all

package tui

import (
	"fmt"
	"sort"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/spf13/viper"
)

// Only capture records are retained: protocol metadata and presentation strings
// remain owned by the ordinary packet buffer. Offline records contain IDs only.
type packetMarks struct {
	records    map[uint64]offline.RawRecord
	anchor     uint64
	maxPackets int
	maxBytes   uint64
	bytes      uint64
	revision   uint64
}

func (m *Model) ensurePacketMarks() {
	if m.packetMarks.records != nil {
		return
	}
	m.packetMarks.records = make(map[uint64]offline.RawRecord)
	m.packetMarks.maxPackets = 10000
	m.packetMarks.maxBytes = 64 << 20
	if viper.IsSet("watch.marked_packet_limit") {
		m.packetMarks.maxPackets = max(0, viper.GetInt("watch.marked_packet_limit"))
	}
	if viper.IsSet("watch.marked_bytes_limit") {
		m.packetMarks.maxBytes = viper.GetUint64("watch.marked_bytes_limit")
	}
}

func (m *Model) publishPacketMarks() {
	m.packetMarks.revision++
	ids := make(map[uint64]bool, len(m.packetMarks.records))
	for id := range m.packetMarks.records {
		ids[id] = true
	}
	m.uiState.PacketList.SetMarkedPackets(ids)
	if m.uiState.FileDialog.IsActive() {
		m.uiState.FileDialog.SetPacketMarks(len(ids))
	}
}

func (m *Model) clearPacketMarks() {
	m.ensurePacketMarks()
	m.packetMarks.records = make(map[uint64]offline.RawRecord)
	m.packetMarks.bytes, m.packetMarks.anchor = 0, 0
	m.publishPacketMarks()
}

func (m *Model) markError(err error) tea.Cmd {
	return m.uiState.Toast.Show(err.Error(), components.ToastWarning, components.ToastDurationLong)
}

func (m Model) handleMarkPacket(rangeMark bool) (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() != 0 || m.uiState.ViewMode != "packets" || m.captureDetailsFocused() {
		return m, nil
	}
	m.ensurePacketMarks()
	if rangeMark {
		cmd := m.markPacketRange(false)
		return m, cmd
	}
	p := m.uiState.PacketList.GetSelectedPacket()
	if p == nil || p.CaptureID == 0 {
		return m, m.markError(fmt.Errorf("packet is not loaded yet"))
	}
	cmd := m.togglePacketMark(*p)
	return m, cmd
}

func clonePacketMarks(records map[uint64]offline.RawRecord) map[uint64]offline.RawRecord {
	copy := make(map[uint64]offline.RawRecord, len(records))
	for id, record := range records {
		copy[id] = record
	}
	return copy
}

func (m *Model) togglePacketMark(p components.PacketDisplay) tea.Cmd {
	m.ensurePacketMarks()
	records := clonePacketMarks(m.packetMarks.records)
	if old, exists := records[p.CaptureID]; exists {
		delete(records, p.CaptureID)
		m.packetMarks.bytes -= uint64(len(old.RawData))
		m.packetMarks.records = records
	} else {
		if err := m.addPacketMarks([]components.PacketDisplay{p}, false); err != nil {
			return m.markError(err)
		}
	}
	m.packetMarks.anchor = p.CaptureID
	m.publishPacketMarks()
	return nil
}

// Admission precedes allocation and publication, so failed ranges preserve the
// entire previous selection, including when Shift-click would replace it.
func (m *Model) addPacketMarks(packets []components.PacketDisplay, replace bool) error {
	records := m.packetMarks.records
	bytes := m.packetMarks.bytes
	count := len(records)
	if replace {
		records = nil
		bytes = 0
		count = 0
	}
	for _, p := range packets {
		if _, exists := records[p.CaptureID]; exists {
			continue
		}
		if p.CaptureID == 0 {
			return fmt.Errorf("packet is not loaded yet")
		}
		if m.offlineSession == nil && len(p.RawData) == 0 {
			return fmt.Errorf("packet bytes are unavailable; cannot mark it for export")
		}
		count++
		if count > m.packetMarks.maxPackets {
			return fmt.Errorf("marked packet limit reached (%d); save and clear marks before adding more", m.packetMarks.maxPackets)
		}
		if m.offlineSession == nil {
			size := uint64(len(p.RawData))
			if size > m.packetMarks.maxBytes || bytes > m.packetMarks.maxBytes-size {
				return fmt.Errorf("marked packet byte limit reached (%d bytes); clear marks before adding more", m.packetMarks.maxBytes)
			}
			bytes += size
		}
	}
	next := clonePacketMarks(records)
	for _, p := range packets {
		if _, exists := next[p.CaptureID]; exists {
			continue
		}
		r := offline.RawRecord{ID: offline.PacketID(p.CaptureID - 1)}
		if m.offlineSession == nil {
			r.Timestamp, r.LinkType = p.Timestamp, p.LinkType
			r.CapturedLength = uint32(len(p.RawData))
			r.OriginalLength = uint32(max(p.Length, len(p.RawData)))
			r.RawData = append([]byte(nil), p.RawData...)
		}
		next[p.CaptureID] = r
	}
	m.packetMarks.records, m.packetMarks.bytes = next, bytes
	return nil
}

func (m *Model) markPacketRange(replace bool) tea.Cmd {
	m.ensurePacketMarks()
	if m.packetMarks.anchor == 0 {
		p := m.uiState.PacketList.GetSelectedPacket()
		if p == nil || p.CaptureID == 0 {
			return m.markError(fmt.Errorf("packet is not loaded yet"))
		}
		if err := m.addPacketMarks([]components.PacketDisplay{*p}, replace); err != nil {
			return m.markError(err)
		}
		m.packetMarks.anchor = p.CaptureID
		m.publishPacketMarks()
		return nil
	}
	if m.offlineSession != nil {
		return m.startOfflineMarkRange(m.packetMarks.anchor, m.uiState.PacketList.LogicalCursor(), replace)
	}
	packets := m.uiState.PacketList.GetPackets()
	anchor := -1
	for i := range packets {
		if packets[i].CaptureID == m.packetMarks.anchor {
			anchor = i
			break
		}
	}
	if anchor < 0 {
		return m.markError(fmt.Errorf("range anchor is no longer in this list; click or mark a new anchor"))
	}
	cursor := int(m.uiState.PacketList.LogicalCursor())
	if cursor >= len(packets) {
		return nil
	}
	if err := m.addPacketMarks(packets[min(anchor, cursor):max(anchor, cursor)+1], replace); err != nil {
		return m.markError(err)
	}
	m.publishPacketMarks()
	return nil
}

func (m *Model) startMarkedPacketExport(path string) tea.Cmd {
	if m.uiState.SaveInProgress || m.exportRunning() {
		return m.markError(fmt.Errorf("a packet export is already in progress"))
	}
	ids := make([]uint64, 0, len(m.packetMarks.records))
	for id := range m.packetMarks.records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if m.offlineSession != nil {
		return m.startMarkedOfflineExport(path, ids)
	}
	records := make([]offline.RawRecord, 0, len(ids))
	for _, id := range ids {
		records = append(records, m.packetMarks.records[id])
	}
	// Records are immutable and owned independently of the capture buffer. Take
	// this snapshot on Update, never read mutable marks from the export worker.
	return m.startResidentMarkedExport(path, records)
}

func (m *Model) setPacketMarkAnchor() {
	m.ensurePacketMarks()
	if p := m.uiState.PacketList.GetSelectedPacket(); p != nil {
		m.packetMarks.anchor = p.CaptureID
		m.packetMarks.revision++
	}
}

func (m *Model) markPacketClick(msg tea.MouseMsg) tea.Cmd {
	m.ensurePacketMarks()
	if msg.Shift {
		return m.markPacketRange(!msg.Ctrl)
	}
	if p := m.uiState.PacketList.GetSelectedPacket(); p != nil && p.CaptureID != 0 {
		return m.togglePacketMark(*p)
	}
	return m.markError(fmt.Errorf("packet is not loaded yet"))
}
