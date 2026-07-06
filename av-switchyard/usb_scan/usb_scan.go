package usb_scan

// USB AV device discovery for Windows, macOS, and Linux.
//
// Because CGO_ENABLED=0, we cannot use libusb-based libraries.  Instead each
// platform is handled with its own native facility:
//   Linux   — read /sys/bus/usb/devices/*
//   macOS   — exec `system_profiler SPUSBDataType -json`
//   Windows — exec PowerShell `Get-PnpDevice` / `Get-CimInstance`

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"av-switchyard/cli"
)

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

func RunUSBScan(c *cli.CLI) error {
	devices, err := discoverUSBDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "usb-scan: discovery error: %v\n", err)
	}

	// Classify and keep only AV hardware.
	var avDevices []*USBDevice
	for _, d := range devices {
		if cat := classifyAV(d); cat != "" {
			d.AVCategory = cat
			avDevices = append(avDevices, d)
		}
	}

	sort.Slice(avDevices, func(i, j int) bool {
		ki := avDevices[i].Manufacturer + avDevices[i].Product
		kj := avDevices[j].Manufacturer + avDevices[j].Product
		return ki < kj
	})

	printUSBReport(avDevices)
	return nil
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// USBDevice describes one enumerated USB device.
type USBDevice struct {
	BusPath      string  `json:"bus_path,omitempty"`
	VendorID     string  `json:"vendor_id"`            // lowercase hex, no prefix
	ProductID    string  `json:"product_id"`
	Manufacturer string  `json:"manufacturer,omitempty"`
	Product      string  `json:"product,omitempty"`
	Serial       string  `json:"serial,omitempty"`
	Speed        string  `json:"speed,omitempty"`
	DeviceClass  uint8   `json:"device_class,omitempty"`
	IfaceClasses []uint8 `json:"iface_classes,omitempty"`
	AVCategory   string  `json:"av_category,omitempty"`
}

// ---------------------------------------------------------------------------
// Platform dispatcher
// ---------------------------------------------------------------------------

func discoverUSBDevices() ([]*USBDevice, error) {
	switch runtime.GOOS {
	case "linux":
		return discoverLinux()
	case "darwin":
		return discoverDarwin()
	case "windows":
		return discoverWindows()
	default:
		return nil, fmt.Errorf("USB discovery not implemented for %s", runtime.GOOS)
	}
}

// ---------------------------------------------------------------------------
// Linux — /sys/bus/usb/devices/
// ---------------------------------------------------------------------------

func discoverLinux() ([]*USBDevice, error) {
	base := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", base, err)
	}

	var devices []*USBDevice
	for _, e := range entries {
		name := e.Name()
		// Skip interface entries (e.g. "1-1:1.0") — these are sub-nodes of a
		// device, not separate devices.
		if strings.Contains(name, ":") {
			continue
		}
		devPath := filepath.Join(base, name)
		// All entries in /sys/bus/usb/devices are symlinks; use os.Stat
		// (which follows symlinks) to confirm the target is a directory.
		fi, err := os.Stat(devPath)
		if err != nil || !fi.IsDir() {
			continue
		}

		vidStr := strings.TrimSpace(sysRead(devPath, "idVendor"))
		pidStr := strings.TrimSpace(sysRead(devPath, "idProduct"))
		if vidStr == "" || pidStr == "" {
			continue
		}

		dev := &USBDevice{
			BusPath:      name,
			VendorID:     strings.ToLower(vidStr),
			ProductID:    strings.ToLower(pidStr),
			Manufacturer: strings.TrimSpace(sysRead(devPath, "manufacturer")),
			Product:      strings.TrimSpace(sysRead(devPath, "product")),
			Serial:       strings.TrimSpace(sysRead(devPath, "serial")),
			Speed:        normaliseSpeedLinux(strings.TrimSpace(sysRead(devPath, "speed"))),
		}

		classHex := strings.TrimSpace(sysRead(devPath, "bDeviceClass"))
		if v, err := strconv.ParseUint(classHex, 16, 8); err == nil {
			dev.DeviceClass = uint8(v)
		}

		// For composite devices (class 0x00), gather interface classes from
		// the sibling entries in the parent sysfs directory (e.g. "1-1:1.0").
		if dev.DeviceClass == 0x00 {
			dev.IfaceClasses = linuxIfaceClasses(base, name)
		}

		devices = append(devices, dev)
	}
	return devices, nil
}

// sysRead reads a single-value file under a sysfs directory; returns "" on error.
func sysRead(devPath, file string) string {
	data, err := os.ReadFile(filepath.Join(devPath, file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// linuxIfaceClasses returns the unique bInterfaceClass values for a USB device
// by scanning the sibling interface entries in the sysfs base directory.
// Interface entries are named "devName:config.iface" (e.g. "1-1:1.0").
func linuxIfaceClasses(base, devName string) []uint8 {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	prefix := devName + ":"
	seen := map[uint8]bool{}
	var out []uint8
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		val := strings.TrimSpace(sysRead(filepath.Join(base, e.Name()), "bInterfaceClass"))
		if v, err := strconv.ParseUint(val, 16, 8); err == nil && !seen[uint8(v)] {
			seen[uint8(v)] = true
			out = append(out, uint8(v))
		}
	}
	return out
}

func normaliseSpeedLinux(raw string) string {
	switch raw {
	case "1.5":
		return "Low-Speed (1.5 Mbps)"
	case "12":
		return "Full-Speed (12 Mbps)"
	case "480":
		return "Hi-Speed (480 Mbps)"
	case "5000":
		return "SuperSpeed (5 Gbps)"
	case "10000":
		return "SuperSpeed+ (10 Gbps)"
	case "20000":
		return "SuperSpeed+ (20 Gbps)"
	default:
		if raw != "" {
			return raw + " Mbps"
		}
		return ""
	}
}

// ---------------------------------------------------------------------------
// macOS — system_profiler SPUSBDataType -json
// ---------------------------------------------------------------------------

func discoverDarwin() ([]*USBDevice, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "system_profiler", "SPUSBDataType", "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler: %w", err)
	}

	// Top-level shape: {"SPUSBDataType": [...]}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, fmt.Errorf("parsing system_profiler JSON: %w", err)
	}
	raw, ok := top["SPUSBDataType"]
	if !ok {
		return nil, nil
	}

	var buses []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &buses); err != nil {
		return nil, fmt.Errorf("parsing SPUSBDataType array: %w", err)
	}

	var devices []*USBDevice
	for _, bus := range buses {
		darwinWalk(bus, &devices)
	}
	return devices, nil
}

// darwinWalk recursively descends the system_profiler USB tree, appending
// leaf devices (those that have product_id / vendor_id) to out.
func darwinWalk(node map[string]json.RawMessage, out *[]*USBDevice) {
	// Check if this node looks like a real USB device.
	vidRaw, hasVID := node["vendor_id"]
	pidRaw, hasPID := node["product_id"]
	if hasVID && hasPID {
		dev := &USBDevice{}
		dev.VendorID = darwinParseVIDPID(jsonStr(vidRaw))
		dev.ProductID = darwinParseVIDPID(jsonStr(pidRaw))

		dev.Product = jsonStr(node["_name"])
		// manufacturer field has changed names across OS versions
		for _, key := range []string{"manufacturer_name", "_manufacturer", "manufacturer"} {
			if v := jsonStr(node[key]); v != "" {
				dev.Manufacturer = v
				break
			}
		}
		for _, key := range []string{"serial_num", "serial_number", "_serial_num"} {
			if v := jsonStr(node[key]); v != "" {
				dev.Serial = v
				break
			}
		}
		dev.Speed = normaliseSpeedDarwin(jsonStr(node["speed"]))
		if dev.VendorID != "" && dev.ProductID != "" {
			*out = append(*out, dev)
		}
	}

	// Recurse into "_items" (child hubs / devices).
	if itemsRaw, ok := node["_items"]; ok {
		var items []map[string]json.RawMessage
		if json.Unmarshal(itemsRaw, &items) == nil {
			for _, child := range items {
				darwinWalk(child, out)
			}
		}
	}
}

// darwinParseVIDPID strips "0x" prefix and any trailing parenthetical, lowercases.
func darwinParseVIDPID(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, " "); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	return strings.ToLower(s)
}

func normaliseSpeedDarwin(raw string) string {
	switch strings.ToLower(raw) {
	case "low_speed":
		return "Low-Speed (1.5 Mbps)"
	case "full_speed":
		return "Full-Speed (12 Mbps)"
	case "high_speed":
		return "Hi-Speed (480 Mbps)"
	case "super_speed":
		return "SuperSpeed (5 Gbps)"
	case "super_speed_plus":
		return "SuperSpeed+ (10 Gbps)"
	default:
		return raw
	}
}

// jsonStr extracts a bare string value from a json.RawMessage; returns "" on error.
func jsonStr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// ---------------------------------------------------------------------------
// Windows — PowerShell Get-PnpDevice / Get-CimInstance
// ---------------------------------------------------------------------------

// winPnpDevice mirrors the fields we select from the PowerShell output.
type winPnpDevice struct {
	FriendlyName string `json:"FriendlyName"`
	Manufacturer string `json:"Manufacturer"`
	InstanceId   string `json:"InstanceId"`   // USB\VID_XXXX&PID_YYYY\...
	PNPClass     string `json:"PNPClass"`
}

// vidpidRe matches VID_XXXX&PID_YYYY in Windows InstanceId strings.
var vidpidRe = regexp.MustCompile(`(?i)VID_([0-9A-F]{4})&PID_([0-9A-F]{4})`)

func discoverWindows() ([]*USBDevice, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Collect all PnP devices whose InstanceId begins with "USB\VID_".
	// AV-relevant PNP classes include: AudioEndpoint, MEDIA, Camera, Image,
	// WSD, HIDClass, USB (for vendor-specific interfaces).
	psCmd := `Get-CimInstance -Class Win32_PnPEntity |` +
		` Where-Object { $_.DeviceID -like 'USB\VID_*' } |` +
		` Select-Object FriendlyName,Manufacturer,InstanceId,PNPClass |` +
		` ConvertTo-Json -Depth 2`

	out, err := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-Command", psCmd).Output()
	if err != nil {
		return nil, fmt.Errorf("PowerShell USB query failed: %w", err)
	}

	out = []byte(strings.TrimSpace(string(out)))
	if len(out) == 0 {
		return nil, nil
	}

	var raw []winPnpDevice
	if out[0] == '[' {
		if err := json.Unmarshal(out, &raw); err != nil {
			return nil, fmt.Errorf("parsing PowerShell JSON array: %w", err)
		}
	} else {
		var single winPnpDevice
		if err := json.Unmarshal(out, &single); err != nil {
			return nil, fmt.Errorf("parsing PowerShell JSON object: %w", err)
		}
		raw = []winPnpDevice{single}
	}

	var devices []*USBDevice
	for _, r := range raw {
		m := vidpidRe.FindStringSubmatch(r.InstanceId)
		if m == nil {
			continue
		}
		dev := &USBDevice{
			BusPath:      r.InstanceId,
			VendorID:     strings.ToLower(m[1]),
			ProductID:    strings.ToLower(m[2]),
			Product:      r.FriendlyName,
			Manufacturer: r.Manufacturer,
		}
		// Map Windows PNP classes to USB device class codes for the heuristic.
		switch strings.ToLower(r.PNPClass) {
		case "audioendpoint", "media":
			dev.DeviceClass = 0x01
		case "camera", "image":
			dev.DeviceClass = 0x0E
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

// ---------------------------------------------------------------------------
// AV classification heuristic
// ---------------------------------------------------------------------------

// avAlwaysVendors: any USB device from these VIDs is AV equipment regardless
// of product name or class code.
var avAlwaysVendors = map[uint16]string{
	// Audio interfaces & mixers
	0x1235: "Focusrite / Novation",
	0x2496: "Focusrite / Novation",
	0x0582: "Roland / BOSS",
	0x0499: "Yamaha",
	0x17CC: "Native Instruments",
	0x0763: "M-Audio / Midiman",
	0x0E41: "Line 6",
	0x09E8: "AKAI Professional",
	0x2B0E: "AKAI Electronics",
	0x1397: "BEHRINGER / Music Tribe",
	0x17A0: "Samson Technologies",
	0x194F: "PreSonus",
	0x1B71: "Avid Technology",
	0x2B3E: "Avid / Digidesign",
	0x20B1: "XMOS Ltd",
	0x0944: "KORG Inc.",
	0x1C75: "Arturia",
	0x0397: "Dave Smith Instruments / Sequential",
	0x1935: "Elektron Music Machines",
	0x041E: "Creative Technology",
	0x06F8: "Guillemot / Hercules",
	0x12BA: "Logitech (Harmonix / DJ)",
	0x2B49: "Waves Audio",
	0x1A9E: "TEAC Corporation",
	0x06A3: "Saitek / Mad Catz",

	// Microphones
	0x19F7: "RODE Microphones",
	0x1395: "Sennheiser Communications",
	0x3053: "Sennheiser",

	// Capture & streaming
	0x0FD9: "Elgato Systems",
	0x21A9: "Elgato / Corsair",
	0x534D: "MacroSilicon (HDMI capture)",
	0x2040: "Hauppauge",
	0x1B80: "Afatek / Geniatech",
	0x07CA: "AVerMedia Technologies",
	0x1EDB: "Blackmagic Design",
	0x0B48: "TechnoTrend",
	0x2935: "Magewell",

	// DMX / stage lighting
	0x2F3B: "ENTTEC",
	0x16D0: "MCS (AV / DMX)",
	0x30BE: "CL Corp (DMX)",
	0x1CBE: "Luminary Micro",

	// DIY / open-source MIDI & lighting (VOTI, AVR community)
	0x16C0: "Van Ooijen Technische Informatica",
	0x1781: "Multiple Vendors (AVR MIDI/Audio)",
}

// avContextualVendors: include a device from these VIDs only if the device
// class code or product name also indicates AV use.
var avContextualVendors = map[uint16]bool{
	0x046D: true, // Logitech — webcams yes, mice no
	0x054C: true, // Sony — cameras/audio yes, storage no
	0x04A9: true, // Canon
	0x04B0: true, // Nikon
	0x04CB: true, // Fujifilm
	0x04E8: true, // Samsung — capture yes
	0x2B28: true, // GoPro
	0x05AC: true, // Apple — FaceTime HD yes, keyboards no
	0x04D8: true, // Microchip Technology — MIDI yes, storage no
	0x0483: true, // STMicroelectronics — MIDI/audio yes
	0x1BC0: true, // Broadcom — audio chipsets
	0x0403: true, // FTDI — AV control adapters yes, plain serial no
	0x10C4: true, // Silicon Labs — AV control yes
	0x067B: true, // Prolific Technology — AV control yes
	0x2A86: true, // Arduino — AV controller sketches yes
	0x04D9: true, // Holtek Semiconductor
	0x1BCF: true, // Sunplus — webcams yes
	0x0C45: true, // Microdia — webcams yes
}

// usb audio chip manufacturers — include only when device class is audio/video
// (these chips appear in both AV and non-AV products)
var avAudioChipVendors = map[uint16]bool{
	0x04B4: true, // Cypress Semiconductor
	0x0D8C: true, // C-Media Electronics
	0x08BB: true, // Texas Instruments PCM
	0x1B3F: true, // GeneralPlus Technology
	0x0C76: true, // JMTek LLC
	0x1FC9: true, // NXP Semiconductors
	0x04CC: true, // NXP / Philips
	0x1DE1: true, // Actions Semiconductor
	0x0BDA: true, // Realtek Semiconductor
	0x0572: true, // Conexant Systems
	0x1B3B: true, // Hauppauge (alt)
	0x1130: true, // Tenx Technology (USB audio)
	0x0A67: true, // Medeli Electronics
}

// strongAVKeywords — any of these in the lowercased product+manufacturer
// string is sufficient to classify as AV, regardless of vendor ID.
var strongAVKeywords = []string{
	"audio interface", "usb audio", "usb microphone", "usb mic",
	"midi", "dmx", "artnet", "sacn",
	"focusrite", "scarlett", "behringer", "presonus", "motu",
	"native instruments", "launchpad", "launchkey", "maschine",
	"traktor", "serato", "rekordbox",
	"streamdeck", "stream deck", "cam link", "camlink",
	"elgato", "avermedia", "hauppauge", "blackmagic", "magewell", "epiphan",
	"enttec", "opendmx", "dmxking",
	"rode microphone", "rode wireless", "rode usb",
	"blue yeti", "blue snowball", "blue microphone",
	"apollo twin", "apollo x", "ua-22", "ua-55", "uafx",
	"focusrite", "saffire", "clarett", "rednet",
	"ur22", "ur44", "ur242", "ur-rt", "steinberg",
	"studiodisplay", "studio capture", "studio phono",
	"preamp", "phantom power", "48v",
	"headset amplifier", "headphone amplifier", "headphone amp",
	"video capture", "hdmi capture", "hdmi converter", "hdmi adapter",
	"sdi capture", "hdmi to", "to hdmi",
}

// contextualAVKeywords — these indicate AV only when combined with another
// signal (audio class, video class, or a known contextual vendor).
var contextualAVKeywords = []string{
	"microphone", " mic ", " mic,",
	"headset", "headphone",
	"speaker", "earphone",
	"webcam", "camera", "cam ",
	"capture",
	"mixer",
	"amplifier",
	"synthesizer", "synth",
	"dj controller", "dj mixer",
	"piano", "organ", "drum pad", "drum machine",
	"studio monitor",
}

// nonAVKeywords — if any of these appear in a product name, the device is
// NOT AV (overrides weaker positive signals, but not class codes or strong keywords).
var nonAVKeywords = []string{
	"keyboard" + " usb", // computer keyboard (MIDI keyboard won't have "usb" suffix)
	"mouse", "mice ", "trackball", "touchpad",
	"gamepad", "joystick", "game controller",
	"fingerprint", "biometric",
	"barcode", "scanner" + " usb",
	"flash drive", "thumb drive", "pen drive",
	"card reader", "memory card",
	"bluetooth adapter", "wifi adapter", "wlan adapter",
	"ethernet adapter", "network adapter",
	"usb hub", "usb 3 hub", "usb 2 hub", "4-port hub", "7-port hub",
	"root hub",
}

// classifyAV returns the AV category label for d, or "" if d is not AV equipment.
func classifyAV(d *USBDevice) string {
	vid := parseVID(d.VendorID)
	combined := strings.ToLower(d.Product + " " + d.Manufacturer)

	// Reject obvious non-AV devices first.
	for _, kw := range nonAVKeywords {
		if strings.Contains(combined, kw) {
			return ""
		}
	}

	// Determine USB class evidence.
	audioClass := d.DeviceClass == 0x01
	videoClass := d.DeviceClass == 0x0E
	for _, cls := range d.IfaceClasses {
		if cls == 0x01 {
			audioClass = true
		}
		if cls == 0x0E {
			videoClass = true
		}
	}

	// 1. Always-AV vendor: classify immediately.
	if _, ok := avAlwaysVendors[vid]; ok {
		return avCategoryByName(combined, audioClass, videoClass)
	}

	// 2. USB Audio class — always AV.
	if audioClass {
		return avCategoryByName(combined, true, false)
	}

	// 3. USB Video class — always AV.
	if videoClass {
		return avCategoryByName(combined, false, true)
	}

	// 4. Audio chip vendor — only if actually in audio/video class.
	if avAudioChipVendors[vid] && (audioClass || videoClass) {
		return avCategoryByName(combined, audioClass, videoClass)
	}

	// 5. Contextual vendor + strong keyword or class evidence.
	if avContextualVendors[vid] {
		if hasAny(combined, strongAVKeywords) || audioClass || videoClass {
			return avCategoryByName(combined, audioClass, videoClass)
		}
		if hasAny(combined, contextualAVKeywords) {
			return avCategoryByName(combined, audioClass, videoClass)
		}
	}

	// 6. Strong AV keyword anywhere in name — classify regardless of vendor.
	if hasAny(combined, strongAVKeywords) {
		return avCategoryByName(combined, audioClass, videoClass)
	}

	return ""
}

// avCategoryByName assigns the most specific AV subcategory it can determine
// from product/manufacturer strings and class codes.
func avCategoryByName(combined string, audioClass, videoClass bool) string {
	// Streaming / capture takes precedence for video-class devices.
	if videoClass || hasAny(combined, []string{"capture", "hdmi capture", "sdi", "camlink", "cam link", "video capture"}) {
		if hasAny(combined, []string{"capture", "hdmi", "sdi", "encode", "broadcast", "stream"}) {
			return "Video Capture / Streaming"
		}
		return "Webcam / Camera"
	}

	// DMX / stage lighting.
	if hasAny(combined, []string{"dmx", "artnet", "sacn", "stage light", "opendmx", "dmxking", "enttec", "pixelator", "node"}) {
		return "DMX / Stage Lighting"
	}

	// MIDI controllers and synthesizers.
	if hasAny(combined, []string{"midi", "synthesizer", "synth", "launchpad", "launchkey", "maschine",
		"keystep", "minilab", "mpk", "mpd", "apc mini", "apc key", "push 2",
		"keystroke", "piano", "organ", "drum pad", "drum machine"}) {
		if hasAny(combined, []string{"dj", "traktor", "serato", "rekordbox", "scratch"}) {
			return "DJ Controller / MIDI"
		}
		return "MIDI Controller / Synthesizer"
	}

	// DJ equipment.
	if hasAny(combined, []string{"dj ", "traktor", "serato", "rekordbox", "turntable", "scratch"}) {
		return "DJ Controller"
	}

	// Stream controllers (Elgato Stream Deck, Loupedeck, etc.)
	if hasAny(combined, []string{"stream deck", "streamdeck", "loupedeck", "shuttle", "tangent"}) {
		return "Stream Deck / Production Controller"
	}

	// Microphones.
	if hasAny(combined, []string{"microphone", " mic ", " mic,", "condenser", "dynamic mic", "rode", "blue yeti", "yeti", "snowball"}) {
		return "USB Microphone"
	}

	// Headsets / headphones.
	if hasAny(combined, []string{"headset", "headphone", "earphone", "gaming headset", "earbuds"}) {
		return "USB Headset / Headphones"
	}

	// Audio interfaces (recording / playback).
	if audioClass || hasAny(combined, []string{
		"interface", "scarlett", "focusrite", "apollo", "saffire", "clarett",
		"presonus", "motu", "avid", "mbox", "profire", "fast track",
		"behringer", "uca202", "umc", "um2", "ur22", "ur44", "ur242",
		"yamaha ag", "yamaha rx", "tascam", "zoom", "preamp",
		"usb audio", "audio device", "sound card",
	}) {
		return "USB Audio Interface"
	}

	// Video cameras.
	if hasAny(combined, []string{"camera", "webcam", "cam "}) {
		return "Webcam / Camera"
	}

	// USB-to-serial adapters (used for AV equipment control).
	if hasAny(combined, []string{"ftdi", "cp210", "ch340", "serial adapter", "uart", "rs-232", "rs232"}) {
		return "AV Control Serial Adapter"
	}

	// Fallback.
	if videoClass {
		return "USB Video Device"
	}
	if audioClass {
		return "USB Audio Device"
	}
	return "USB AV Device"
}

// hasAny returns true if s contains any of the given substrings.
func hasAny(s string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// parseVID converts a lowercase hex string (e.g. "1235") to uint16.
func parseVID(s string) uint16 {
	v, _ := strconv.ParseUint(s, 16, 16)
	return uint16(v)
}

// ---------------------------------------------------------------------------
// Text report
// ---------------------------------------------------------------------------

func printUSBReport(devices []*USBDevice) {
	fmt.Printf("USB AV Device Report: %d device(s) found  [%s]\n", len(devices), runtime.GOOS)
	fmt.Println(strings.Repeat("=", 72))

	if len(devices) == 0 {
		fmt.Println("\n  No AV USB devices detected.")
		fmt.Println()
		return
	}

	for _, d := range devices {
		fmt.Println()
		name := d.Product
		if name == "" {
			name = fmt.Sprintf("VID:%s PID:%s", d.VendorID, d.ProductID)
		}
		mfg := d.Manufacturer
		if mfg == "" {
			mfg = "(unknown manufacturer)"
		}
		fmt.Printf("  %s  ·  %s\n", name, mfg)
		fmt.Printf("  Category:   %s\n", d.AVCategory)
		fmt.Printf("  VID:PID:    %s:%s\n", d.VendorID, d.ProductID)
		if d.Serial != "" {
			fmt.Printf("  Serial:     %s\n", d.Serial)
		}
		if d.Speed != "" {
			fmt.Printf("  Speed:      %s\n", d.Speed)
		}
		if d.BusPath != "" {
			fmt.Printf("  Bus path:   %s\n", d.BusPath)
		}
	}
	fmt.Println()
}
