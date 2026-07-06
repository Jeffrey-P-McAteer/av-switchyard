package test

// AV hardware test subcommand — sends a single command to one piece of AV
// hardware using the specified protocol.  All operations are intentional
// control actions (the opposite of the scan subcommand's read-only posture).
//
// Supported protocols:
//
//   artnet  — Art-Net ArtDMX unicast: set DMX channel values on a universe.
//             Typical use: drive a moving light, RGB fixture, or dimmer rack.
//   sacn    — sACN / E1.31 unicast DMX: same semantics as Art-Net but using
//             the ANSI E1.31 framing expected by many modern fixtures and
//             media servers.
//   osc     — Open Sound Control UDP message with one typed argument.
//             Covers media servers, lighting consoles, audio workstations and
//             any other OSC-capable device.
//   pjlink  — PJLink class-1 TCP command for projectors and displays:
//             power control, input switching, AV mute, lamp queries.

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jsimonetti/go-artnet/packet"

	"av-switchyard/cli"
)

// RunTest is the entry point for the "test" subcommand.
func RunTest(c *cli.CLI) error {
	if c.TestIP == "" {
		return fmt.Errorf("--ip is required for the test subcommand")
	}
	if net.ParseIP(c.TestIP) == nil {
		return fmt.Errorf("--ip %q is not a valid IPv4 address", c.TestIP)
	}

	switch strings.ToLower(c.TestProtocol) {
	case "artnet":
		return runArtNet(c)
	case "sacn":
		return runSACN(c)
	case "osc":
		return runOSC(c)
	case "pjlink":
		return runPJLink(c)
	default:
		return fmt.Errorf("unknown protocol %q — choose one of: artnet, sacn, osc, pjlink", c.TestProtocol)
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// parseDMX builds a 512-byte DMX frame from CLI flags.
// If --all is ≥ 0 every channel is preset to that value first, then
// individual overrides from --channels are applied on top.
func parseDMX(allVal int, channelsCSV string) ([512]byte, error) {
	var data [512]byte
	if allVal >= 0 && allVal <= 255 {
		for i := range data {
			data[i] = byte(allVal)
		}
	}
	if channelsCSV == "" {
		return data, nil
	}
	for _, pair := range strings.Split(channelsCSV, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return data, fmt.Errorf("invalid channel pair %q — expected ch:val", pair)
		}
		ch, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		val, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || ch < 1 || ch > 512 || val < 0 || val > 255 {
			return data, fmt.Errorf("invalid channel pair %q — ch must be 1–512, val 0–255", pair)
		}
		data[ch-1] = byte(val)
	}
	return data, nil
}

// holdAndSend calls send once (duration == 0) or repeatedly at interval until
// duration elapses or the process receives SIGINT/SIGTERM.
func holdAndSend(send func() error, duration, interval time.Duration) error {
	if err := send(); err != nil {
		return err
	}
	if duration <= 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := send(); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		case <-sig:
			fmt.Println("\nstopped.")
			return nil
		}
	}
}

// printDMXSummary prints a compact summary of the non-zero channels being sent.
func printDMXSummary(data [512]byte) {
	var active []string
	for i, v := range data {
		if v != 0 {
			active = append(active, fmt.Sprintf("ch%d=%d", i+1, v))
		}
	}
	switch len(active) {
	case 0:
		fmt.Println("  channels: all zeros (blackout)")
	case 1:
		fmt.Println("  channels:", active[0])
	default:
		preview := active
		if len(preview) > 6 {
			preview = preview[:6]
		}
		fmt.Printf("  channels: %s … (%d non-zero)\n", strings.Join(preview, " "), len(active))
	}
}

// ---------------------------------------------------------------------------
// Art-Net — ArtDMX unicast
// ---------------------------------------------------------------------------

func runArtNet(c *cli.CLI) error {
	data, err := parseDMX(c.TestAll, c.TestChannels)
	if err != nil {
		return err
	}

	universe := c.TestUniverse
	if universe < 0 || universe > 32767 {
		return fmt.Errorf("--universe %d out of Art-Net range 0–32767", universe)
	}
	net_ := uint8(universe >> 8)
	subUni := uint8(universe & 0xFF)

	addr := &net.UDPAddr{IP: net.ParseIP(c.TestIP), Port: 6454}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("UDP bind failed: %w", err)
	}
	defer conn.Close()

	seq := uint8(1)
	send := func() error {
		p := packet.NewArtDMXPacket()
		p.Sequence = seq
		p.SubUni = subUni
		p.Net = net_
		p.Length = 512
		p.Data = data
		b, err := p.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal ArtDMX: %w", err)
		}
		_, err = conn.WriteToUDP(b, addr)
		if seq++; seq == 0 {
			seq = 1
		}
		return err
	}

	fmt.Printf("Art-Net → %s  universe %d (net=%d subUni=0x%02X)\n",
		c.TestIP, universe, net_, subUni)
	printDMXSummary(data)
	printHoldNote(c.TestDuration, c.TestInterval)

	return holdAndSend(send, c.TestDuration, c.TestInterval)
}

// ---------------------------------------------------------------------------
// sACN / E1.31 — unicast DMX
// ---------------------------------------------------------------------------

// sacnCID is the fixed Component Identifier for this test tool.
var sacnCID = [16]byte{
	0x61, 0x76, 0x2D, 0x73, 0x77, 0x79, 0x61, 0x72,
	0x64, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x00, 0x01,
}

// buildSACNPacket encodes one E1.31 unicast data packet.
// Packet structure follows ANSI E1.31-2018 §6 (Table 4-1).
func buildSACNPacket(seq uint8, universe uint16, priority uint8, data [512]byte) []byte {
	const (
		propCount = 513   // start-code byte + 512 DMX channels
		dmpLen    = 10 + propCount
		framingLen = 77 + dmpLen
		rootLen   = 22 + framingLen
		totalLen  = 16 + rootLen
	)
	buf := make([]byte, totalLen)

	// ── Preamble (16 bytes) ───────────────────────────────────────────────
	buf[0], buf[1] = 0x00, 0x10 // preamble size
	buf[2], buf[3] = 0x00, 0x00 // postamble size
	copy(buf[4:16], "ASC-E1.17\x00\x00\x00")

	// ── Root PDU (starts at byte 16) ─────────────────────────────────────
	putPDULen(buf[16:18], rootLen)
	buf[18], buf[19], buf[20], buf[21] = 0x00, 0x00, 0x00, 0x04 // VECTOR_ROOT_E131_DATA
	copy(buf[22:38], sacnCID[:])

	// ── Framing PDU (starts at byte 38) ──────────────────────────────────
	putPDULen(buf[38:40], framingLen)
	buf[40], buf[41], buf[42], buf[43] = 0x00, 0x00, 0x00, 0x02 // VECTOR_E131_DATA_PACKET
	sn := make([]byte, 64)
	copy(sn, "av-switchyard test")
	copy(buf[44:108], sn)
	buf[108] = priority       // priority
	buf[109], buf[110] = 0, 0 // sync address (none)
	buf[111] = seq            // sequence
	buf[112] = 0x00           // options
	binary.BigEndian.PutUint16(buf[113:115], universe)

	// ── DMP PDU (starts at byte 115) ─────────────────────────────────────
	putPDULen(buf[115:117], dmpLen)
	buf[117] = 0x02                    // VECTOR_DMP_SET_PROP
	buf[118] = 0xa1                    // address+data type
	buf[119], buf[120] = 0x00, 0x00    // first property address
	buf[121], buf[122] = 0x00, 0x01    // address increment
	binary.BigEndian.PutUint16(buf[123:125], propCount)
	buf[125] = 0x00 // DMX start code
	copy(buf[126:], data[:])

	return buf
}

// putPDULen writes a 12-bit PDU length with the standard 0x7 flags nibble.
func putPDULen(b []byte, length int) {
	b[0] = 0x70 | byte(length>>8)
	b[1] = byte(length)
}

func runSACN(c *cli.CLI) error {
	data, err := parseDMX(c.TestAll, c.TestChannels)
	if err != nil {
		return err
	}
	universe := uint16(c.TestUniverse)
	if c.TestUniverse < 1 || c.TestUniverse > 63999 {
		return fmt.Errorf("--universe %d out of sACN range 1–63999", c.TestUniverse)
	}
	priority := uint8(c.TestSACNPriority)

	addr := &net.UDPAddr{IP: net.ParseIP(c.TestIP), Port: 5568}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("UDP bind failed: %w", err)
	}
	defer conn.Close()

	seq := uint8(1)
	send := func() error {
		pkt := buildSACNPacket(seq, universe, priority, data)
		_, err := conn.WriteToUDP(pkt, addr)
		if seq++; seq == 0 {
			seq = 1
		}
		return err
	}

	fmt.Printf("sACN/E1.31 → %s  universe %d  priority %d\n",
		c.TestIP, universe, priority)
	printDMXSummary(data)
	printHoldNote(c.TestDuration, c.TestInterval)

	return holdAndSend(send, c.TestDuration, c.TestInterval)
}

// ---------------------------------------------------------------------------
// OSC — Open Sound Control (UDP)
// ---------------------------------------------------------------------------

// buildOSCMessage encodes an OSC message with zero or one argument.
// argType: "f" float32, "i" int32, "s" string, "none" no args.
func buildOSCMessage(address, argType string, fval float64, ival int, sval string) ([]byte, error) {
	padStr := func(s string) []byte {
		s += "\x00"
		b := []byte(s)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}

	var typeTag string
	switch argType {
	case "f":
		typeTag = ",f"
	case "i":
		typeTag = ",i"
	case "s":
		typeTag = ",s"
	case "none", "":
		typeTag = ","
	default:
		return nil, fmt.Errorf("unknown --osc-type %q (choose f, i, s, or none)", argType)
	}

	var msg []byte
	msg = append(msg, padStr(address)...)
	msg = append(msg, padStr(typeTag)...)

	switch argType {
	case "f":
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, math.Float32bits(float32(fval)))
		msg = append(msg, b...)
	case "i":
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(int32(ival)))
		msg = append(msg, b...)
	case "s":
		msg = append(msg, padStr(sval)...)
	}
	return msg, nil
}

func runOSC(c *cli.CLI) error {
	msg, err := buildOSCMessage(c.TestOSCAddress, c.TestOSCType, c.TestOSCFloat, c.TestOSCInt, c.TestOSCString)
	if err != nil {
		return err
	}

	addr := &net.UDPAddr{IP: net.ParseIP(c.TestIP), Port: c.TestOSCPort}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("UDP bind failed: %w", err)
	}
	defer conn.Close()

	argDesc := ""
	switch c.TestOSCType {
	case "f":
		argDesc = fmt.Sprintf(" float=%g", c.TestOSCFloat)
	case "i":
		argDesc = fmt.Sprintf(" int=%d", c.TestOSCInt)
	case "s":
		argDesc = fmt.Sprintf(" string=%q", c.TestOSCString)
	}
	fmt.Printf("OSC → %s:%d  %s%s\n", c.TestIP, c.TestOSCPort, c.TestOSCAddress, argDesc)
	printHoldNote(c.TestDuration, c.TestInterval)

	send := func() error {
		_, err := conn.WriteToUDP(msg, addr)
		return err
	}
	return holdAndSend(send, c.TestDuration, c.TestInterval)
}

// ---------------------------------------------------------------------------
// PJLink — projector / display TCP control (class 1)
// ---------------------------------------------------------------------------

// pjlinkSend connects to the projector, performs optional MD5 authentication,
// sends one command, and prints the response.
func pjlinkSend(ip, cmd, arg, password string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "4352"), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s:4352: %w", ip, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read the greeting: "PJLINK 0\r" (no auth) or "PJLINK 1 <random>\r" (auth)
	greeting := make([]byte, 128)
	n, err := conn.Read(greeting)
	if err != nil {
		return fmt.Errorf("reading PJLink greeting: %w", err)
	}
	greet := strings.TrimRight(string(greeting[:n]), "\r\n ")

	var prefix string
	if strings.HasPrefix(greet, "PJLINK 1 ") {
		// Authentication required: send MD5(random+password)
		random := strings.TrimPrefix(greet, "PJLINK 1 ")
		h := md5.Sum([]byte(random + password))
		prefix = fmt.Sprintf("%x", h)
	} else if greet != "PJLINK 0" {
		return fmt.Errorf("unexpected PJLink greeting: %q", greet)
	}

	// Format and send the command
	request := fmt.Sprintf("%s%%1%s %s\r", prefix, strings.ToUpper(cmd), arg)
	if _, err := fmt.Fprint(conn, request); err != nil {
		return fmt.Errorf("sending command: %w", err)
	}

	// Read the response
	resp := make([]byte, 256)
	n, err = conn.Read(resp)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	response := strings.TrimRight(string(resp[:n]), "\r\n ")
	fmt.Printf("  → %s\n", response)

	// Decode common responses
	printPJLinkResponse(cmd, response)
	return nil
}

func printPJLinkResponse(cmd, resp string) {
	if strings.Contains(resp, "=ERR1") {
		fmt.Println("  (ERR1: undefined command)")
		return
	}
	if strings.Contains(resp, "=ERR2") {
		fmt.Println("  (ERR2: out-of-parameter)")
		return
	}
	if strings.Contains(resp, "=ERR3") {
		fmt.Println("  (ERR3: unavailable time — projector may be warming up or cooling down)")
		return
	}
	if strings.Contains(resp, "=ERR4") {
		fmt.Println("  (ERR4: projector failure)")
		return
	}
	if strings.Contains(resp, "=ERRA") {
		fmt.Println("  (ERRA: authentication failure — check --pjlink-password)")
		return
	}
	// Decode known response values
	switch strings.ToUpper(cmd) {
	case "POWR":
		switch {
		case strings.HasSuffix(resp, "=0"):
			fmt.Println("  (power: standby)")
		case strings.HasSuffix(resp, "=1"):
			fmt.Println("  (power: on)")
		case strings.HasSuffix(resp, "=2"):
			fmt.Println("  (power: cooling)")
		case strings.HasSuffix(resp, "=3"):
			fmt.Println("  (power: warming up)")
		}
	case "AVMT":
		switch {
		case strings.HasSuffix(resp, "=11"):
			fmt.Println("  (AV mute: video muted)")
		case strings.HasSuffix(resp, "=21"):
			fmt.Println("  (AV mute: audio muted)")
		case strings.HasSuffix(resp, "=31"):
			fmt.Println("  (AV mute: video+audio muted)")
		case strings.HasSuffix(resp, "=30"), strings.HasSuffix(resp, "=10"), strings.HasSuffix(resp, "=20"):
			fmt.Println("  (AV mute: off)")
		}
	}
}

func runPJLink(c *cli.CLI) error {
	cmd := strings.ToUpper(c.TestPJLinkCmd)
	arg := c.TestPJLinkArg

	// Quick usage hint for common commands
	hints := map[string]string{
		"POWR": "args: 1=on  0=off  ?=query",
		"INPT": "args: 11=RGB1 12=RGB2 21=Video1 31=Digital1(HDMI) ?=query",
		"AVMT": "args: 11=video-mute 21=audio-mute 31=both  10/20/30=off  ?=query",
		"LAMP": "args: ?=query lamp hours+status",
		"CLSS": "args: ?=query PJLink class (1 or 2)",
	}
	if hint, ok := hints[cmd]; ok {
		fmt.Printf("PJLink → %s  %%1%s %s\n  hint: %s\n", c.TestIP, cmd, arg, hint)
	} else {
		fmt.Printf("PJLink → %s  %%1%s %s\n", c.TestIP, cmd, arg)
	}

	return pjlinkSend(c.TestIP, cmd, arg, c.TestPJLinkPwd)
}

// ---------------------------------------------------------------------------
// Shared display helpers
// ---------------------------------------------------------------------------

func printHoldNote(duration, interval time.Duration) {
	if duration > 0 {
		fmt.Printf("  holding for %s (re-sending every %s) — Ctrl-C to stop early\n",
			duration, interval)
	} else {
		fmt.Println("  (sending once — use --duration=5s to hold for DMX fixtures)")
	}
}
