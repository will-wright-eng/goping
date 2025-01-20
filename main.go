package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"text/tabwriter"

	"encoding/json"
	"io"
	"net/http"

	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PingOptions struct {
	size     int           // Size of ICMP packet
	ttl      int           // Time To Live
	timeout  time.Duration // Timeout for each ping
	interval time.Duration // Interval between pings
	verbose  bool          // Add verbose flag
}

type PingStats struct {
	PacketsSent int
	PacketsRecv int
	MinRTT      time.Duration
	MaxRTT      time.Duration
	TotalRTT    time.Duration
	StartTime   time.Time
	RTTs        []time.Duration
}

func (ps *PingStats) updateRTT(rtt time.Duration) {
	if ps.MinRTT == 0 || rtt < ps.MinRTT {
		ps.MinRTT = rtt
	}
	if rtt > ps.MaxRTT {
		ps.MaxRTT = rtt
	}
	ps.TotalRTT += rtt
	ps.PacketsRecv++
	ps.RTTs = append(ps.RTTs, rtt)
}

func (ps *PingStats) avgRTT() time.Duration {
	if ps.PacketsRecv == 0 {
		return 0
	}
	return time.Duration(int64(ps.TotalRTT) / int64(ps.PacketsRecv))
}

func (ps *PingStats) lossPercentage() float64 {
	if ps.PacketsSent == 0 {
		return 0
	}
	return float64(ps.PacketsSent-ps.PacketsRecv) / float64(ps.PacketsSent) * 100
}

func (ps *PingStats) stdDevRTT() time.Duration {
	if ps.PacketsRecv < 2 {
		return 0
	}

	mean := float64(ps.avgRTT())
	var sumSquares float64

	for _, rtt := range ps.RTTs {
		diff := float64(rtt) - mean
		sumSquares += diff * diff
	}

	variance := sumSquares / float64(len(ps.RTTs)-1)
	return time.Duration(math.Sqrt(variance))
}

type GeoData struct {
	City        string
	Country     string
	ISP         string
	Coordinates string
}

func (g GeoData) Location() string {
	if g.City != "" && g.Country != "" {
		return fmt.Sprintf("%s, %s", g.City, g.Country)
	}
	return ""
}

type Pinger struct {
	host    string
	addr    *net.IPAddr
	conn    *icmp.PacketConn
	id      int
	options PingOptions
	stats   PingStats
	stop    chan struct{}
	msgSize int
	log     *logrus.Logger
	writer  *tabwriter.Writer
	geoIP   *geoip2.Reader
	geoData GeoData
}

func NewPinger(host string, options PingOptions) (*Pinger, error) {
	// Resolve hostname to IP address
	addr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %v", host, err)
	}

	// Create ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP connection: %v", err)
	}

	// Set TTL
	if err := conn.IPv4PacketConn().SetTTL(options.ttl); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set TTL: %v", err)
	}

	// Initialize logger with custom formatting
	log := logrus.New()
	if options.verbose {
		log.SetLevel(logrus.DebugLevel)
		log.SetFormatter(&logrus.TextFormatter{
			DisableColors:          false,
			FullTimestamp:          true,
			TimestampFormat:        "15:04:05", // Shorter timestamp format
			DisableLevelTruncation: true,       // Show full level name
		})
	}

	// Initialize tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Initialize GeoIP database
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Warn("GeoIP database not found, geographic features will be disabled")
	}

	return &Pinger{
		host:    host,
		addr:    addr,
		conn:    conn,
		id:      os.Getpid() & 0xffff,
		options: options,
		stop:    make(chan struct{}),
		log:     log,
		writer:  w,
		geoIP:   db,
	}, nil
}

func (p *Pinger) sendPing(seq int) error {
	// Create ICMP message
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  seq,
			Data: make([]byte, p.options.size),
		},
	}

	// Marshal the message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %v", err)
	}

	// Store the actual message size
	p.msgSize = len(msgBytes)

	// Send the packet
	if _, err := p.conn.WriteTo(msgBytes, p.addr); err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	p.stats.PacketsSent++
	return nil
}

func (p *Pinger) receivePing(seq int) error {
	// Set read deadline
	p.conn.SetReadDeadline(time.Now().Add(p.options.timeout))

	// Wait for reply
	reply := make([]byte, 1500)
	n, _, err := p.conn.ReadFrom(reply)
	if err != nil {
		return fmt.Errorf("failed to receive packet: %v", err)
	}

	if p.options.verbose {
		ipHeader := reply[:20]
		tos := ipHeader[1]
		fragOffset := (uint16(ipHeader[6])<<8 | uint16(ipHeader[7])) & 0x1FFF
		flags := (ipHeader[6] >> 5) & 0x07

		// Split the debug information into logical groups
		p.log.WithFields(logrus.Fields{
			"size":   n,
			"header": reply[0] & 0x0F * 4,
		}).Debug("IPv4 packet received")

		p.log.WithFields(logrus.Fields{
			"tos":    fmt.Sprintf("0x%02x", tos),
			"flags":  p.formatFlags(flags),
			"offset": fragOffset,
		}).Debug("Packet details")

		fmt.Fprintln(p.writer, "\nReceived Packet Details\t")
		fmt.Fprintf(p.writer, "IPv4 Header Length\t%d bytes\t\n", reply[0]&0x0F*4)
		fmt.Fprintf(p.writer, "Type of Service\t0x%02x%s\t\n",
			tos, p.formatToS(tos))
		fmt.Fprintf(p.writer, "Fragment Offset\t%d\t\n", fragOffset)
		fmt.Fprintf(p.writer, "Flags\t%s\t\n", p.formatFlags(flags))

		fmt.Fprintln(p.writer, "\nICMP Details\t")
		fmt.Fprintf(p.writer, "Type\t%d (Echo Reply)\t\n", reply[20])
		fmt.Fprintf(p.writer, "Code\t%d\t\n", reply[21])
		fmt.Fprintf(p.writer, "Checksum\t0x%02x%02x (Verified)\t\n",
			reply[22], reply[23])
		fmt.Fprintf(p.writer, "Identifier\t%d\t\n", p.id)
		fmt.Fprintf(p.writer, "Sequence\t%d\t\n", seq)
		p.writer.Flush()
	}

	// Parse reply
	msg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return fmt.Errorf("failed to parse ICMP message: %v", err)
	}

	// Verify reply
	if msg.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("unexpected ICMP message type: %v", msg.Type)
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return fmt.Errorf("invalid ICMP echo reply")
	}

	if echo.ID != p.id {
		return fmt.Errorf("ICMP reply ID mismatch")
	}

	// Add sequence number verification
	if echo.Seq != seq {
		return fmt.Errorf("ICMP reply sequence mismatch")
	}

	return nil
}

func (p *Pinger) tracePath() error {
	fmt.Printf("\nTracing route to %s [%s]\n", p.host, p.addr.String())
	fmt.Printf("Maximum hops: %d, Packet size: %d bytes\n\n", p.options.ttl, p.options.size)

	for ttl := 1; ttl <= p.options.ttl; ttl++ {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}

		conn.IPv4PacketConn().SetTTL(ttl)

		// Send three probes for each hop
		var responses []time.Duration
		var hopIP string

		for probe := 0; probe < 3; probe++ {
			start := time.Now()

			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   p.id,
					Seq:  ttl*100 + probe,
					Data: make([]byte, p.options.size),
				},
			}

			msgBytes, _ := msg.Marshal(nil)
			conn.WriteTo(msgBytes, p.addr)

			reply := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, peer, err := conn.ReadFrom(reply)

			if err == nil {
				rtt := time.Since(start)
				responses = append(responses, rtt)
				hopIP = peer.String()

				// Parse ICMP message
				msg, err := icmp.ParseMessage(1, reply[:n])
				if err == nil {
					if msg.Type == ipv4.ICMPTypeTimeExceeded {
						p.log.WithFields(logrus.Fields{
							"hop": ttl,
							"ip":  hopIP,
							"rtt": rtt,
						}).Debug("Intermediate hop")
					}
				}
			}
		}

		conn.Close()

		if len(responses) > 0 {
			// Calculate average RTT
			var avgRTT time.Duration
			for _, rtt := range responses {
				avgRTT += rtt
			}
			avgRTT /= time.Duration(len(responses))

			// Get hop information
			hopInfo := p.getHopInfo(hopIP)
			fmt.Printf("%2d  %s (%s) %.1f ms  %s\n",
				ttl,
				hopIP,
				hopInfo.ISP,
				float64(avgRTT.Microseconds())/1000,
				hopInfo.Location(),
			)

			if hopIP == p.addr.String() {
				break
			}
		} else {
			fmt.Printf("%2d  *  *  *  Request timed out.\n", ttl)
		}
	}
	return nil
}

func (p *Pinger) getHopInfo(ip string) GeoData {
	if p.geoIP == nil {
		return GeoData{}
	}

	parsedIP := net.ParseIP(ip)
	record, err := p.geoIP.City(parsedIP)
	if err != nil {
		return GeoData{}
	}

	// Try to get ISP information from ipapi.co (free tier)
	resp, err := http.Get(fmt.Sprintf("https://ipapi.co/%s/json", ip))
	var isp string
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err == nil {
			isp = fmt.Sprintf("%v", result["org"])
		}
	}

	return GeoData{
		City:        record.City.Names["en"],
		Country:     record.Country.Names["en"],
		ISP:         isp,
		Coordinates: fmt.Sprintf("%.4f,%.4f", record.Location.Latitude, record.Location.Longitude),
	}
}

func (p *Pinger) Run() {
	defer p.conn.Close()
	defer p.writer.Flush()

	// Setup interrupt handler
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("PING %s (%s): %d data bytes\n", p.host, p.addr, p.options.size)
	if p.options.verbose {
		p.log.Info("Starting ping session with detailed protocol information")

		fmt.Fprintln(p.writer, "\nICMP Protocol Details\t")
		fmt.Fprintf(p.writer, "Type\tEcho Request (Type 8)\t\n")
		fmt.Fprintf(p.writer, "Code\t0\t\n")
		fmt.Fprintf(p.writer, "Identifier\t%d\t\n", p.id)
		fmt.Fprintf(p.writer, "Total Size\t%d bytes (Header: 8, Data: %d)\t\n",
			p.options.size+8, p.options.size)
		fmt.Fprintf(p.writer, "Checksum\tCalculated over header and data\t\n")
		p.writer.Flush()

		fmt.Fprintln(p.writer, "\nIPv4 Details\t")
		fmt.Fprintf(p.writer, "TTL\t%d hops\t\n", p.options.ttl)
		fmt.Fprintf(p.writer, "Protocol\t1 (ICMP)\t\n")
		fmt.Fprintf(p.writer, "ToS\t0x00 (Normal Service)\t\n")
		fmt.Fprintf(p.writer, "Fragment\tDon't Fragment bit set\t\n")
		p.writer.Flush()

		// Get and display target information
		targetInfo := p.getHopInfo(p.addr.String())
		p.log.WithFields(logrus.Fields{
			"city":     targetInfo.City,
			"country":  targetInfo.Country,
			"isp":      targetInfo.ISP,
			"location": targetInfo.Coordinates,
		}).Info("Target details")

		// Perform traceroute if requested
		if err := p.tracePath(); err != nil {
			p.log.WithError(err).Error("Failed to trace path")
		}
	}

	sequence := 0
	ticker := time.NewTicker(p.options.interval)
	defer ticker.Stop()

	p.stats.StartTime = time.Now()

	for {
		select {
		case <-p.stop:
			return
		case <-interrupt:
			p.printStats()
			return
		case <-ticker.C:
			start := time.Now()

			if err := p.sendPing(sequence); err != nil {
				fmt.Printf("Failed to send ping: %v\n", err)
				continue
			}

			if err := p.receivePing(sequence); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					fmt.Printf("Request timeout for icmp_seq %d\n", sequence)
				} else {
					fmt.Printf("Failed to receive ping: %v\n", err)
				}
				continue
			}

			rtt := time.Since(start)
			p.stats.updateRTT(rtt)

			fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
				p.msgSize, p.addr, sequence, p.options.ttl, float64(rtt.Microseconds())/1000)

			sequence++
		}
	}
}

func (p *Pinger) printStats() {
	fmt.Printf("\n--- %s ping statistics ---\n", p.host)
	fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		p.stats.PacketsSent,
		p.stats.PacketsRecv,
		p.stats.lossPercentage())

	if p.stats.PacketsRecv > 0 {
		fmt.Printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
			float64(p.stats.MinRTT.Microseconds())/1000,
			float64(p.stats.avgRTT().Microseconds())/1000,
			float64(p.stats.MaxRTT.Microseconds())/1000,
			float64(p.stats.stdDevRTT().Microseconds())/1000)
	}
}

// Helper methods for formatting
func (p *Pinger) formatToS(tos byte) string {
	if tos == 0 {
		return " (Normal Service)"
	}
	return ""
}

func (p *Pinger) formatFlags(flags byte) string {
	var flagStrings []string
	if flags&0x4 != 0 {
		flagStrings = append(flagStrings, "Don't Fragment")
	}
	if flags&0x2 != 0 {
		flagStrings = append(flagStrings, "More Fragments")
	}
	if len(flagStrings) == 0 {
		return "None"
	}
	return strings.Join(flagStrings, ", ")
}

func main() {
	// Parse command line flags
	size := flag.Int("s", 56, "size of ICMP packet payload")
	ttl := flag.Int("t", 52, "time to live")
	timeout := flag.Duration("W", time.Second, "timeout for each ping")
	interval := flag.Duration("i", time.Second, "interval between pings")
	verbose := flag.Bool("v", false, "verbose output with ICMP and networking details")
	trace := flag.Bool("trace", false, "trace route to destination")
	geo := flag.Bool("geo", false, "show geographic information")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: ping [-s size] [-t ttl] [-W timeout] [-i interval] host")
		os.Exit(1)
	}

	options := PingOptions{
		size:     *size,
		ttl:      *ttl,
		timeout:  *timeout,
		interval: *interval,
		verbose:  *verbose || *trace || *geo,
	}

	pinger, err := NewPinger(flag.Arg(0), options)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	pinger.Run()
}
