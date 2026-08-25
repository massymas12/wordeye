//go:build linux

package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"wordeye/internal/model"
)

// Network state, read straight from /proc/net.
//
// The bash original shelled out to `ss`, which is absent on plenty of minimal
// containers and silently skipped the whole check when missing. Parsing
// /proc/net directly removes that dependency, and — because /proc/PID/fd gives
// us socket inodes — lets a connection be attributed to the process holding it
// without needing `ss -p` or elevated privileges.

// TCP states we care about, as they appear in /proc/net/tcp.
const (
	tcpEstablished = "01"
	tcpListen      = "0A"
)

type sockEntry struct {
	local, remote netip
	state         string
	uid           uint32
	inode         uint64
}

type netip struct {
	ip   net.IP
	port int
}

func (n netip) String() string {
	if n.ip == nil {
		return fmt.Sprintf("?:%d", n.port)
	}
	return net.JoinHostPort(n.ip.String(), strconv.Itoa(n.port))
}

func (a *Agent) checkNetwork(ctx context.Context) {
	a.timed("net.sockets", func() (model.CheckState, string) {
		var socks []sockEntry
		read := 0
		for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			s, err := readSockets(p)
			if err != nil {
				continue
			}
			read++
			socks = append(socks, s...)
		}
		if read == 0 {
			return model.CheckError, "/proc/net/tcp unreadable"
		}

		// Attribute sockets to processes via inode.
		byInode := map[uint64]*procInfo{}
		for _, p := range a.procSnapshot() {
			for _, in := range p.SockInodes {
				byInode[in] = p
			}
		}

		iocNets := parseIOCNets(a.set.IOCs.IPs)

		var publicPeers, iocHits int
		for _, s := range socks {
			proc := byInode[s.inode]

			switch s.state {
			case tcpEstablished:
				if s.remote.ip == nil || isPrivateIP(s.remote.ip) {
					continue
				}
				publicPeers++
				if matchesAny(s.remote.ip, iocNets) {
					iocHits++
					a.emitNetFinding("net.ioc_peer", model.SevCritical, model.ConfConfirmed,
						"Live connection to a known-bad IOC address",
						fmt.Sprintf("Established connection to %s. This is an active C2/beacon link, not a historical artefact.", s.remote),
						"Contain the owning process, then block egress. Capture the connection before killing it.",
						s, proc)
					continue
				}
				// Covert-channel egress, judged by DESTINATION PORT rather than
				// by how the process looks.
				//
				// This exists because of a real miss. An operator ran gsocket
				// on a compromised host: no inbound listener, no web-log entry,
				// a binary with an unremarkable name in an unremarkable place.
				// File scanning found nothing, IOC matching found nothing, and
				// the exe-based egress check below found nothing either,
				// because nothing about the process looked wrong. What gave it
				// away was the socket: an outbound TCP connection to port 53.
				//
				// Tools pick these ports precisely because egress filters
				// everywhere allow them. Ordinary name resolution uses UDP and
				// goes to the configured resolver, which is normally loopback
				// or an RFC1918 address; a web server's own processes opening
				// TCP to port 53 on a PUBLIC host is not name resolution.
				if why, covert := covertEgressPorts[s.remote.port]; covert && !isResolverProc(proc) {
					sev, conf := model.SevCritical, model.ConfLikely
					if proc == nil {
						// Unattributed: still worth reporting, less certain.
						conf = model.ConfReview
					}
					a.emitNetFinding("net.covert_channel_egress", sev, conf,
						fmt.Sprintf("Outbound TCP to port %d (%s) from a non-resolver process", s.remote.port, why),
						fmt.Sprintf("%s holds an established connection to %s. %s over TCP to a public address is "+
							"not name resolution; this port is chosen by tunnelling and relay tools (gsocket, iodine, "+
							"dnscat) because egress filters allow it. The binary looking ordinary is expected — that "+
							"is the technique.", procLabel(proc), s.remote, why),
						"Identify the peer and the process, capture the connection, then contain. Check whether the same peer appears on other hosts.",
						s, proc)
					continue
				}
				// Egress from a process that has no business making it.
				if proc != nil && (proc.ExeDeleted || hasSuspiciousExe(proc.Exe)) {
					a.emitNetFinding("net.suspicious_egress", model.SevCritical, model.ConfLikely,
						"Outbound connection from a suspicious process",
						fmt.Sprintf("%s (pid %d, exe %s%s) holds an established connection to %s.",
							proc.Comm, proc.PID, proc.Exe, deletedSuffix(proc), s.remote),
						"Identify the peer, then contain the process.",
						s, proc)
				}

			case tcpListen:
				if proc == nil || s.local.port == 0 {
					continue
				}
				if isExpectedListener(proc, s.local.port) {
					continue
				}
				sev := model.SevMedium
				conf := model.ConfReview
				if hasSuspiciousExe(proc.Exe) || proc.ExeDeleted {
					sev, conf = model.SevCritical, model.ConfLikely
				}
				a.emitNetFinding("net.unexpected_listener", sev, conf,
					fmt.Sprintf("Unexpected listening socket on port %d", s.local.port),
					fmt.Sprintf("%s (pid %d, exe %s) is listening on %s. A bind shell looks exactly like this.",
						proc.Comm, proc.PID, proc.Exe, s.local),
					"Confirm the service is expected on this host.",
					s, proc)
			}
		}

		a.emit(model.Finding{
			RuleID:     "net.summary",
			Class:      "NET",
			Severity:   model.SevInfo,
			Confidence: model.ConfConfirmed,
			Title:      fmt.Sprintf("%d public peer(s) in this snapshot, %d matched the IOC list", publicPeers, iocHits),
			Detail:     "A point-in-time snapshot. Absence of a match proves nothing — PHP-based C2 is transient and may be idle right now — but a match is strong evidence of live activity.",
			Meta:       map[string]any{"public_peers": publicPeers, "ioc_hits": iocHits, "sockets": len(socks)},
		})
		return model.CheckOK, ""
	})
}

func (a *Agent) emitNetFinding(id string, sev model.Severity, conf model.Confidence, title, detail, rem string, s sockEntry, proc *procInfo) {
	f := model.Finding{
		RuleID:      id,
		Class:       "NET",
		Severity:    sev,
		Confidence:  conf,
		Title:       title,
		Detail:      detail,
		Remediation: rem,
		Meta: map[string]any{
			"local": s.local.String(), "remote": s.remote.String(),
			"state": s.state, "uid": s.uid,
		},
	}
	if proc != nil {
		f.ContainPID = proc.PID
		f.Path = proc.Exe
		f.Meta["pid"] = proc.PID
		f.Meta["comm"] = proc.Comm
		f.Meta["exe"] = proc.Exe
		f.Meta["cmdline"] = truncate(proc.Cmdline, 300)
	}
	a.emit(f)
}

func deletedSuffix(p *procInfo) string {
	if p.ExeDeleted {
		return " (deleted)"
	}
	return ""
}

// covertEgressPorts are destination ports that a web host's own processes have
// no legitimate reason to reach over TCP, and that tunnelling tools favour
// because outbound filters allow them everywhere.
//
// 443 is deliberately absent. It is the single most common legitimate
// destination on any web server — API calls, updates, CDN — so flagging it
// would drown the signal. Judging by port only works where the port is rare.
var covertEgressPorts = map[int]string{
	53:  "DNS",
	853: "DNS-over-TLS",
	123: "NTP",
}

// resolverComms are the processes whose job IS name resolution, for which
// outbound DNS is unremarkable.
var resolverComms = []string{
	"systemd-resolve", "resolvconf", "named", "bind", "unbound",
	"dnsmasq", "nscd", "pdns", "knot", "coredns", "chronyd", "ntpd", "systemd-timesyn",
}

func isResolverProc(p *procInfo) bool {
	if p == nil {
		return false
	}
	c := strings.ToLower(p.Comm)
	for _, r := range resolverComms {
		if strings.Contains(c, r) {
			return true
		}
	}
	return false
}

// procLabel describes a process for a finding, tolerating an unattributed
// socket. Inode attribution fails when the owning process exits between reading
// /proc/net and reading /proc/PID/fd, which is common for short-lived beacons.
func procLabel(p *procInfo) string {
	if p == nil {
		return "An unattributed socket"
	}
	return fmt.Sprintf("%s (pid %d, exe %s%s)", p.Comm, p.PID, p.Exe, deletedSuffix(p))
}

func hasSuspiciousExe(exe string) bool {
	for _, d := range suspiciousExeDirs {
		if strings.Contains(exe, d) {
			return true
		}
	}
	return false
}

// isExpectedListener suppresses the ordinary server processes. Ports below 1024
// require privilege to bind, and the usual web/database/ssh daemons listening
// on their own ports are not news.
func isExpectedListener(p *procInfo, port int) bool {
	c := strings.ToLower(p.Comm)
	for _, known := range []string{"nginx", "apache", "httpd", "php-fpm", "mysqld", "mariadb", "sshd", "redis", "memcached", "litespeed", "lsphp", "systemd"} {
		if strings.Contains(c, known) {
			return true
		}
	}
	switch port {
	case 80, 443, 3306, 22, 6379, 11211, 9000:
		return true
	}
	return false
}

// readSockets parses /proc/net/tcp or tcp6.
func readSockets(path string) ([]sockEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []sockEntry
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, ok1 := parseHexAddr(fields[1])
		remote, ok2 := parseHexAddr(fields[2])
		if !ok1 || !ok2 {
			continue
		}
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		out = append(out, sockEntry{
			local: local, remote: remote, state: fields[3],
			uid: uint32(uid), inode: inode,
		})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0035" style addresses. The kernel writes each
// 32-bit word in host byte order, which on x86 means little-endian, so the
// bytes need reversing per word.
func parseHexAddr(s string) (netip, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip{}, false
	}
	rawIP, portHex := s[:i], s[i+1:]

	port, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil {
		return netip{}, false
	}
	b, err := hex.DecodeString(rawIP)
	if err != nil {
		return netip{}, false
	}
	switch len(b) {
	case 4:
		v := binary.LittleEndian.Uint32(b)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, v)
		return netip{ip: ip, port: int(port)}, true
	case 16:
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			v := binary.LittleEndian.Uint32(b[w*4 : w*4+4])
			binary.BigEndian.PutUint32(ip[w*4:w*4+4], v)
		}
		return netip{ip: ip, port: int(port)}, true
	}
	return netip{}, false
}

func parseIOCNets(list []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func matchesAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
