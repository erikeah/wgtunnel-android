package vpn

/*
#include "vpn_jni.h"
*/
import "C"
import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/miekg/dns"
	"github.com/wgtunnel/android/shared"
	"golang.org/x/sys/unix"
)

const fakeDnsIP = "10.111.222.53"
const maxPendingDnsQueries = 64
const maxCacheEntries = 512
const cacheCleanupInterval = 60 * time.Second

type ExtendedDnsRule struct {
	Domains []string
	Servers []string
}

type ExtendedDnsConfig struct {
	Rules            []ExtendedDnsRule
	SystemDnsServers []string
}

type dnsCacheEntry struct {
	reply  *dns.Msg
	expiry time.Time
}

type extendedDnsWrapper struct {
	realTun            tun.Device
	fakeIP             netip.Addr
	config             *ExtendedDnsConfig
	configMu           sync.RWMutex
	tunnelClient       dns.Client
	bypassClient       *dns.Client
	ctx                context.Context
	cancel             context.CancelFunc
	cache              map[string]dnsCacheEntry
	cacheMu            sync.Mutex
	cacheCleanupTicker *time.Ticker
}

var dnsQuerySem = make(chan struct{}, maxPendingDnsQueries)

var (
	dnsWrappers = make(map[int32]*extendedDnsWrapper)
	dnsMu       sync.RWMutex
)

func registerDnsWrapper(handle int32, w *extendedDnsWrapper) {
	dnsMu.Lock()
	dnsWrappers[handle] = w
	dnsMu.Unlock()
}

func unregisterDnsWrapper(handle int32) {
	dnsMu.Lock()
	delete(dnsWrappers, handle)
	dnsMu.Unlock()
}

var bypassDialer = &net.Dialer{
	Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		c.Control(func(fd uintptr) {
			if C.bypass_socket(C.int(fd)) == 0 {
				opErr = unix.EACCES
			}
		})
		return opErr
	},
}

func extractDnsFromConfig(config string) string {
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "dns") {
			continue
		}
		if len(lower) > 3 {
			c := lower[3]
			if c != '=' && c != ' ' && c != '\t' {
				continue
			}
		}
		eqIdx := strings.IndexByte(trimmed, '=')
		if eqIdx >= 0 {
			return strings.TrimSpace(trimmed[eqIdx+1:])
		}
	}
	return ""
}

func newExtendedDnsWrapper(realTun tun.Device, rawConfig string, rawSystemDnsServers string) *extendedDnsWrapper {
	fakeIP := netip.MustParseAddr(fakeDnsIP)
	rules := parseExtendedDnsRules(rawConfig)
	rawSystemDnsServers = strings.Map(func(rune rune) rune {
		if rune == 0 || rune == 32 {
			return -1
		}
		return rune
	}, rawSystemDnsServers)

	config := &ExtendedDnsConfig{
		Rules:            rules,
		SystemDnsServers: strings.Split(rawSystemDnsServers, ","),
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &extendedDnsWrapper{
		realTun: realTun,
		fakeIP:  fakeIP,
		config:  config,
		tunnelClient: dns.Client{
			Timeout: 5 * time.Second,
		},
		bypassClient: &dns.Client{
			Timeout: 5 * time.Second,
			Dialer:  bypassDialer,
		},
		ctx:    ctx,
		cancel: cancel,
		cache:  make(map[string]dnsCacheEntry),
	}

	w.cacheCleanupTicker = time.NewTicker(cacheCleanupInterval)
	go func() {
		for {
			select {
			case <-w.cacheCleanupTicker.C:
				w.evictExpired()
			case <-w.ctx.Done():
				w.cacheCleanupTicker.Stop()
				return
			}
		}
	}()

	return w
}

func parseExtendedDnsRules(raw string) []ExtendedDnsRule {
	extendedDnsRules := []ExtendedDnsRule{}
	raw = strings.TrimRight(raw, ",")
	raw = strings.ReplaceAll(raw, " ", "")
	parts := strings.Split(raw, ",")
	var servers []string
	var domains []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			if len(domains) > 0 {
				extendedDnsRules = append(extendedDnsRules, ExtendedDnsRule{Servers: servers, Domains: domains})
				shared.LogDebug(tag, "DNS rule added: domains=%v servers=%v", domains, servers)
				servers = []string{}
				domains = []string{}
			}
			servers = append(servers, p)
		} else {
			if len(servers) == 0 {
				continue
			}
			domains = append(domains, strings.ToLower(p))
		}
	}
	if len(servers) > 0 {
		if len(domains) == 0 {
			domains = append(domains, "~")
		}
		extendedDnsRules = append(extendedDnsRules, ExtendedDnsRule{Servers: servers, Domains: domains})
		shared.LogDebug(tag, "DNS rule added: domains=%v servers=%v", domains, servers)
	}
	return extendedDnsRules
}

func (w *extendedDnsWrapper) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := w.realTun.Read(bufs, sizes, offset)
	if err != nil {
		return n, err
	}

	for i := 0; i < n; i++ {
		pkt := bufs[i][offset : offset+sizes[i]]
		if len(pkt) < 20 {
			continue
		}
		if !w.isDnsQuery(pkt) {
			continue
		}
		sizes[i] = 0
		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		select {
		case dnsQuerySem <- struct{}{}:
			go func() {
				defer func() { <-dnsQuerySem }()
				w.handleDnsQuery(pktCopy)
			}()
		default:
			shared.LogDebug(tag, "dropped DNS query for %s (too many pending)", "<unknown>")
		}
	}

	return n, nil
}

func (w *extendedDnsWrapper) isDnsQuery(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || ihl > len(pkt) {
			return false
		}
		if pkt[9] != 17 {
			return false
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen > len(pkt) {
			totalLen = len(pkt)
		}
		if ihl+8 > totalLen {
			return false
		}
		dstIP, ok := netip.AddrFromSlice(pkt[16:20])
		if !ok || dstIP != w.fakeIP {
			return false
		}
		dstPort := int(binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]))
		return dstPort == 53
	}
	return false
}

func (w *extendedDnsWrapper) handleDnsQuery(pkt []byte) {
	defer func() {
		if r := recover(); r != nil {
			shared.LogError(tag, "panic in handleDnsQuery: %v", r)
		}
	}()

	version := pkt[0] >> 4
	var hdrLen int
	var srcIP, dstIP []byte
	var totalLen int

	switch version {
	case 4:
		hdrLen = int(pkt[0]&0x0f) * 4
		totalLen = int(binary.BigEndian.Uint16(pkt[2:4]))
		srcIP = pkt[12:16]
		dstIP = pkt[16:20]
	default:
		return
	}

	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}

	srcPort := int(binary.BigEndian.Uint16(pkt[hdrLen : hdrLen+2]))
	dstPort := int(binary.BigEndian.Uint16(pkt[hdrLen+2 : hdrLen+4]))
	udpLen := int(binary.BigEndian.Uint16(pkt[hdrLen+4 : hdrLen+6]))

	dnsStart := hdrLen + 8
	dnsLen := udpLen - 8
	if dnsLen <= 0 || dnsStart+dnsLen > totalLen {
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(pkt[dnsStart : dnsStart+dnsLen]); err != nil {
		return
	}
	if len(msg.Question) == 0 {
		return
	}

	qname := msg.Question[0].Name
	if strings.HasSuffix(qname, ".") {
		qname = qname[:len(qname)-1]
	}

	rule, matched := w.matchDomain(qname)
	var servers []string
	if matched {
		servers = rule.Servers
		shared.LogDebug(tag, "matched %s: %d server(s) from rule", qname, len(servers))
	} else {
		w.configMu.RLock()
		servers = cloneStrings(w.config.SystemDnsServers)
		w.configMu.RUnlock()
		shared.LogDebug(tag, "non matched %s: %d server(s) from system dns", qname, len(servers))
	}
	if len(servers) == 0 {
		shared.LogDebug(tag, "no upstream for %s, returning NXDOMAIN (no DNS servers configured)", qname)
		resp := w.buildReply(msg, dns.RcodeNameError)
		w.writeResponse(version, srcIP, dstIP, srcPort, dstPort, resp)
		return
	}

	if cached := w.cacheGet(qname); cached != nil {
		cached.Id = msg.Id
		w.writeResponse(version, srcIP, dstIP, srcPort, dstPort, cached)
		return
	}

	proxy := new(dns.Msg)
	proxy.SetQuestion(msg.Question[0].Name, msg.Question[0].Qtype)
	proxy.SetEdns0(4096, true)

	client := w.bypassClient
	if matched {
		client = &w.tunnelClient
	}

	for _, timeout := range []time.Duration{500 * time.Millisecond, 5 * time.Second} {
		for _, server := range servers {
			upAddr, _, err := net.SplitHostPort(server)
			if err != nil {
				upAddr = server
				server = net.JoinHostPort(server, "53")
			}

			ctx, cancel := context.WithTimeout(w.ctx, timeout)
			reply, _, err := client.ExchangeContext(ctx, proxy, server)
			cancel()
			if err != nil || reply == nil {
				shared.LogError(tag, "resolve %s via %s FAILED (timeout=%v): %v", qname, upAddr, timeout, err)
				continue
			}
			shared.LogDebug(tag, "resolve %s via %s OK (timeout=%v)", qname, upAddr, timeout)

			w.cacheSet(qname, reply)
			reply.Id = msg.Id
			w.writeResponse(version, srcIP, dstIP, srcPort, dstPort, reply)
			return
		}
	}

	shared.LogError(tag, "all upstreams failed for %s (matched=%v), returning SERVFAIL", qname, matched)
	resp := w.buildReply(msg, dns.RcodeServerFailure)
	w.writeResponse(version, srcIP, dstIP, srcPort, dstPort, resp)
}

func cloneStrings(src []string) []string {
	dst := make([]string, len(src))
	for i, s := range src {
		dst[i] = strings.Clone(s)
	}
	return dst
}

func (w *extendedDnsWrapper) setSystemDnsServers(systemDnsServers []string) {
	w.configMu.Lock()
	defer w.configMu.Unlock()
	w.config.SystemDnsServers = cloneStrings(systemDnsServers)
}

func (w *extendedDnsWrapper) matchDomain(qname string) (*ExtendedDnsRule, bool) {
	w.configMu.RLock()
	defer w.configMu.RUnlock()
	rules := w.config.Rules
	qnameLower := strings.ToLower(qname)
	for i := range rules {
		for _, domainPattern := range rules[i].Domains {
			var matched bool
			if strings.HasPrefix(domainPattern, "~") {
				suffix := strings.TrimPrefix(domainPattern, "~")
				matched = suffix == "" || strings.HasSuffix(qnameLower, suffix) || qnameLower == suffix
			} else {
				matched = qnameLower == domainPattern
			}
			if matched {
				return &rules[i], true
			}
		}
	}
	return nil, false
}

func (w *extendedDnsWrapper) buildReply(query *dns.Msg, rcode int) *dns.Msg {
	reply := &dns.Msg{}
	reply.SetReply(query)
	reply.Rcode = rcode
	return reply
}

func (w *extendedDnsWrapper) cacheGet(qname string) *dns.Msg {
	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()
	entry, ok := w.cache[qname]
	if !ok || time.Now().After(entry.expiry) {
		if ok {
			delete(w.cache, qname)
		}
		return nil
	}
	data, _ := entry.reply.Pack()
	if data == nil {
		return nil
	}
	reply := new(dns.Msg)
	reply.Unpack(data)
	return reply
}

func (w *extendedDnsWrapper) cacheSet(qname string, reply *dns.Msg) {
	if reply.Rcode != dns.RcodeSuccess {
		return
	}
	minTTL := uint32(60)
	for _, rr := range reply.Answer {
		if t := rr.Header().Ttl; t < minTTL {
			minTTL = t
		}
	}
	data, _ := reply.Pack()
	if data == nil {
		return
	}
	cached := new(dns.Msg)
	cached.Unpack(data)
	expiry := time.Now().Add(time.Duration(minTTL) * time.Second)

	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()

	if _, exists := w.cache[qname]; !exists && len(w.cache) >= maxCacheEntries {
		evictCount := maxCacheEntries / 5
		for key := range w.cache {
			if evictCount <= 0 {
				break
			}
			delete(w.cache, key)
			evictCount--
		}
	}

	w.cache[qname] = dnsCacheEntry{reply: cached, expiry: expiry}
}

func (w *extendedDnsWrapper) evictExpired() {
	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()
	now := time.Now()
	for key, entry := range w.cache {
		if now.After(entry.expiry) {
			delete(w.cache, key)
		}
	}
}

func computeChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func (w *extendedDnsWrapper) writeResponse(version byte, srcIP, dstIP []byte, srcPort, dstPort int, dnsMsg *dns.Msg) {
	dnsResp, err := dnsMsg.Pack()
	if err != nil || dnsResp == nil {
		return
	}

	udpLen := 8 + len(dnsResp)

	switch version {
	case 4:
		ipTotalLen := 20 + udpLen
		buf := make([]byte, ipTotalLen)

		buf[0] = 0x45
		buf[1] = 0
		binary.BigEndian.PutUint16(buf[2:4], uint16(ipTotalLen))
		binary.BigEndian.PutUint16(buf[4:6], 0)
		binary.BigEndian.PutUint16(buf[6:8], 0)
		buf[8] = 64
		buf[9] = 17
		binary.BigEndian.PutUint16(buf[10:12], 0)
		copy(buf[12:16], dstIP)
		copy(buf[16:20], srcIP)

		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
		}
		for sum > 0xffff {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(buf[10:12], uint16(^sum))

		binary.BigEndian.PutUint16(buf[20:22], uint16(dstPort))
		binary.BigEndian.PutUint16(buf[22:24], uint16(srcPort))
		binary.BigEndian.PutUint16(buf[24:26], uint16(udpLen))
		binary.BigEndian.PutUint16(buf[26:28], 0)
		copy(buf[28:], dnsResp)

		pseudo := make([]byte, 0, 12+udpLen)
		pseudo = append(pseudo, dstIP[:4]...)
		pseudo = append(pseudo, srcIP[:4]...)
		pseudo = append(pseudo, 0, 17)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(udpLen))
		pseudo = append(pseudo, buf[20:20+udpLen]...)
		binary.BigEndian.PutUint16(buf[26:28], computeChecksum(pseudo))

		if _, err := w.realTun.Write([][]byte{buf}, 0); err != nil {
			shared.LogError(tag, "write response: %v", err)
		}
	}
}

func (w *extendedDnsWrapper) Write(bufs [][]byte, offset int) (int, error) {
	return w.realTun.Write(bufs, offset)
}

func (w *extendedDnsWrapper) File() *os.File {
	return w.realTun.File()
}

func (w *extendedDnsWrapper) MTU() (int, error) {
	return w.realTun.MTU()
}

func (w *extendedDnsWrapper) Name() (string, error) {
	return w.realTun.Name()
}

func (w *extendedDnsWrapper) Events() <-chan tun.Event {
	return w.realTun.Events()
}

func (w *extendedDnsWrapper) Close() error {
	w.cancel()
	return w.realTun.Close()
}

func (w *extendedDnsWrapper) BatchSize() int {
	return w.realTun.BatchSize()
}
