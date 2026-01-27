package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"tcpsocks"
	"text/tabwriter"
	"time"
)

const (
	CONTROL_PORT = 1080

	// Control messages
	MSG_HEARTBEAT     = 0
	MSG_CONNECT_REQ   = 1
	MSG_CONNECT_REPLY = 2

	// Extensions
	MSG_CAPS      = 10
	MSG_CAPS_ACK  = 11
	MSG_MUX_DATA  = 12
	MSG_MUX_CLOSE = 13
)

const (
	// Protocol
	PROTO_VER = 2

	FEATURE_MUX  uint32 = 1 << 0
	FEATURE_AEAD uint32 = 1 << 1
)

const (
	AEAD_TAG_SIZE  = 16
	AEAD_NONCE_LEN = 12
	CAPS_BASE_LEN  = 1 + 4 + 2 + 2 + 2 + 2 + 8
)

const (
	MAX_SESSIONS   = 1200
	MAX_QUEUE_SIZE = 4000
	FORWARD_BUF    = 8192

	// Safety cap per control TCP connection (lane). Real capacity is announced by client in CAPS.
	MAX_SESSIONS_PER_CLIENT = 300
)

// Mux settings.
const (
	MUX_CHUNK_MIN     = 1024
	MUX_CHUNK_DEFAULT = 8192
	MUX_CHUNK_MAX     = 16384

	// Per-session inbound buffer (muxIn) bounds in "frames".
	MUX_IN_CAP_MIN     = 4
	MUX_IN_CAP_DEFAULT = 16
	MUX_IN_CAP_MAX     = 64

	// Per-session fairness: max number of DATA frames that may be in-flight (queued or being written).
	DATA_INFLIGHT_DEFAULT = 4
)

// Timeouts.
const (
	HANDSHAKE_TIMEOUT         = 4 * time.Second
	SOCKS_REPLY_WRITE_TIMEOUT = 2 * time.Second
	QUEUE_PUT_TIMEOUT         = 800 * time.Millisecond
	SOCKS_WAIT_TIMEOUT        = 15 * time.Second
	CONNECT_REPLY_TIMEOUT     = 8 * time.Second
	MUX_CLOSE_ENQUEUE_TIMEOUT = 300 * time.Millisecond

	CONTROL_WRITE_TIMEOUT   = 15 * time.Second
	CONTROL_REAPER_INTERVAL = 20 * time.Second
	CONTROL_HB_TIMEOUT      = 75 * time.Second
	CONTROL_CAPS_TIMEOUT    = 5 * time.Second

	TCP_KEEPALIVE_IDLE = 30 * time.Second
)

const (
	CLR_RESET  = "\033[0m"
	CLR_GREEN  = "\033[32m"
	CLR_YELLOW = "\033[33m"
	CLR_BLUE   = "\033[34m"
)

var (
	controlClientsMu sync.RWMutex
	controlClients   = make(map[*ControlClient]struct{})

	sessionsMu sync.RWMutex
	sessions          = make(map[uint32]*Session)
	nextSID    uint32 = 1

	sessionTokens = make(chan struct{}, MAX_SESSIONS)
	requestQueue  = make(chan *Request, MAX_QUEUE_SIZE)

	// Payload bytes forwarded (DATA only; excludes control framing / headers).
	statsForwardedPayloadBytes uint64
	statsActiveSessions        int32

	lastActive atomic.Value // *ControlClient

	// selectedClient controls routing mode.
	// "" means auto mode (all clients participate).
	// Non-empty value pins routing to a specific client IP.
	selectedClient atomic.Value // string

	autoPickRR uint64

	clientIDMu   sync.Mutex
	clientIDByIP = make(map[string]int)
	clientIPByID = make(map[int]string)
	nextClientID = 1

	consoleUsed int32

	frameBodyPool = sync.Pool{
		New: func() any {
			b := make([]byte, 5+MUX_CHUNK_MAX)
			return &b
		},
	}
	dataBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, maxInt(FORWARD_BUF, MUX_CHUNK_MAX))
			return &b
		},
	}
)

var (
	socksReplySuccess          = []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	socksReplyHostUnreachable  = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	socksReplyCmdNotSupported  = []byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	socksReplyAddrNotSupported = []byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

type aeadConfig struct {
	send cipher.AEAD
	recv cipher.AEAD

	sendSalt [4]byte
	recvSalt [4]byte
}

func rand32() ([32]byte, error) {
	var r [32]byte
	_, err := io.ReadFull(rand.Reader, r[:])
	return r, err
}

func hmac16(key []byte, parts ...[]byte) [16]byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	sum := h.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func hmac32(key []byte, parts ...[]byte) [32]byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum[:32])
	return out
}

func ctEq16(got []byte, want [16]byte) bool {
	if len(got) != 16 {
		return false
	}
	return subtle.ConstantTimeCompare(got, want[:]) == 1
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func shouldProtectAEAD(msgType byte) bool {
	if msgType == MSG_CAPS || msgType == MSG_CAPS_ACK || msgType == MSG_HEARTBEAT {
		return false
	}
	return true
}

func makeAAD(sid uint32, msgType byte) [5]byte {
	var aad [5]byte
	binary.BigEndian.PutUint32(aad[0:4], sid)
	aad[4] = msgType
	return aad
}

func makeNonce(salt4 [4]byte, seq uint64) [AEAD_NONCE_LEN]byte {
	var n [AEAD_NONCE_LEN]byte
	copy(n[0:4], salt4[:])
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n
}

func sealFrameAEAD(cfg *aeadConfig, seq *uint64, sid uint32, msgType byte, payload []byte) ([]byte, error) {
	if cfg == nil || !shouldProtectAEAD(msgType) {
		return payload, nil
	}
	nonce := makeNonce(cfg.sendSalt, *seq)
	aad := makeAAD(sid, msgType)
	dst := payload[:0]
	if cap(payload) < len(payload)+cfg.send.Overhead() {
		dst = make([]byte, 0, len(payload)+cfg.send.Overhead())
	}
	out := cfg.send.Seal(dst, nonce[:], payload, aad[:])
	*seq++
	return out, nil
}

func openFrameAEAD(cfg *aeadConfig, seq *uint64, sid uint32, msgType byte, payload []byte) ([]byte, error) {
	if cfg == nil || !shouldProtectAEAD(msgType) {
		return payload, nil
	}
	nonce := makeNonce(cfg.recvSalt, *seq)
	aad := makeAAD(sid, msgType)
	dst := payload[:0]
	out, err := cfg.recv.Open(dst, nonce[:], payload, aad[:])
	if err != nil {
		return nil, err
	}
	*seq++
	return out, nil
}

func deriveServerAEADConfig(ackBase []byte, clientRand, serverRand [32]byte) (*aeadConfig, error) {
	// prk = HMAC(PSK, "KDF" || ackBase || clientRand || serverRand)
	key := tcpsocks.PSK()
	prk := hmac32(key[:], []byte("KDF"), ackBase, clientRand[:], serverRand[:])
	keyC2S := hmac32(prk[:], []byte("c2s"))
	keyS2C := hmac32(prk[:], []byte("s2c"))
	saltC2S := hmac32(prk[:], []byte("c2s_salt"))
	saltS2C := hmac32(prk[:], []byte("s2c_salt"))

	sendAEAD, err := newGCM(keyS2C)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := newGCM(keyC2S)
	if err != nil {
		return nil, err
	}

	cfg := &aeadConfig{send: sendAEAD, recv: recvAEAD}
	copy(cfg.sendSalt[:], saltS2C[:4])
	copy(cfg.recvSalt[:], saltC2S[:4])
	return cfg, nil
}

type muxPayload struct {
	b    []byte
	bufp *[]byte // returned to frameBodyPool when consumed
}

type outFrame struct {
	sid     uint32
	msgType byte
	payload []byte

	bufp    *[]byte       // returned to dataBufPool when written (for MSG_MUX_DATA)
	tokenCh chan struct{} // released when written (fairness)
}

type ControlClient struct {
	conn net.Conn
	addr string
	ip   string

	clientID int

	lastHbSec int64

	capsDone     uint32 // 0/1
	features     uint32
	maxMux       int32
	maxPend      int32
	muxChunk     int32
	dataInflight int32

	// AEAD state is published after CAPS when FEATURE_AEAD is negotiated.
	// Stored as *aeadConfig via atomic.Value to avoid data races with writerLoop.
	aead atomic.Value // *aeadConfig

	activeSessions  int32
	pendingConnects int32

	rx uint64
	tx uint64

	outHi chan outFrame
	outLo chan outFrame

	done      chan struct{}
	closeOnce sync.Once
}

type Session struct {
	sid        uint32
	clientConn net.Conn
	control    *ControlClient

	repCh chan byte

	pendingConnect bool

	mux        bool
	muxIn      chan muxPayload
	muxChunk   int
	dataTokens chan struct{}
	done       chan struct{}
	doneOnce   sync.Once
}

func (s *Session) markDone() {
	s.doneOnce.Do(func() { close(s.done) })
}

type Request struct {
	clientConn net.Conn
	clientAddr string
	payload    []byte

	done     chan struct{}
	doneOnce sync.Once
}

func (r *Request) notify() {
	r.doneOnce.Do(func() { close(r.done) })
}

func logf(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s\n", ts, fmt.Sprintf(format, args...))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt32(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func getEnvInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func ensureClientID(ip string) int {
	if ip == "" {
		return 0
	}
	clientIDMu.Lock()
	defer clientIDMu.Unlock()
	if id, ok := clientIDByIP[ip]; ok {
		return id
	}
	id := nextClientID
	nextClientID++
	clientIDByIP[ip] = id
	clientIPByID[id] = ip
	return id
}

func getClientIPByID(id int) (string, bool) {
	clientIDMu.Lock()
	defer clientIDMu.Unlock()
	ip, ok := clientIPByID[id]
	return ip, ok
}

func getClientIDByIP(ip string) (int, bool) {
	clientIDMu.Lock()
	defer clientIDMu.Unlock()
	id, ok := clientIDByIP[ip]
	return id, ok
}

func extractRemoteIP(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i > 1 {
			return strings.TrimSpace(addr[1:i])
		}
	}
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return strings.TrimSpace(addr[:i])
	}
	return strings.TrimSpace(addr)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func safeCloseConn(c net.Conn) {
	if c != nil {
		_ = c.Close()
	}
}

func tuneTCPConn(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(TCP_KEEPALIVE_IDLE)
	_ = tcp.SetNoDelay(true)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short write: wrote 0 bytes without error")
		}
		b = b[n:]
	}
	return nil
}

func writeAllWithWriteDeadline(conn net.Conn, b []byte, timeout time.Duration) error {
	if conn == nil {
		return errors.New("nil conn")
	}
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	err := writeAll(conn, b)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// recvFramePooled reads a length-prefixed frame body into a pooled buffer when possible.
// If bufp != nil, the returned payload slice references (*bufp), so caller MUST eventually
// return bufp to frameBodyPool (immediately for non-MUX_DATA, or after consuming MUX payload).
func recvFramePooled(r *bufio.Reader) (sid uint32, msgType byte, payload []byte, bufp *[]byte, bodyLen int, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, nil, 0, err
	}
	ln := int(binary.BigEndian.Uint16(hdr[:]))
	if ln < 5 {
		return 0, 0, nil, nil, 0, errors.New("invalid frame length")
	}
	bodyLen = ln

	if ln <= 5+MUX_CHUNK_MAX {
		bufp = frameBodyPool.Get().(*[]byte)
		buf := (*bufp)[:ln]
		if _, err = io.ReadFull(r, buf); err != nil {
			frameBodyPool.Put(bufp)
			return 0, 0, nil, nil, 0, err
		}
		sid = binary.BigEndian.Uint32(buf[0:4])
		msgType = buf[4]
		payload = buf[5:]
		return sid, msgType, payload, bufp, bodyLen, nil
	}

	body := make([]byte, ln)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, 0, nil, nil, 0, err
	}
	sid = binary.BigEndian.Uint32(body[0:4])
	msgType = body[4]
	payload = body[5:]
	return sid, msgType, payload, nil, bodyLen, nil
}

func writeFrame(conn net.Conn, sid uint32, msgType byte, payload []byte) (int, error) {
	bodyLen := 5 + len(payload)
	if bodyLen > 0xFFFF {
		return 0, errors.New("frame too large")
	}
	var lenHdr [2]byte
	binary.BigEndian.PutUint16(lenHdr[:], uint16(bodyLen))
	var sidHdr [4]byte
	binary.BigEndian.PutUint32(sidHdr[:], sid)
	var tHdr [1]byte
	tHdr[0] = msgType

	bufs := net.Buffers{lenHdr[:], sidHdr[:], tHdr[:], payload}

	_ = conn.SetWriteDeadline(time.Now().Add(CONTROL_WRITE_TIMEOUT))
	n, err := bufs.WriteTo(conn)
	return int(n), err
}

func decClampNonNegative(p *int32) {
	for {
		old := atomic.LoadInt32(p)
		if old <= 0 {
			return
		}
		if atomic.CompareAndSwapInt32(p, old, old-1) {
			return
		}
	}
}

func tryIncLimit(p *int32, limit int32) bool {
	if limit <= 0 {
		atomic.AddInt32(p, 1)
		return true
	}
	for {
		cur := atomic.LoadInt32(p)
		if cur >= limit {
			return false
		}
		if atomic.CompareAndSwapInt32(p, cur, cur+1) {
			return true
		}
	}
}

func (cc *ControlClient) Close(reason string) {
	cc.closeOnce.Do(func() {
		close(cc.done)
		safeCloseConn(cc.conn)

		controlClientsMu.Lock()
		delete(controlClients, cc)
		controlClientsMu.Unlock()

		logf("Control %s closed: %s", cc.addr, reason)

		if v := lastActive.Load(); v != nil {
			if la, ok := v.(*ControlClient); ok && la == cc {
				lastActive.Store((*ControlClient)(nil))
			}
		}

		var sids []uint32
		sessionsMu.RLock()
		for sid, s := range sessions {
			if s != nil && s.control == cc {
				sids = append(sids, sid)
			}
		}
		sessionsMu.RUnlock()
		for _, sid := range sids {
			closeSession(sid, false)
		}
	})
}

func (cc *ControlClient) enqueueHi(f outFrame) error {
	select {
	case <-cc.done:
		return errors.New("control closed")
	default:
	}
	select {
	case cc.outHi <- f:
		return nil
	case <-cc.done:
		return errors.New("control closed")
	default:
		// Hi queue overflow is a strong signal that the link is unhealthy. Close it.
		cc.Close("outHi overflow")
		return errors.New("outHi overflow")
	}
}

func (cc *ControlClient) tryEnqueueHi(f outFrame) bool {
	select {
	case <-cc.done:
		return false
	default:
	}
	select {
	case cc.outHi <- f:
		return true
	default:
		return false
	}
}

// enqueueLoOrDone enqueues to outLo, but also aborts if either control or session is closed.
// Prevents shutdown/cleanup from being blocked forever by a congested outLo.
func (cc *ControlClient) enqueueLoOrDone(done <-chan struct{}, f outFrame) error {
	select {
	case <-cc.done:
		return errors.New("control closed")
	case <-done:
		return errors.New("session closed")
	default:
	}
	select {
	case cc.outLo <- f:
		return nil
	case <-cc.done:
		return errors.New("control closed")
	case <-done:
		return errors.New("session closed")
	}
}

// enqueueLoTimeout tries to enqueue to outLo within timeout.
// Used for best-effort signals (e.g., MSG_MUX_CLOSE) to avoid hanging on overload.
func (cc *ControlClient) enqueueLoTimeout(f outFrame, timeout time.Duration) error {
	select {
	case <-cc.done:
		return errors.New("control closed")
	default:
	}

	if timeout <= 0 {
		select {
		case cc.outLo <- f:
			return nil
		case <-cc.done:
			return errors.New("control closed")
		default:
			return errors.New("outLo full")
		}
	}

	t := time.NewTimer(timeout)
	defer func() {
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}()

	select {
	case cc.outLo <- f:
		return nil
	case <-cc.done:
		return errors.New("control closed")
	case <-t.C:
		return errors.New("outLo enqueue timeout")
	}
}

func (cc *ControlClient) writerLoop() {
	defer cc.drainQueues()
	var sendSeq uint64
	for {
		var f outFrame
		select {
		case <-cc.done:
			return
		case f = <-cc.outHi:
		default:
			select {
			case <-cc.done:
				return
			case f = <-cc.outHi:
			case f = <-cc.outLo:
			}
		}

		if cc.conn == nil {
			cc.Close("nil conn")
			cc.afterFrame(&f)
			return
		}

		plainLen := len(f.payload)
		payload := f.payload
		if v := cc.aead.Load(); v != nil {
			if cfg, ok := v.(*aeadConfig); ok && cfg != nil {
				p, perr := sealFrameAEAD(cfg, &sendSeq, f.sid, f.msgType, payload)
				if perr != nil {
					cc.Close("seal error")
					cc.afterFrame(&f)
					return
				}
				payload = p
			}
		}
		n, err := writeFrame(cc.conn, f.sid, f.msgType, payload)
		if f.bufp != nil {
			dataBufPool.Put(f.bufp)
			f.bufp = nil
		}
		if f.tokenCh != nil {
			select {
			case f.tokenCh <- struct{}{}:
			default:
			}
			f.tokenCh = nil
		}
		if err != nil {
			cc.Close(fmt.Sprintf("write error: %v", err))
			return
		}
		atomic.AddUint64(&cc.tx, uint64(n))
		if f.msgType == MSG_MUX_DATA {
			atomic.AddUint64(&statsForwardedPayloadBytes, uint64(plainLen))
		}
	}
}

func (cc *ControlClient) afterFrame(f *outFrame) {
	if f == nil {
		return
	}
	if f.bufp != nil {
		dataBufPool.Put(f.bufp)
		f.bufp = nil
	}
	if f.tokenCh != nil {
		select {
		case f.tokenCh <- struct{}{}:
		default:
		}
		f.tokenCh = nil
	}
}

func (cc *ControlClient) drainQueues() {
	for {
		drainedAny := false
		for {
			select {
			case f := <-cc.outHi:
				cc.afterFrame(&f)
				drainedAny = true
			default:
				goto lo
			}
		}
	lo:
		for {
			select {
			case f := <-cc.outLo:
				cc.afterFrame(&f)
				drainedAny = true
			default:
				goto done
			}
		}
	done:
		if !drainedAny {
			runtime.Gosched()
			select {
			case f := <-cc.outHi:
				cc.afterFrame(&f)
				continue
			default:
			}
			select {
			case f := <-cc.outLo:
				cc.afterFrame(&f)
				continue
			default:
			}
			return
		}
	}
}

func (cc *ControlClient) muxEnabled() bool {
	return atomic.LoadUint32(&cc.features)&FEATURE_MUX != 0
}

func (cc *ControlClient) capsReady() bool {
	return atomic.LoadUint32(&cc.capsDone) != 0
}

func (cc *ControlClient) getMuxChunk() int {
	v := atomic.LoadInt32(&cc.muxChunk)
	if v <= 0 {
		return MUX_CHUNK_DEFAULT
	}
	return int(v)
}

func (cc *ControlClient) getMaxPend() int32 {
	v := atomic.LoadInt32(&cc.maxPend)
	if v <= 0 {
		return int32(MAX_SESSIONS_PER_CLIENT)
	}
	return v
}

func (cc *ControlClient) getMaxSessions() int32 {
	v := atomic.LoadInt32(&cc.maxMux)
	if v <= 0 {
		return int32(MAX_SESSIONS_PER_CLIENT)
	}
	return v
}

func (cc *ControlClient) getDataInflight() int {
	v := atomic.LoadInt32(&cc.dataInflight)
	if v <= 0 {
		return DATA_INFLIGHT_DEFAULT
	}
	return int(v)
}

func (cc *ControlClient) recommendedMuxInCap() int {
	// Server-side heuristic: keep defaults small to protect memory; slightly increase for "strong" clients.
	cap := MUX_IN_CAP_DEFAULT
	maxMux := atomic.LoadInt32(&cc.maxMux)
	if maxMux > 0 {
		switch {
		case maxMux <= 32:
			cap = 8
		case maxMux >= 200:
			cap = 24
		}
	}
	return clampInt(cap, MUX_IN_CAP_MIN, MUX_IN_CAP_MAX)
}

func handleCaps(cc *ControlClient, payload []byte) {
	// CAPS payload v2 base:
	// ver(1) feats(4) maxMux(2) maxPend(2) muxChunk(2) dataInflight(2) nonce(8)
	// Optional AEAD extension (if FEATURE_AEAD offered):
	// clientRand(32) tagC(16) where tagC = HMAC(PSK, "CAPS" || capsBase || clientRand)[:16]
	if len(payload) < CAPS_BASE_LEN {
		return
	}
	if atomic.LoadUint32(&cc.capsDone) != 0 {
		return
	}
	ver := payload[0]
	if ver != PROTO_VER {
		cc.Close("protocol version mismatch")
		return
	}
	feats := binary.BigEndian.Uint32(payload[1:5])
	if feats&FEATURE_MUX == 0 {
		// No legacy fallback: mux is mandatory.
		cc.Close("client did not offer FEATURE_MUX")
		return
	}

	aeadOffered := (feats & FEATURE_AEAD) != 0
	aeadPolicyOff := strings.TrimSpace(os.Getenv("SOCKS_NO_AEAD")) == "1"

	// If PSK is configured and AEAD is not explicitly disabled, require AEAD from clients.
	// Otherwise a client can bypass PSK by simply not offering FEATURE_AEAD.
	if tcpsocks.HasPSK() && !aeadPolicyOff && !aeadOffered {
		cc.Close("PSK is configured: FEATURE_AEAD required")
		return
	}

	acceptAEAD := aeadOffered && tcpsocks.HasPSK() && !aeadPolicyOff
	var clientRand [32]byte
	if acceptAEAD {
		if len(payload) < CAPS_BASE_LEN+32+16 {
			cc.Close("short CAPS for AEAD")
			return
		}
		copy(clientRand[:], payload[CAPS_BASE_LEN:CAPS_BASE_LEN+32])
		tag := payload[CAPS_BASE_LEN+32 : CAPS_BASE_LEN+32+16]
		key := tcpsocks.PSK()
		expected := hmac16(key[:], []byte("CAPS"), payload[:CAPS_BASE_LEN], clientRand[:])
		if !ctEq16(tag, expected) {
			cc.Close("CAPS HMAC mismatch")
			return
		}
	}

	off := 5
	getU16 := func() uint16 {
		v := binary.BigEndian.Uint16(payload[off : off+2])
		off += 2
		return v
	}
	maxMux := int32(getU16())
	maxPend := int32(getU16())
	muxChunk := int32(getU16())
	dataInflight := int32(getU16())
	nonce := binary.BigEndian.Uint64(payload[13:21])

	acceptedFeats := uint32(FEATURE_MUX)
	if acceptAEAD {
		acceptedFeats |= FEATURE_AEAD
	}

	maxMux = clampInt32(maxMux, 1, int32(MAX_SESSIONS_PER_CLIENT))
	maxPend = clampInt32(maxPend, 1, int32(MAX_SESSIONS_PER_CLIENT))
	if maxPend > maxMux {
		maxPend = maxMux
	}

	// Chunk size negotiation (plaintext bytes per MSG_MUX_DATA).
	if muxChunk <= 0 {
		muxChunk = MUX_CHUNK_DEFAULT
	}
	maxChunk := int32(MUX_CHUNK_MAX)
	if acceptAEAD {
		maxChunk = int32(MUX_CHUNK_MAX - AEAD_TAG_SIZE)
	}
	muxChunk = clampInt32(muxChunk, MUX_CHUNK_MIN, maxChunk)

	if dataInflight <= 0 {
		dataInflight = DATA_INFLIGHT_DEFAULT
	}
	dataInflight = clampInt32(dataInflight, 1, 32)

	// Reply ACK base.
	// Queue ACK before marking CAPS as ready; otherwise CONNECT_REQ/MUX_DATA could be sent before ACK.
	ackBase := make([]byte, CAPS_BASE_LEN)
	ackBase[0] = PROTO_VER
	binary.BigEndian.PutUint32(ackBase[1:5], acceptedFeats)
	binary.BigEndian.PutUint16(ackBase[5:7], uint16(maxMux))
	binary.BigEndian.PutUint16(ackBase[7:9], uint16(maxPend))
	binary.BigEndian.PutUint16(ackBase[9:11], uint16(muxChunk))
	binary.BigEndian.PutUint16(ackBase[11:13], uint16(dataInflight))
	binary.BigEndian.PutUint64(ackBase[13:21], nonce)

	ackPayload := ackBase
	if acceptAEAD {
		serverRand, rerr := rand32()
		if rerr != nil {
			cc.Close("rand failed")
			return
		}
		key := tcpsocks.PSK()
		tagS := hmac16(key[:], []byte("ACK"), ackBase, clientRand[:], serverRand[:])
		ackPayload = make([]byte, 0, len(ackBase)+32+16)
		ackPayload = append(ackPayload, ackBase...)
		ackPayload = append(ackPayload, serverRand[:]...)
		ackPayload = append(ackPayload, tagS[:]...)

		cfg, err := deriveServerAEADConfig(ackBase, clientRand, serverRand)
		if err != nil {
			cc.Close(fmt.Sprintf("AEAD init failed: %v", err))
			return
		}
		cc.aead.Store(cfg)
		logf("Control %s AEAD enabled (AES-GCM)", cc.addr)
	}

	if err := cc.enqueueHi(outFrame{sid: 0, msgType: MSG_CAPS_ACK, payload: ackPayload}); err != nil {
		return
	}

	atomic.StoreUint32(&cc.features, acceptedFeats)
	atomic.StoreInt32(&cc.maxMux, maxMux)
	atomic.StoreInt32(&cc.maxPend, maxPend)
	atomic.StoreInt32(&cc.muxChunk, muxChunk)
	atomic.StoreInt32(&cc.dataInflight, dataInflight)
	atomic.StoreUint32(&cc.capsDone, 1)
}

func controlReader(cc *ControlClient) {
	reader := bufio.NewReaderSize(cc.conn, 64*1024)
	var recvSeq uint64
	capsDeadline := time.Now().Add(CONTROL_CAPS_TIMEOUT)
	for {
		if !cc.capsReady() {
			if time.Now().After(capsDeadline) {
				cc.Close("CAPS timeout")
				break
			}
			_ = cc.conn.SetReadDeadline(capsDeadline)
		} else {
			_ = cc.conn.SetReadDeadline(time.Time{})
		}
		sid, mtype, payload, bufp, bodyLen, err := recvFramePooled(reader)
		if err != nil {
			if !cc.capsReady() && time.Now().After(capsDeadline) {
				cc.Close("CAPS timeout")
			}
			break
		}
		atomic.AddUint64(&cc.rx, uint64(bodyLen))

		if v := cc.aead.Load(); v != nil {
			if cfg, ok := v.(*aeadConfig); ok && cfg != nil {
				p, derr := openFrameAEAD(cfg, &recvSeq, sid, mtype, payload)
				if derr != nil {
					if bufp != nil {
						frameBodyPool.Put(bufp)
					}
					cc.Close(fmt.Sprintf("decrypt error: %v", derr))
					break
				}
				payload = p
			}
		}

		switch mtype {
		case MSG_HEARTBEAT:
			if cc.capsReady() {
				atomic.StoreInt64(&cc.lastHbSec, time.Now().Unix())
			}
			if len(payload) == 8 {
				p := make([]byte, 8)
				copy(p, payload)
				cc.tryEnqueueHi(outFrame{sid: 0, msgType: MSG_HEARTBEAT, payload: p})
			}
			if bufp != nil {
				frameBodyPool.Put(bufp)
			}
		case MSG_CAPS:
			handleCaps(cc, payload)
			if bufp != nil {
				frameBodyPool.Put(bufp)
			}
		case MSG_CONNECT_REPLY:
			if len(payload) >= 1 {
				rep := payload[0]
				sessionsMu.Lock()
				sess := sessions[sid]
				if sess != nil && sess.control == cc {
					if sess.pendingConnect {
						sess.pendingConnect = false
						decClampNonNegative(&cc.pendingConnects)
					}
					select {
					case sess.repCh <- rep:
					default:
					}
				}
				sessionsMu.Unlock()
			}
			if bufp != nil {
				frameBodyPool.Put(bufp)
			}
		case MSG_MUX_DATA:
			// payload references bufp; must be returned after consumption.
			mp := muxPayload{b: payload, bufp: bufp}
			var ok bool
			sessionsMu.RLock()
			sess := sessions[sid]
			if sess == nil || !sess.mux || sess.control != cc {
				sessionsMu.RUnlock()
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
				continue
			}
			select {
			case sess.muxIn <- mp:
				ok = true
			default:
				ok = false
			}
			sessionsMu.RUnlock()
			if ok {
				continue
			}
			if bufp != nil {
				frameBodyPool.Put(bufp)
			}
			closeSession(sid, true)

		case MSG_MUX_CLOSE:
			if bufp != nil {
				frameBodyPool.Put(bufp)
			}
			sessionsMu.RLock()
			sess := sessions[sid]
			own := sess != nil && sess.control == cc
			sessionsMu.RUnlock()
			if !own {
				continue
			}
			closeSession(sid, false)
		default:
			if bufp != nil {
				frameBodyPool.Put(bufp)
			}
		}
	}
	cc.Close("reader exit")
}

func controlAcceptor() {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", CONTROL_PORT))
	if err != nil {
		logf("FATAL: cannot listen control port %d: %v", CONTROL_PORT, err)
		os.Exit(2)
	}
	logf("Control listen 0.0.0.0:%d", CONTROL_PORT)
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("control_acceptor error: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		tuneTCPConn(conn)
		remoteAddr := conn.RemoteAddr().String()
		ip := extractRemoteIP(remoteAddr)
		cid := ensureClientID(ip)
		cc := &ControlClient{
			conn:         conn,
			addr:         remoteAddr,
			ip:           ip,
			clientID:     cid,
			lastHbSec:    time.Now().Unix(),
			maxMux:       MAX_SESSIONS_PER_CLIENT,
			maxPend:      MAX_SESSIONS_PER_CLIENT,
			muxChunk:     MUX_CHUNK_DEFAULT,
			dataInflight: DATA_INFLIGHT_DEFAULT,
			outHi:        make(chan outFrame, 2048),
			outLo:        make(chan outFrame, 8192),
			done:         make(chan struct{}),
		}
		cc.aead.Store((*aeadConfig)(nil))

		controlClientsMu.Lock()
		controlClients[cc] = struct{}{}
		controlClientsMu.Unlock()

		go cc.writerLoop()
		go controlReader(cc)
	}
}

func pickControlClient() *ControlClient {
	// Pinning is opt-in via console: "clients use <ip|id>".
	if v := selectedClient.Load(); v != nil {
		if ip, ok := v.(string); ok {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				return pickControlClientPinned(ip)
			}
		}
	}
	return pickControlClientAuto()
}

func laneState(cc *ControlClient) (score int64, ready bool, eligible bool) {
	select {
	case <-cc.done:
		return 0, false, false
	default:
	}

	if !cc.capsReady() || !cc.muxEnabled() {
		return 0, false, false
	}
	ready = true

	as := atomic.LoadInt32(&cc.activeSessions)
	pend := atomic.LoadInt32(&cc.pendingConnects)
	score = int64(as) + int64(pend)*2

	maxPend := cc.getMaxPend()
	if maxPend > 0 && pend >= maxPend {
		return score, ready, false
	}
	maxSess := cc.getMaxSessions()
	if as >= maxSess {
		return score, ready, false
	}
	return score, ready, true
}

func pickControlClientPinned(ip string) *ControlClient {
	controlClientsMu.RLock()
	defer controlClientsMu.RUnlock()

	var best *ControlClient
	bestScore := int64(1 << 62)
	for cc := range controlClients {
		if cc == nil {
			continue
		}
		if cc.ip != ip {
			continue
		}
		score, ready, eligible := laneState(cc)
		if !ready || !eligible {
			continue
		}
		if best == nil || score < bestScore {
			best = cc
			bestScore = score
		}
	}
	return best
}

func pickControlClientAuto() *ControlClient {
	controlClientsMu.RLock()
	defer controlClientsMu.RUnlock()

	type group struct {
		ip        string
		score     int64
		bestLane  *ControlClient
		bestScore int64
	}

	groups := make(map[string]*group)
	for cc := range controlClients {
		if cc == nil {
			continue
		}
		score, ready, eligible := laneState(cc)
		if !ready {
			continue
		}
		ip := cc.ip
		if ip == "" {
			ip = extractRemoteIP(cc.addr)
		}
		g := groups[ip]
		if g == nil {
			g = &group{ip: ip, bestScore: int64(1 << 62)}
			groups[ip] = g
		}
		g.score += score
		if eligible {
			if g.bestLane == nil || score < g.bestScore {
				g.bestLane = cc
				g.bestScore = score
			}
		}
	}

	minScore := int64(1 << 62)
	candidates := make([]*group, 0, len(groups))
	for _, g := range groups {
		if g.bestLane == nil {
			continue
		}
		candidates = append(candidates, g)
		if g.score < minScore {
			minScore = g.score
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	mins := make([]*group, 0, len(candidates))
	for _, g := range candidates {
		if g.score == minScore {
			mins = append(mins, g)
		}
	}
	if len(mins) == 0 {
		return nil
	}

	sort.Slice(mins, func(i, j int) bool { return mins[i].ip < mins[j].ip })
	idx := int(atomic.AddUint64(&autoPickRR, 1)-1) % len(mins)
	return mins[idx].bestLane
}

func failAndClose(conn net.Conn, reply []byte) {
	_ = writeAllWithWriteDeadline(conn, reply, SOCKS_REPLY_WRITE_TIMEOUT)
	safeCloseConn(conn)
}

func handleSocks5(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(HANDSHAKE_TIMEOUT))

	var h [2]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		safeCloseConn(conn)
		return
	}
	ver := h[0]
	nmethods := int(h[1])
	if ver != 0x05 || nmethods <= 0 {
		safeCloseConn(conn)
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		safeCloseConn(conn)
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_ = writeAll(conn, []byte{0x05, 0xFF})
		safeCloseConn(conn)
		return
	}
	if err := writeAll(conn, []byte{0x05, 0x00}); err != nil {
		safeCloseConn(conn)
		return
	}

	var rh [4]byte
	if _, err := io.ReadFull(conn, rh[:]); err != nil {
		safeCloseConn(conn)
		return
	}
	ver = rh[0]
	cmd := rh[1]
	atyp := rh[3]
	if ver != 0x05 || cmd != 0x01 {
		failAndClose(conn, socksReplyCmdNotSupported)
		return
	}

	var payload []byte
	switch atyp {
	case 0x01: // IPv4
		addrPort := make([]byte, 6)
		if _, err := io.ReadFull(conn, addrPort); err != nil {
			safeCloseConn(conn)
			return
		}
		ip := addrPort[0:4]
		if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
			failAndClose(conn, socksReplyHostUnreachable)
			return
		}
		payload = make([]byte, 1+len(addrPort))
		payload[0] = 0x01
		copy(payload[1:], addrPort)
	case 0x03: // Domain
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			safeCloseConn(conn)
			return
		}
		dn := int(lb[0])
		if dn <= 0 || dn > 255 {
			failAndClose(conn, socksReplyAddrNotSupported)
			return
		}
		domPort := make([]byte, dn+2)
		if _, err := io.ReadFull(conn, domPort); err != nil {
			safeCloseConn(conn)
			return
		}
		payload = make([]byte, 2+len(domPort))
		payload[0] = 0x03
		payload[1] = byte(dn)
		copy(payload[2:], domPort)
	default:
		failAndClose(conn, socksReplyAddrNotSupported)
		return
	}

	_ = conn.SetDeadline(time.Time{})

	if len(requestQueue) > 600 {
		logf("Queue overloaded, drop %s", conn.RemoteAddr().String())
		failAndClose(conn, socksReplyHostUnreachable)
		return
	}

	req := &Request{
		clientConn: conn,
		clientAddr: conn.RemoteAddr().String(),
		payload:    payload,
		done:       make(chan struct{}),
	}

	select {
	case requestQueue <- req:
	default:
		t := time.NewTimer(QUEUE_PUT_TIMEOUT)
		select {
		case requestQueue <- req:
			if !t.Stop() {
				<-t.C
			}
		case <-t.C:
			logf("Queue full, drop %s", req.clientAddr)
			failAndClose(conn, socksReplyHostUnreachable)
			return
		}
	}

	t := time.NewTimer(SOCKS_WAIT_TIMEOUT)
	select {
	case <-req.done:
		if !t.Stop() {
			<-t.C
		}
		return
	case <-t.C:
		logf("Timeout waiting session %s", req.clientAddr)
		failAndClose(conn, socksReplyHostUnreachable)
		return
	}
}

func closeSession(sid uint32, sendClose bool) {
	var sess *Session
	sessionsMu.Lock()
	sess = sessions[sid]
	if sess == nil {
		sessionsMu.Unlock()
		return
	}
	delete(sessions, sid)
	cc := sess.control
	pending := sess.pendingConnect
	mux := sess.mux
	muxIn := sess.muxIn
	sessionsMu.Unlock()

	if cc != nil {
		decClampNonNegative(&cc.activeSessions)
		if pending {
			decClampNonNegative(&cc.pendingConnects)
		}
	}

	decClampNonNegative(&statsActiveSessions)

	sess.markDone()

	safeCloseConn(sess.clientConn)

	if mux && muxIn != nil {
		for {
			select {
			case mp := <-muxIn:
				if mp.bufp != nil {
					frameBodyPool.Put(mp.bufp)
				}
			default:
				goto drained
			}
		}
	}

drained:
	select {
	case sessionTokens <- struct{}{}:
	default:
		logf("WARN: sessionTokens overflow on sid=%d", sid)
	}

	if sendClose && cc != nil && mux {
		go func(cc *ControlClient, sess *Session, sid uint32) {
			err := cc.enqueueLoTimeout(outFrame{sid: sid, msgType: MSG_MUX_CLOSE}, MUX_CLOSE_ENQUEUE_TIMEOUT)
			if err != nil {
				// If we can't even enqueue CLOSE, the lane is unhealthy. Reset it to force client cleanup.
				cc.Close(fmt.Sprintf("enqueue MUX_CLOSE sid=%d: %v", sid, err))
			}
		}(cc, sess, sid)
	}
}

func processRequest(req *Request) {
	<-sessionTokens

	sess := &Session{
		clientConn: req.clientConn,
		repCh:      make(chan byte, 1),
		done:       make(chan struct{}),
	}

	sessionsMu.Lock()
	var sid uint32
	for {
		sid = nextSID
		nextSID++
		if nextSID == 0 {
			nextSID = 1
		}
		if sid == 0 {
			continue
		}
		if _, exists := sessions[sid]; !exists {
			break
		}
	}
	sess.sid = sid
	sessions[sid] = sess
	sessionsMu.Unlock()
	atomic.AddInt32(&statsActiveSessions, 1)

	var cc *ControlClient
	ok := false
	for i := 0; i < 8; i++ {
		cand := pickControlClient()
		if cand == nil {
			break
		}
		maxSess := cand.getMaxSessions()
		if !tryIncLimit(&cand.activeSessions, maxSess) {
			continue
		}
		if !tryIncLimit(&cand.pendingConnects, cand.getMaxPend()) {
			decClampNonNegative(&cand.activeSessions)
			continue
		}
		cc = cand
		ok = true
		break
	}
	if !ok || cc == nil {
		failAndClose(req.clientConn, socksReplyHostUnreachable)
		req.notify()
		closeSession(sid, false)
		return
	}

	sessionsMu.Lock()
	cur := sessions[sid]
	if cur != nil {
		cur.control = cc
		cur.pendingConnect = true
		cur.mux = true
		cur.muxChunk = cc.getMuxChunk()
		cur.muxIn = make(chan muxPayload, cc.recommendedMuxInCap())
		tokN := cc.getDataInflight()
		cur.dataTokens = make(chan struct{}, tokN)
		for i := 0; i < tokN; i++ {
			cur.dataTokens <- struct{}{}
		}
	}
	sessionsMu.Unlock()

	if err := cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REQ, payload: req.payload}); err != nil {
		logf("process_request failed sid=%d: send CONNECT_REQ: %v", sid, err)
		failAndClose(req.clientConn, socksReplyHostUnreachable)
		req.notify()
		closeSession(sid, false)
		return
	}

	tmr := time.NewTimer(CONNECT_REPLY_TIMEOUT)
	var rep byte
	select {
	case rep = <-sess.repCh:
		if !tmr.Stop() {
			<-tmr.C
		}
	case <-tmr.C:
		logf("process_request failed sid=%d: no reply", sid)
		failAndClose(req.clientConn, socksReplyHostUnreachable)
		req.notify()
		closeSession(sid, true)
		return
	}

	if rep != 0x00 {
		reply := make([]byte, 10)
		copy(reply, socksReplySuccess)
		reply[1] = rep
		failAndClose(req.clientConn, reply)
		req.notify()
		closeSession(sid, false)
		return
	}

	if err := writeAllWithWriteDeadline(req.clientConn, socksReplySuccess, SOCKS_REPLY_WRITE_TIMEOUT); err != nil {
		logf("process_request failed sid=%d: send socks success: %v", sid, err)
		req.notify()
		closeSession(sid, true)
		return
	}
	req.notify()

	sessionsMu.RLock()
	cur = sessions[sid]
	sessionsMu.RUnlock()
	if cur == nil {
		return
	}
	go muxLocalToControl(cur)
	go muxControlToLocal(cur)
}

func muxLocalToControl(sess *Session) {
	cc := sess.control
	if cc == nil {
		closeSession(sess.sid, false)
		return
	}
	chunk := sess.muxChunk
	if chunk <= 0 {
		chunk = cc.getMuxChunk()
	}
	chunk = clampInt(chunk, MUX_CHUNK_MIN, MUX_CHUNK_MAX)
	for {
		select {
		case <-sess.done:
			return
		default:
		}

		bp := dataBufPool.Get().(*[]byte)
		buf := (*bp)[:chunk]
		n, rerr := sess.clientConn.Read(buf)
		if n > 0 {
			lastActive.Store(cc)

			select {
			case <-sess.dataTokens:
			case <-sess.done:
				dataBufPool.Put(bp)
				return
			}

			fr := outFrame{sid: sess.sid, msgType: MSG_MUX_DATA, payload: buf[:n], bufp: bp, tokenCh: sess.dataTokens}
			err := cc.enqueueLoOrDone(sess.done, fr)
			if err != nil {
				dataBufPool.Put(bp)
				select {
				case sess.dataTokens <- struct{}{}:
				default:
				}
				closeSession(sess.sid, false)
				return
			}
		} else {
			dataBufPool.Put(bp)
		}
		if rerr != nil {
			closeSession(sess.sid, true)
			return
		}
	}
}

func muxControlToLocal(sess *Session) {
	for {
		select {
		case <-sess.done:
			return
		case mp := <-sess.muxIn:
			if len(mp.b) == 0 {
				if mp.bufp != nil {
					frameBodyPool.Put(mp.bufp)
				}
				continue
			}
			if err := writeAll(sess.clientConn, mp.b); err != nil {
				if mp.bufp != nil {
					frameBodyPool.Put(mp.bufp)
				}
				closeSession(sess.sid, true)
				return
			}
			atomic.AddUint64(&statsForwardedPayloadBytes, uint64(len(mp.b)))
			if sess.control != nil {
				lastActive.Store(sess.control)
			}
			if mp.bufp != nil {
				frameBodyPool.Put(mp.bufp)
			}
		}
	}
}

func queueProcessor() {
	for req := range requestQueue {
		processRequest(req)
	}
}

func fmtBytes(n uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	val := float64(n)
	idx := 0
	for val >= 1024.0 && idx < len(units)-1 {
		val /= 1024.0
		idx++
	}
	return fmt.Sprintf("%.1f%s", val, units[idx])
}

func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	cnt := 0
	for _, e := range entries {
		name := e.Name()
		if name == "" {
			continue
		}
		ok := true
		for i := 0; i < len(name); i++ {
			if name[i] < '0' || name[i] > '9' {
				ok = false
				break
			}
		}
		if ok {
			cnt++
		}
	}
	return cnt
}

func isTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

func statsPrinter() {
	tty := isTTY(os.Stdout)
	interval := 500 * time.Millisecond
	if !tty {
		interval = 10 * time.Second
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	lastLog := time.Now().Add(-10 * time.Second)
	for range t.C {

		controlClientsMu.RLock()
		clientSess := len(controlClients)
		ips := make(map[string]struct{}, clientSess)
		for cc := range controlClients {
			if cc == nil {
				continue
			}
			ip := cc.ip
			if ip == "" {
				ip = extractRemoteIP(cc.addr)
			}
			if ip != "" {
				ips[ip] = struct{}{}
			}
		}
		clients := len(ips)
		controlClientsMu.RUnlock()

		fwd := atomic.LoadUint64(&statsForwardedPayloadBytes)
		sess := atomic.LoadInt32(&statsActiveSessions)
		qsize := len(requestQueue)
		fds := countOpenFDs()

		useStr := "auto"
		if v := selectedClient.Load(); v != nil {
			if s, ok := v.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					useStr = s
				}
			}
		}

		lastStr := "none"
		if v := lastActive.Load(); v != nil {
			if cc, ok := v.(*ControlClient); ok && cc != nil {
				as := atomic.LoadInt32(&cc.activeSessions)
				pend := atomic.LoadInt32(&cc.pendingConnects)
				lastStr = fmt.Sprintf("%s (sess=%d pend=%d)", cc.addr, as, pend)
			}
		}

		if tty && atomic.LoadInt32(&consoleUsed) == 0 {
			line := fmt.Sprintf(
				"Clients:%s%d%s ClientSess:%s%d%s Use:%s%s%s Sess:%s%d%s Data:%s%s%s Queue:%s%d%s FD:%s%d%s last: %s%s%s",
				CLR_GREEN, clients, CLR_RESET,
				CLR_GREEN, clientSess, CLR_RESET,
				CLR_GREEN, useStr, CLR_RESET,
				CLR_YELLOW, sess, CLR_RESET,
				CLR_BLUE, fmtBytes(fwd), CLR_RESET,
				CLR_YELLOW, qsize, CLR_RESET,
				CLR_YELLOW, fds, CLR_RESET,
				CLR_GREEN, lastStr, CLR_RESET,
			)
			fmt.Fprintf(os.Stdout, "\r\033[2K%s", line)
			continue
		}

		if tty {
			if time.Since(lastLog) < 2*time.Second {
				continue
			}
			lastLog = time.Now()
		}
		logf("Stats clients=%d clientSess=%d use=%s sess=%d data=%s queue=%d fd=%d last=%s", clients, clientSess, useStr, sess, fmtBytes(fwd), qsize, fds, lastStr)
	}
}

type clientGroupSnapshot struct {
	ID         int
	IP         string
	ClientSess int
	ReadySess  int
	Sess       int32
	Pend       int32
	Rx         uint64
	Tx         uint64
	HbAgeSec   int64
}

func snapshotClientGroups() []clientGroupSnapshot {
	now := time.Now().Unix()
	groups := make(map[string]*clientGroupSnapshot)

	controlClientsMu.RLock()
	for cc := range controlClients {
		if cc == nil {
			continue
		}
		ip := cc.ip
		if ip == "" {
			ip = extractRemoteIP(cc.addr)
		}
		if ip == "" {
			continue
		}
		g := groups[ip]
		if g == nil {
			g = &clientGroupSnapshot{ID: cc.clientID, IP: ip, HbAgeSec: int64(1 << 62)}
			groups[ip] = g
		}
		g.ClientSess++
		if cc.capsReady() && cc.muxEnabled() {
			g.ReadySess++
		}
		g.Sess += atomic.LoadInt32(&cc.activeSessions)
		g.Pend += atomic.LoadInt32(&cc.pendingConnects)
		g.Rx += atomic.LoadUint64(&cc.rx)
		g.Tx += atomic.LoadUint64(&cc.tx)
		age := now - atomic.LoadInt64(&cc.lastHbSec)
		if age < g.HbAgeSec {
			g.HbAgeSec = age
		}
	}
	controlClientsMu.RUnlock()

	out := make([]clientGroupSnapshot, 0, len(groups))
	for _, g := range groups {
		if g.HbAgeSec == int64(1<<62) {
			g.HbAgeSec = 0
		}
		if g.ID == 0 {
			if id, ok := getClientIDByIP(g.IP); ok {
				g.ID = id
			}
		}
		out = append(out, *g)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != 0 && out[j].ID != 0 {
			return out[i].ID < out[j].ID
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func countClientLanes(ip string) (lanes int, ready int) {
	if ip == "" {
		return 0, 0
	}
	controlClientsMu.RLock()
	defer controlClientsMu.RUnlock()
	for cc := range controlClients {
		if cc == nil {
			continue
		}
		if cc.ip != ip {
			continue
		}
		lanes++
		if cc.capsReady() && cc.muxEnabled() {
			ready++
		}
	}
	return lanes, ready
}

func currentUseStatus() (useStr string, pinnedIP string) {
	useStr = "auto"
	if v := selectedClient.Load(); v != nil {
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s != "" {
				useStr = s
				pinnedIP = s
			}
		}
	}
	return useStr, pinnedIP
}

func printUseStatus() {
	useStr, pinnedIP := currentUseStatus()
	if pinnedIP == "" {
		fmt.Printf("Use: %s (all clients)\n", useStr)
		return
	}
	id, _ := getClientIDByIP(pinnedIP)
	lanes, ready := countClientLanes(pinnedIP)
	if id > 0 {
		fmt.Printf("Use: pinned %s (ID %d, lanes=%d, ready=%d)\n", pinnedIP, id, lanes, ready)
		return
	}
	fmt.Printf("Use: pinned %s (lanes=%d, ready=%d)\n", pinnedIP, lanes, ready)
}

func printClientsTable() {
	groups := snapshotClientGroups()
	useStr, pinnedIP := currentUseStatus()
	clientSess := 0
	for _, g := range groups {
		clientSess += g.ClientSess
	}
	fmt.Printf("Use: %s | Clients: %d | ClientSess: %d\n", useStr, len(groups), clientSess)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tClientSess\tReady\tSess\tPend\tRx\tTx\tHB")
	for _, g := range groups {
		mark := ""
		if pinnedIP != "" && g.IP == pinnedIP {
			mark = "*"
		}
		readyStr := fmt.Sprintf("%d/%d", g.ReadySess, g.ClientSess)
		fmt.Fprintf(w, "%s%d\t%s\t%d\t%s\t%d\t%d\t%s\t%s\t%ds\n",
			mark,
			g.ID,
			g.IP,
			g.ClientSess,
			readyStr,
			g.Sess,
			g.Pend,
			fmtBytes(g.Rx),
			fmtBytes(g.Tx),
			g.HbAgeSec,
		)
	}
	_ = w.Flush()
}

func handleClientsCommand(args []string) {
	if len(args) == 0 {
		printClientsTable()
		return
	}
	if args[0] != "use" {
		fmt.Println("Usage: clients [use <auto|status|ip|id>]")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: clients use <auto|status|ip|id>")
		return
	}
	sub := strings.TrimSpace(args[1])
	switch sub {
	case "auto":
		selectedClient.Store("")
		printUseStatus()
		return
	case "status":
		printUseStatus()
		return
	default:
	}

	var ip string
	if isAllDigits(sub) {
		id, err := strconv.Atoi(sub)
		if err != nil || id <= 0 {
			fmt.Println("Invalid client ID")
			return
		}
		v, ok := getClientIPByID(id)
		if !ok || v == "" {
			fmt.Printf("Client with ID %d not found. Use 'clients' to list clients.\n", id)
			return
		}
		ip = v
	} else {
		ip = sub
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		fmt.Println("Invalid client IP")
		return
	}
	lanes, ready := countClientLanes(ip)
	if lanes == 0 {
		fmt.Printf("Client %s not found. Use 'clients' to list clients.\n", ip)
		return
	}
	selectedClient.Store(ip)
	printUseStatus()
	if ready == 0 {
		fmt.Println("WARN: selected client is not ready yet (CAPS/MUX not negotiated).")
	}
}

func consoleLoop() {
	if !isTTY(os.Stdin) {
		return
	}
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if atomic.CompareAndSwapInt32(&consoleUsed, 0, 1) {
			fmt.Fprintf(os.Stdout, "\r\033[2K\n")
		}
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "clients":
			handleClientsCommand(args[1:])
		default:
			fmt.Printf("Unknown command: %s\n", args[0])
		}
	}
	if err := s.Err(); err != nil {
		logf("console error: %v", err)
	}
}

func controlReaper() {
	for {
		time.Sleep(CONTROL_REAPER_INTERVAL)
		now := time.Now().Unix()

		controlClientsMu.RLock()
		clients := make([]*ControlClient, 0, len(controlClients))
		for cc := range controlClients {
			clients = append(clients, cc)
		}
		controlClientsMu.RUnlock()

		for _, cc := range clients {
			last := atomic.LoadInt64(&cc.lastHbSec)
			if now-last > int64(CONTROL_HB_TIMEOUT/time.Second) {
				cc.Close("timeout")
			}
		}
	}
}

func socksAcceptor(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		logf("FATAL: cannot listen SOCKS5 port %d: %v", port, err)
		os.Exit(2)
	}
	logf("SOCKS5 listen 0.0.0.0:%d (control %d)", port, CONTROL_PORT)
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("socks_acceptor error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		tuneTCPConn(conn)
		go handleSocks5(conn)
	}
}

func usageAndExit() {
	bin := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s -socks <socks_port>\n", bin)
	fmt.Fprintf(os.Stderr, "   or: %s <socks_port>\n", bin)
	os.Exit(1)
}

func main() {
	var socksPort int
	flag.IntVar(&socksPort, "socks", 0, "SOCKS5 listen port")
	flag.Parse()
	if err := tcpsocks.LoadPSK(); err != nil {
		logf("FATAL: %v", err)
		os.Exit(2)
	}
	allowPlain := strings.TrimSpace(os.Getenv("SOCKS_ALLOW_PLAINTEXT")) == "1"
	if !tcpsocks.HasPSK() && !allowPlain {
		logf("FATAL: SOCKS_PSK_HEX is not set. Refusing to run with plaintext control channel. Set SOCKS_PSK_HEX (64 hex chars) or SOCKS_ALLOW_PLAINTEXT=1 (insecure).")
		os.Exit(2)
	}
	if strings.TrimSpace(os.Getenv("SOCKS_NO_AEAD")) == "1" && !allowPlain {
		logf("FATAL: SOCKS_NO_AEAD=1 would disable encryption. Refusing to run. Unset SOCKS_NO_AEAD or set SOCKS_ALLOW_PLAINTEXT=1 (insecure).")
		os.Exit(2)
	}
	if tcpsocks.HasPSK() && strings.TrimSpace(os.Getenv("SOCKS_NO_AEAD")) != "1" {
		logf("AEAD enabled (PSK loaded)")
	} else if allowPlain {
		logf("WARN: running in insecure plaintext mode (SOCKS_ALLOW_PLAINTEXT=1)")
	}

	if socksPort == 0 {
		if flag.NArg() == 1 {
			p, err := strconv.Atoi(flag.Arg(0))
			if err == nil {
				socksPort = p
			}
		}
	}
	if socksPort <= 0 || socksPort > 65535 {
		usageAndExit()
	}

	for i := 0; i < MAX_SESSIONS; i++ {
		sessionTokens <- struct{}{}
	}

	lastActive.Store((*ControlClient)(nil))
	selectedClient.Store("")

	go controlAcceptor()
	go socksAcceptor(socksPort)
	go statsPrinter()
	go controlReaper()
	go consoleLoop()
	workers := getEnvInt("SOCKS_QUEUE_WORKERS", 0)
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0) * 8
	}
	workers = clampInt(workers, 8, 512)
	for i := 0; i < workers; i++ {
		go queueProcessor()
	}

	select {}
}
