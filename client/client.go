package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"tcpsocks"
	"time"
)

var (
	serviceName        = "SOCKS"
	serviceDescription = "Client "

	SOCKSIP = "0"

	serviceEnvVar   = "SOCKS_SERVICE_RUN"
	noServiceEnvVar = "SOCKS_NO_SERVICE"
)

var (
	traceEnabled bool
)

const (
	MSG_HEARTBEAT     = 0
	MSG_CONNECT_REQ   = 1
	MSG_CONNECT_REPLY = 2

	MSG_CAPS      = 10
	MSG_CAPS_ACK  = 11
	MSG_MUX_DATA  = 12
	MSG_MUX_CLOSE = 13
)

const (
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
	controlDialTimeout = 6 * time.Second
	remoteDialTimeout  = 6 * time.Second

	heartbeatInterval = 15 * time.Second
	keepAlivePeriod   = 30 * time.Second

	controlWriteTimeout = 15 * time.Second

	reconnectBaseDelay = 500 * time.Millisecond
	reconnectMaxDelay  = 30 * time.Second

	capsAckTimeout = 3 * time.Second

	heartbeatJitterMax = 2 * time.Second

	connectQueueSize = 1024

	forwardBufSize = 8192

	MUX_CHUNK_MIN     = 1024
	MUX_CHUNK_DEFAULT = 8192
	MUX_CHUNK_MAX     = 16384

	// Per-session inbound buffering limit for MUX_DATA.
	MUX_IN_CAP_MIN     = 4
	MUX_IN_CAP_DEFAULT = 16
	MUX_IN_CAP_MAX     = 64

	// Per-session in-flight DATA chunk limit for fairness (fair queuing).
	DATA_INFLIGHT_DEFAULT = 4

	// HOL blocking mitigation: multiple control connections.
	CONTROL_CONNS_DEFAULT = 2
	CONTROL_CONNS_MAX     = 4

	// Best-effort enqueue timeout for MSG_MUX_CLOSE under congestion.
	MUX_CLOSE_ENQUEUE_TIMEOUT = 300 * time.Millisecond
)

var (
	errUnsupportedATYP   = errors.New("unsupported atyp")
	errBadConnectPayload = errors.New("bad connect payload")
)

type aeadConfig struct {
	send cipher.AEAD
	recv cipher.AEAD

	sendSalt [4]byte
	recvSalt [4]byte
}

func loadTraceFlag() {
	traceEnabled = strings.TrimSpace(os.Getenv("SOCKS_TRACE")) != ""
}

func tracef(format string, args ...any) {
	if !traceEnabled {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(os.Stderr, "[%s] "+format+"\n", append([]any{ts}, args...)...)
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

func deriveClientAEADConfig(ackBase []byte, clientRand, serverRand [32]byte) (*aeadConfig, error) {
	// prk = HMAC(PSK, "KDF" || ackBase || clientRand || serverRand)
	key := tcpsocks.PSK()
	prk := hmac32(key[:], []byte("KDF"), ackBase, clientRand[:], serverRand[:])
	keyC2S := hmac32(prk[:], []byte("c2s"))
	keyS2C := hmac32(prk[:], []byte("s2c"))
	saltC2S := hmac32(prk[:], []byte("c2s_salt"))
	saltS2C := hmac32(prk[:], []byte("s2c_salt"))

	sendAEAD, err := newGCM(keyC2S)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := newGCM(keyS2C)
	if err != nil {
		return nil, err
	}

	cfg := &aeadConfig{send: sendAEAD, recv: recvAEAD}
	copy(cfg.sendSalt[:], saltC2S[:4])
	copy(cfg.recvSalt[:], saltS2C[:4])
	return cfg, nil
}

type muxPayload struct {
	b    []byte
	bufp *[]byte // return to frameBodyPool after consumption
}

type outFrame struct {
	sid     uint32
	msgType byte
	payload []byte

	bufp    *[]byte       // return to forwardBufPool after send
	tokenCh chan struct{} // release token after send
}

type session struct {
	remote net.Conn
	cc     *controlConn

	mux bool

	muxIn chan muxPayload

	dataTokens chan struct{}
	done       chan struct{}
	doneOnce   sync.Once
}

var (
	sessions   = make(map[uint32]*session)
	sessionsMu sync.RWMutex

	// Buffers for reads from remote / MUX forwarding.
	forwardBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, maxInt(forwardBufSize, MUX_CHUNK_MAX))
			return &b
		},
	}

	// Buffers for reading control frames (body = 4 sid + 1 type + payload).
	frameBodyPool = sync.Pool{
		New: func() any {
			b := make([]byte, 5+MUX_CHUNK_MAX)
			return &b
		},
	}
)

type controlConn struct {
	conn       net.Conn
	serverHost string
	addr       string

	outHi chan outFrame
	outLo chan outFrame
	done  chan struct{}

	closeOnce sync.Once

	// AEAD state is published after CAPS_ACK when FEATURE_AEAD was negotiated.
	// Stored as *aeadConfig via atomic.Value to avoid data races with writerLoop.
	aead atomic.Value // *aeadConfig

	wantAEAD       bool
	capsClientRand [32]byte

	features     uint32
	capsDone     uint32
	maxMux       int32
	maxPend      int32
	muxChunk     int32
	dataInflight int32

	rttNanos int64
}

type connectJob struct {
	sid     uint32
	payload []byte
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

func safeClose(c net.Conn) {
	if c != nil {
		_ = c.Close()
	}
}

func applyTCPOptions(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(keepAlivePeriod)
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

func sendFrameVec(conn net.Conn, sid uint32, msgType byte, payload []byte) error {
	bodyLen := 5 + len(payload)
	if bodyLen > 0xFFFF {
		return errors.New("frame too large")
	}

	var hdr2 [2]byte
	binary.BigEndian.PutUint16(hdr2[:], uint16(bodyLen))
	var sid4 [4]byte
	binary.BigEndian.PutUint32(sid4[:], sid)
	var typ1 [1]byte
	typ1[0] = msgType

	bufs := net.Buffers{hdr2[:], sid4[:], typ1[:], payload}
	_, err := bufs.WriteTo(conn)
	return err
}

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
		b := (*bufp)[:ln]
		if _, err = io.ReadFull(r, b); err != nil {
			frameBodyPool.Put(bufp)
			return 0, 0, nil, nil, 0, err
		}
		sid = binary.BigEndian.Uint32(b[0:4])
		msgType = b[4]
		payload = b[5:]
		return sid, msgType, payload, bufp, bodyLen, nil
	}

	b := make([]byte, ln)
	if _, err = io.ReadFull(r, b); err != nil {
		return 0, 0, nil, nil, 0, err
	}
	sid = binary.BigEndian.Uint32(b[0:4])
	msgType = b[4]
	payload = b[5:]
	return sid, msgType, payload, nil, bodyLen, nil
}

func (cc *controlConn) muxEnabled() bool {
	return atomic.LoadUint32(&cc.features)&FEATURE_MUX != 0
}

func (cc *controlConn) getMuxChunk() int {
	v := atomic.LoadInt32(&cc.muxChunk)
	if v <= 0 {
		return MUX_CHUNK_DEFAULT
	}
	return int(v)
}

func (cc *controlConn) getDataInflight() int {
	v := atomic.LoadInt32(&cc.dataInflight)
	if v <= 0 {
		return DATA_INFLIGHT_DEFAULT
	}
	return int(v)
}

func (cc *controlConn) recommendedMuxInCap() int {
	cap := MUX_IN_CAP_DEFAULT
	rtt := time.Duration(atomic.LoadInt64(&cc.rttNanos))
	switch {
	case rtt > 0 && rtt <= 35*time.Millisecond:
		cap = 32
	case rtt > 120*time.Millisecond:
		cap = 12
	case rtt > 35*time.Millisecond:
		cap = 16
	}

	maxMux := atomic.LoadInt32(&cc.maxMux)
	if maxMux > 0 {
		switch {
		case maxMux <= 32:
			cap = cap / 2
		case maxMux >= 200:
			cap = cap + 4
		}
	}
	return clampInt(cap, MUX_IN_CAP_MIN, MUX_IN_CAP_MAX)
}

func (cc *controlConn) enqueueHi(f outFrame) error {
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
		cc.Close("outHi overflow")
		return errors.New("outHi overflow")
	}
}

func (cc *controlConn) tryEnqueueHi(f outFrame) bool {
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
func (cc *controlConn) enqueueLoOrDone(done <-chan struct{}, f outFrame) error {
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
func (cc *controlConn) enqueueLoTimeout(f outFrame, timeout time.Duration) error {
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
			// Timer may have already fired. If the timeout branch in the select
			// below was chosen, its value has already been received, so a blocking
			// drain would deadlock. Drain non-blocking.
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

func (cc *controlConn) writerLoop() {
	defer cc.drainQueues()
	var sendSeq uint64
	for {
		select {
		case <-cc.done:
			return
		default:
		}

		var f outFrame
		select {
		case f = <-cc.outHi:
		default:
			select {
			case f = <-cc.outHi:
			case f = <-cc.outLo:
			case <-cc.done:
				return
			}
		}

		if cc.conn == nil {
			cc.releaseFrame(&f)
			cc.Close("nil conn")
			return
		}

		payload := f.payload
		if v := cc.aead.Load(); v != nil {
			if cfg, ok := v.(*aeadConfig); ok && cfg != nil {
				p, perr := sealFrameAEAD(cfg, &sendSeq, f.sid, f.msgType, payload)
				if perr != nil {
					cc.releaseFrame(&f)
					cc.Close("seal error")
					return
				}
				payload = p
			}
		}

		_ = cc.conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		err := sendFrameVec(cc.conn, f.sid, f.msgType, payload)
		cc.releaseFrame(&f)
		if err != nil {
			cc.Close("writer error")
			return
		}
	}
}

func (cc *controlConn) drainQueues() {
	for {
		drainedAny := false
		for {
			select {
			case f := <-cc.outHi:
				cc.releaseFrame(&f)
				drainedAny = true
			default:
				goto lo
			}
		}
	lo:
		for {
			select {
			case f := <-cc.outLo:
				cc.releaseFrame(&f)
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
				cc.releaseFrame(&f)
				continue
			default:
			}
			select {
			case f := <-cc.outLo:
				cc.releaseFrame(&f)
				continue
			default:
			}
			return
		}
	}
}

func (cc *controlConn) releaseFrame(f *outFrame) {
	if f.bufp != nil {
		forwardBufPool.Put(f.bufp)
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

func (cc *controlConn) Close(reason string) {
	cc.closeOnce.Do(func() {
		close(cc.done)
		safeClose(cc.conn)

		var sids []uint32
		sessionsMu.RLock()
		for sid, sess := range sessions {
			if sess != nil && sess.cc == cc {
				sids = append(sids, sid)
			}
		}
		sessionsMu.RUnlock()
		for _, sid := range sids {
			cleanupSession(sid, false)
		}

		_ = reason
	})
}

func heartbeatLoop(cc *controlConn) {
	if heartbeatJitterMax > 0 {
		sleep := time.Duration(time.Now().UnixNano() % int64(heartbeatJitterMax))
		time.Sleep(sleep)
	}

	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()

	for {
		select {
		case <-cc.done:
			return
		case <-t.C:
			nonce := uint64(time.Now().UnixNano())
			p := make([]byte, 8)
			binary.BigEndian.PutUint64(p, nonce)
			_ = cc.tryEnqueueHi(outFrame{sid: 0, msgType: MSG_HEARTBEAT, payload: p})
		}
	}
}

func buildCapsPayload(features uint32, maxMux, maxPend, muxChunk, dataInflight int, nonce uint64) []byte {
	// CAPS payload v2:
	// ver(1) feats(4) maxMux(2) maxPend(2) muxChunk(2) dataInflight(2) nonce(8)
	p := make([]byte, CAPS_BASE_LEN)
	p[0] = PROTO_VER
	binary.BigEndian.PutUint32(p[1:5], features)
	binary.BigEndian.PutUint16(p[5:7], uint16(maxMux))
	binary.BigEndian.PutUint16(p[7:9], uint16(maxPend))
	binary.BigEndian.PutUint16(p[9:11], uint16(muxChunk))
	binary.BigEndian.PutUint16(p[11:13], uint16(dataInflight))
	binary.BigEndian.PutUint64(p[13:21], nonce)
	return p
}

func handleCapsAck(cc *controlConn, payload []byte) {
	if len(payload) < CAPS_BASE_LEN {
		return
	}
	if payload[0] != PROTO_VER {
		cc.Close("protocol version mismatch")
		return
	}
	feats := binary.BigEndian.Uint32(payload[1:5])
	if feats&FEATURE_MUX == 0 {
		cc.Close("server did not accept FEATURE_MUX")
		return
	}

	aeadAccepted := (feats & FEATURE_AEAD) != 0
	if cc.wantAEAD && !aeadAccepted {
		cc.Close("server did not accept FEATURE_AEAD")
		return
	}
	if !cc.wantAEAD && aeadAccepted {
		cc.Close("server enabled FEATURE_AEAD unexpectedly")
		return
	}
	maxMux := int32(binary.BigEndian.Uint16(payload[5:7]))
	maxPend := int32(binary.BigEndian.Uint16(payload[7:9]))
	muxChunk := int32(binary.BigEndian.Uint16(payload[9:11]))
	dataInflight := int32(binary.BigEndian.Uint16(payload[11:13]))
	nonce := binary.BigEndian.Uint64(payload[13:21])

	if aeadAccepted {
		if muxChunk > int32(MUX_CHUNK_MAX-AEAD_TAG_SIZE) {
			cc.Close("server muxChunk too large for AEAD")
			return
		}
		if len(payload) < CAPS_BASE_LEN+32+16 {
			cc.Close("short CAPS_ACK for AEAD")
			return
		}
		var serverRand [32]byte
		copy(serverRand[:], payload[CAPS_BASE_LEN:CAPS_BASE_LEN+32])
		tag := payload[CAPS_BASE_LEN+32 : CAPS_BASE_LEN+32+16]
		key := tcpsocks.PSK()
		expected := hmac16(key[:], []byte("ACK"), payload[:CAPS_BASE_LEN], cc.capsClientRand[:], serverRand[:])
		if !ctEq16(tag, expected) {
			cc.Close("CAPS_ACK HMAC mismatch")
			return
		}
		cfg, err := deriveClientAEADConfig(payload[:CAPS_BASE_LEN], cc.capsClientRand, serverRand)
		if err != nil {
			cc.Close(fmt.Sprintf("AEAD init failed: %v", err))
			return
		}
		cc.aead.Store(cfg)
		tracef("%s AEAD enabled (AES-GCM)", cc.addr)
	}

	atomic.StoreUint32(&cc.features, feats)
	atomic.StoreInt32(&cc.maxMux, maxMux)
	atomic.StoreInt32(&cc.maxPend, maxPend)
	atomic.StoreInt32(&cc.muxChunk, muxChunk)
	atomic.StoreInt32(&cc.dataInflight, dataInflight)
	atomic.StoreUint32(&cc.capsDone, 1)

	if nonce != 0 {
		now := time.Now().UnixNano()
		d := now - int64(nonce)
		if d > 0 {
			updateEWMAInt64(&cc.rttNanos, d, 8)
		}
	}
}

func updateEWMAInt64(dst *int64, sample int64, weight int64) {
	for {
		old := atomic.LoadInt64(dst)
		if old == 0 {
			if atomic.CompareAndSwapInt64(dst, old, sample) {
				return
			}
			continue
		}
		newv := (old*(weight-1) + sample) / weight
		if atomic.CompareAndSwapInt64(dst, old, newv) {
			return
		}
	}
}

func cleanupSession(sid uint32, sendClose bool) {
	sessionsMu.Lock()
	sess := sessions[sid]
	if sess != nil {
		delete(sessions, sid)
	}
	sessionsMu.Unlock()

	if sess == nil {
		return
	}

	sess.doneOnce.Do(func() { close(sess.done) })

	if sendClose && sess.mux && sess.cc != nil {
		// Best-effort: do not hang cleanup on congested outLo.
		cc := sess.cc
		go func(cc *controlConn, sess *session, sid uint32) {
			err := cc.enqueueLoTimeout(outFrame{sid: sid, msgType: MSG_MUX_CLOSE}, MUX_CLOSE_ENQUEUE_TIMEOUT)
			if err != nil {
				// If we can't even enqueue CLOSE, the lane is unhealthy. Reset it to force server cleanup.
				cc.Close(fmt.Sprintf("enqueue MUX_CLOSE sid=%d: %v", sid, err))
			}
		}(cc, sess, sid)
	}

	if sess.muxIn != nil {
		for {
			select {
			case mp := <-sess.muxIn:
				if mp.bufp != nil {
					frameBodyPool.Put(mp.bufp)
				}
			default:
				goto drained
			}
		}
	drained:
	}

	safeClose(sess.remote)
}

func parseConnectPayload(payload []byte) (string, uint16, error) {
	if len(payload) < 1 {
		return "", 0, fmt.Errorf("%w: empty payload", errBadConnectPayload)
	}

	atyp := payload[0]
	switch atyp {
	case 1: // IPv4
		if len(payload) < 7 {
			return "", 0, fmt.Errorf("%w: short ipv4 payload", errBadConnectPayload)
		}
		ip := net.IP(payload[1:5])
		port := binary.BigEndian.Uint16(payload[5:7])
		return ip.String(), port, nil
	case 3: // Domain
		if len(payload) < 4 {
			return "", 0, fmt.Errorf("%w: short domain payload", errBadConnectPayload)
		}
		n := int(payload[1])
		if n <= 0 {
			return "", 0, fmt.Errorf("%w: empty domain", errBadConnectPayload)
		}
		if len(payload) < 2+n+2 {
			return "", 0, fmt.Errorf("%w: short domain payload", errBadConnectPayload)
		}
		host := string(payload[2 : 2+n])
		port := binary.BigEndian.Uint16(payload[2+n : 2+n+2])
		return host, port, nil
	default:
		return "", 0, fmt.Errorf("%w: atyp=%d", errUnsupportedATYP, atyp)
	}
}

func socksRepForParseError(err error) byte {
	if err == nil {
		return 0
	}
	if errors.Is(err, errUnsupportedATYP) {
		return 0x08 // Address type not supported
	}
	return 0x01
}

func socksRepForDialError(err error) byte {
	if err == nil {
		return 0
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 0x04
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return 0x05 // Connection refused
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ETIMEDOUT) {
		return 0x04 // Host unreachable
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return 0x04
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return 0x04
	}

	return 0x04
}

func muxServerToRemote(sid uint32, sess *session) {
	for {
		select {
		case <-sess.done:
			return
		case mp := <-sess.muxIn:
			if len(mp.b) > 0 {
				if err := writeAll(sess.remote, mp.b); err != nil {
					if mp.bufp != nil {
						frameBodyPool.Put(mp.bufp)
					}
					cleanupSession(sid, true)
					return
				}
			}
			if mp.bufp != nil {
				frameBodyPool.Put(mp.bufp)
			}
		}
	}
}

func muxRemoteToServer(sid uint32, sess *session) {
	cc := sess.cc
	if cc == nil {
		cleanupSession(sid, true)
		return
	}

	chunk := cc.getMuxChunk()
	for {
		bp := forwardBufPool.Get().(*[]byte)
		buf := (*bp)[:chunk]
		n, rerr := sess.remote.Read(buf)
		if n > 0 {
			select {
			case <-sess.dataTokens:
			case <-sess.done:
				forwardBufPool.Put(bp)
				return
			}

			f := outFrame{sid: sid, msgType: MSG_MUX_DATA, payload: buf[:n], bufp: bp, tokenCh: sess.dataTokens}
			err := cc.enqueueLoOrDone(sess.done, f)
			if err != nil {
				forwardBufPool.Put(bp)
				select {
				case sess.dataTokens <- struct{}{}:
				default:
				}
				cleanupSession(sid, true)
				return
			}
		} else {
			forwardBufPool.Put(bp)
		}
		if rerr != nil {
			break
		}
	}
	cleanupSession(sid, true)
}

func handleConnectReq(ctx context.Context, cc *controlConn, sid uint32, payload []byte) {
	host, port, err := parseConnectPayload(payload)
	if err != nil {
		rep := socksRepForParseError(err)
		_ = cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REPLY, payload: []byte{rep}})
		return
	}

	if !cc.muxEnabled() {
		_ = cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REPLY, payload: []byte{4}})
		cc.Close("mux not enabled")
		return
	}

	sessionsMu.Lock()
	if old := sessions[sid]; old != nil {
		if old.cc != cc {
			sessionsMu.Unlock()
			_ = cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REPLY, payload: []byte{4}})
			cc.Close("sid belongs to another control connection")
			return
		}
	}
	sessionsMu.Unlock()

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	d := net.Dialer{Timeout: remoteDialTimeout, KeepAlive: keepAlivePeriod}
	remote, err := d.DialContext(ctx, "tcp", addr)

	rep := byte(0)
	if err != nil {
		rep = socksRepForDialError(err)
	} else {
		applyTCPOptions(remote)
		sess := &session{remote: remote, cc: cc, done: make(chan struct{})}

		sess.mux = true
		sess.muxIn = make(chan muxPayload, cc.recommendedMuxInCap())
		infl := cc.getDataInflight()
		sess.dataTokens = make(chan struct{}, infl)
		for i := 0; i < infl; i++ {
			sess.dataTokens <- struct{}{}
		}

		sessionsMu.Lock()
		if old := sessions[sid]; old != nil {
			if old.cc != cc {
				sessionsMu.Unlock()
				safeClose(remote)
				_ = cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REPLY, payload: []byte{4}})
				cc.Close("sid belongs to another control connection")
				return
			}
			sessionsMu.Unlock()
			cleanupSession(sid, true)
			sessionsMu.Lock()
		}
		sessions[sid] = sess
		sessionsMu.Unlock()

		go muxServerToRemote(sid, sess)
		go muxRemoteToServer(sid, sess)
	}

	select {
	case <-ctx.Done():
		if rep == 0 {
			cleanupSession(sid, true)
		}
		return
	default:
	}

	_ = cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REPLY, payload: []byte{rep}})
	if rep != 0 {
		cleanupSession(sid, true)
	}
}

func connectWorker(ctx context.Context, cc *controlConn, jobs <-chan connectJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			handleConnectReq(ctx, cc, job.sid, job.payload)
		}
	}
}

func getEnvInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

type capsConfig struct {
	featuresWanted uint32
	maxMux         int
	maxPend        int
	muxChunk       int
	dataInflight   int
	controlConns   int
}

func readRlimitNOFILE() (uint64, bool) {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0, false
	}
	if r.Cur == 0 {
		return 0, false
	}
	return r.Cur, true
}

func computeCaps(controlConns int) capsConfig {
	cc := controlConns
	if cc < 1 {
		cc = CONTROL_CONNS_DEFAULT
	}
	if cc > CONTROL_CONNS_MAX {
		cc = CONTROL_CONNS_MAX
	}

	wantAEAD := tcpsocks.HasPSK() && strings.TrimSpace(os.Getenv("SOCKS_NO_AEAD")) != "1"

	maxChunk := MUX_CHUNK_MAX
	if wantAEAD {
		maxChunk = MUX_CHUNK_MAX - AEAD_TAG_SIZE
	}
	muxChunk := getEnvInt("SOCKS_MUX_CHUNK", MUX_CHUNK_DEFAULT)
	muxChunk = clampInt(muxChunk, MUX_CHUNK_MIN, maxChunk)

	infl := getEnvInt("SOCKS_DATA_INFLIGHT", DATA_INFLIGHT_DEFAULT)
	infl = clampInt(infl, 1, 32)

	fdLimit, ok := readRlimitNOFILE()
	if !ok {
		fdLimit = 1024
	}

	if fdLimit < 128 && cc > 1 {
		cc = 1
	}

	reserve := uint64(64 + cc)
	if fdLimit <= reserve+8 {
		fdLimit = reserve + 8
	}
	budget := int(fdLimit - reserve)

	maxMuxTotal := budget

	if maxMuxTotal > 1200 {
		maxMuxTotal = 1200
	}

	cpu := runtime.NumCPU()
	maxPendTotal := cpu * 8
	if maxPendTotal < 16 {
		maxPendTotal = 16
	}
	if maxPendTotal > 256 {
		maxPendTotal = 256
	}
	if maxPendTotal > maxMuxTotal {
		maxPendTotal = maxMuxTotal
	}

	maxMux := maxMuxTotal / cc
	maxPend := maxPendTotal / cc

	if maxMux < 1 {
		maxMux = 1
	}
	if maxPend < 1 {
		maxPend = 1
	}
	if maxPend > maxMux {
		maxPend = maxMux
	}

	if v := getEnvInt("SOCKS_CAP_MAXMUX", 0); v > 0 {
		maxMux = v
	}
	if v := getEnvInt("SOCKS_CAP_MAXPEND", 0); v > 0 {
		maxPend = v
	}

	maxMux = clampInt(maxMux, 1, 300)
	maxPend = clampInt(maxPend, 1, 300)
	if maxPend > maxMux {
		maxPend = maxMux
	}

	features := uint32(FEATURE_MUX)
	if wantAEAD {
		features |= FEATURE_AEAD
	}
	return capsConfig{
		featuresWanted: features,
		maxMux:         maxMux,
		maxPend:        maxPend,
		muxChunk:       muxChunk,
		dataInflight:   infl,
		controlConns:   cc,
	}
}

func controlLoopLane(serverHost string, controlPort int, laneID int, caps capsConfig) {
	addr := net.JoinHostPort(serverHost, strconv.Itoa(controlPort))

	backoff := reconnectBaseDelay
	sleepBackoff := func() {
		jitterMax := backoff / 2
		jitter := time.Duration(0)
		if jitterMax > 0 {
			jitter = time.Duration(time.Now().UnixNano() % int64(jitterMax))
		}
		time.Sleep(backoff + jitter)

		if backoff < reconnectMaxDelay {
			backoff *= 2
			if backoff > reconnectMaxDelay {
				backoff = reconnectMaxDelay
			}
		}
	}
	resetBackoff := func() { backoff = reconnectBaseDelay }
	for {
		d := net.Dialer{Timeout: controlDialTimeout, KeepAlive: keepAlivePeriod}
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			sleepBackoff()
			continue
		}

		applyTCPOptions(conn)

		cc := &controlConn{
			conn:         conn,
			serverHost:   serverHost,
			addr:         fmt.Sprintf("%s#%d", addr, laneID),
			outHi:        make(chan outFrame, 1024),
			outLo:        make(chan outFrame, 4096),
			done:         make(chan struct{}),
			maxMux:       int32(caps.maxMux),
			maxPend:      int32(caps.maxPend),
			muxChunk:     int32(caps.muxChunk),
			dataInflight: int32(caps.dataInflight),
		}
		cc.aead.Store((*aeadConfig)(nil))
		cc.wantAEAD = (caps.featuresWanted & FEATURE_AEAD) != 0
		handshakeOK := false

		nonce := uint64(time.Now().UnixNano())
		capsBase := buildCapsPayload(caps.featuresWanted, caps.maxMux, caps.maxPend, caps.muxChunk, caps.dataInflight, nonce)
		capsPayload := capsBase
		if cc.wantAEAD {
			cr, rerr := rand32()
			if rerr != nil {
				cc.Close("rand failed")
				_ = conn.Close()
				sleepBackoff()
				continue
			}
			cc.capsClientRand = cr
			key := tcpsocks.PSK()
			tagC := hmac16(key[:], []byte("CAPS"), capsBase, cr[:])
			capsPayload = make([]byte, 0, len(capsBase)+32+16)
			capsPayload = append(capsPayload, capsBase...)
			capsPayload = append(capsPayload, cr[:]...)
			capsPayload = append(capsPayload, tagC[:]...)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		if err := sendFrameVec(conn, 0, MSG_CAPS, capsPayload); err != nil {
			cc.Close(fmt.Sprintf("send CAPS failed: %v", err))
			_ = conn.Close()
			sleepBackoff()
			continue
		}
		go cc.writerLoop()
		go heartbeatLoop(cc)

		ctx, cancel := context.WithCancel(context.Background())
		connectJobs := make(chan connectJob, connectQueueSize)

		connectWorkers := getEnvInt("SOCKS_CONNECT_WORKERS", caps.maxPend)
		connectWorkers = clampInt(connectWorkers, 1, caps.maxPend)

		var wg sync.WaitGroup
		wg.Add(connectWorkers)
		for i := 0; i < connectWorkers; i++ {
			go connectWorker(ctx, cc, connectJobs, &wg)
		}

		reader := bufio.NewReaderSize(conn, 64*1024)
		// CAPS sequencing (strict):
		// 1) Until CAPS_ACK, buffer all inbound frames except HEARTBEAT.
		// 2) After CAPS_ACK, replay buffered frames in order.
		type pendingFrame struct {
			sid     uint32
			mtype   byte
			payload []byte
		}
		pending := make([]pendingFrame, 0, 16)
		capsDeadline := time.Now().Add(capsAckTimeout)

		// dispatch handles a frame; bufp is returned to the pool only where it is safe.
		dispatch := func(sid uint32, mtype byte, payload []byte, bufp *[]byte) {
			switch mtype {
			case MSG_HEARTBEAT:
				if len(payload) == 8 {
					nonce := binary.BigEndian.Uint64(payload)
					now := time.Now().UnixNano()
					d := now - int64(nonce)
					if d > 0 {
						updateEWMAInt64(&cc.rttNanos, d, 8)
					}
				}
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
			case MSG_CAPS_ACK:
				handleCapsAck(cc, payload)
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
			case MSG_CONNECT_REQ:
				jobPayload := payload
				if bufp != nil {
					jobPayload = append([]byte(nil), payload...)
				}
				select {
				case connectJobs <- connectJob{sid: sid, payload: jobPayload}:
					if bufp != nil {
						frameBodyPool.Put(bufp)
					}
				default:
					if bufp != nil {
						frameBodyPool.Put(bufp)
					}
					_ = cc.enqueueHi(outFrame{sid: sid, msgType: MSG_CONNECT_REPLY, payload: []byte{4}})
				}
			case MSG_MUX_DATA:
				// payload references bufp; it will be returned by the session consumer or by cleanupSession drain.
				mp := muxPayload{b: payload, bufp: bufp}
				var ok bool
				sessionsMu.RLock()
				sess := sessions[sid]
				if sess == nil || !sess.mux || sess.cc != cc {
					sessionsMu.RUnlock()
					if bufp != nil {
						frameBodyPool.Put(bufp)
					}
					return
				}
				select {
				case sess.muxIn <- mp:
					ok = true
				default:
					ok = false
				}
				sessionsMu.RUnlock()

				if ok {
					return
				}
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
				cleanupSession(sid, true)
			case MSG_MUX_CLOSE:
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
				sessionsMu.RLock()
				sess := sessions[sid]
				own := sess != nil && sess.cc == cc
				sessionsMu.RUnlock()
				if own {
					cleanupSession(sid, false)
				}
			default:
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
			}
		}

		flushPending := func() {
			for _, pf := range pending {
				dispatch(pf.sid, pf.mtype, pf.payload, nil)
			}
			pending = pending[:0]
		}

		var recvSeq uint64

		for {
			// Until CAPS is negotiated, use a read deadline; without ACK we hard-fail (no legacy fallback).
			if atomic.LoadUint32(&cc.capsDone) == 0 {
				_ = conn.SetReadDeadline(capsDeadline)
			} else {
				_ = conn.SetReadDeadline(time.Time{})
			}

			sid, mtype, payload, bufp, _, rerr := recvFramePooled(reader)
			if rerr != nil {
				break
			}

			// Until CAPS_ACK, buffer everything except HEARTBEAT and CAPS_ACK itself.
			if atomic.LoadUint32(&cc.capsDone) == 0 && mtype != MSG_CAPS_ACK && mtype != MSG_HEARTBEAT {
				// pending stores a COPY of the payload, so return the pooled buffer exactly once.
				pending = append(pending, pendingFrame{sid: sid, mtype: mtype, payload: append([]byte(nil), payload...)})
				if bufp != nil {
					frameBodyPool.Put(bufp)
				}
				continue
			}

			// Decrypt after CAPS_ACK when AEAD is enabled.
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

			dispatch(sid, mtype, payload, bufp)
			if mtype == MSG_CAPS_ACK && atomic.LoadUint32(&cc.capsDone) != 0 {
				handshakeOK = true
				resetBackoff()
				_ = conn.SetReadDeadline(time.Time{})
				flushPending()
			}
		}

		cancel()
		cc.Close("reader exit")
		close(connectJobs)
		wg.Wait()
		_ = conn.Close()

		if !handshakeOK {
			sleepBackoff()
		} else {
			resetBackoff()
		}
	}
}

func resolveConfig(argv []string) (string, int, error) {
	v := strings.TrimSpace(SOCKSIP)
	if v != "0" {
		parts := strings.Fields(v)
		if len(parts) != 2 {
			return "", 0, fmt.Errorf("invalid SOCKSIP, expected \"0\" or \"IP PORT\", got: %q", SOCKSIP)
		}
		serverIP := parts[0]
		cp, err := strconv.Atoi(parts[1])
		if err != nil || cp <= 0 || cp > 65535 {
			return "", 0, fmt.Errorf("invalid port in SOCKSIP: %q", parts[1])
		}
		return serverIP, cp, nil
	}

	if len(argv) != 3 {
		bin := "./socks"
		if len(argv) > 0 {
			bin = filepath.Base(argv[0])
		}
		return "", 0, fmt.Errorf("usage: %s <server_ip> <control_port> | %s service <server_ip> <control_port>", bin, bin)
	}
	serverIP := argv[1]
	cp, err := strconv.Atoi(argv[2])
	if err != nil || cp <= 0 || cp > 65535 {
		return "", 0, errors.New("invalid control port")
	}
	return serverIP, cp, nil
}

func main() {
	loadTraceFlag()
	if err := tcpsocks.LoadPSK(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	allowPlain := strings.TrimSpace(os.Getenv("SOCKS_ALLOW_PLAINTEXT")) == "1"
	if !tcpsocks.HasPSK() && !allowPlain {
		fmt.Fprintln(os.Stderr, "FATAL: SOCKS_PSK_HEX is not set. Refusing to run with plaintext control channel. Set SOCKS_PSK_HEX (64 hex chars) or SOCKS_ALLOW_PLAINTEXT=1 (insecure).")
		os.Exit(2)
	}
	if strings.TrimSpace(os.Getenv("SOCKS_NO_AEAD")) == "1" && !allowPlain {
		fmt.Fprintln(os.Stderr, "FATAL: SOCKS_NO_AEAD=1 would disable encryption. Refusing to run. Unset SOCKS_NO_AEAD or set SOCKS_ALLOW_PLAINTEXT=1 (insecure).")
		os.Exit(2)
	}

	serviceCmd := len(os.Args) >= 2 && strings.TrimSpace(os.Args[1]) == "service"
	argv := os.Args
	if serviceCmd {
		// Drop the "service" subcommand so the rest of the code can reuse the same argument layout.
		argv = append([]string{os.Args[0]}, os.Args[2:]...)
	}

	serverIP, cp, err := resolveConfig(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if serviceCmd {
		if err := installService(serverIP, cp); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("Service %s installed and started\n", serviceName)
		return
	}

	controlConns := getEnvInt("SOCKS_CONTROL_CONNS", CONTROL_CONNS_DEFAULT)
	caps := computeCaps(controlConns)

	for i := 0; i < caps.controlConns; i++ {
		go controlLoopLane(serverIP, cp, i, caps)
	}

	select {}
}

type initSystem int

const (
	initUnknown initSystem = iota
	initSystemd
	initUpstart
	initSysV
)

func installService(serverHost string, controlPort int) error {
	if os.Getenv(noServiceEnvVar) == "1" {
		return fmt.Errorf("%s=1: service installation disabled", noServiceEnvVar)
	}
	if os.Getenv(serviceEnvVar) == "1" {
		return fmt.Errorf("%s=1: already running as a service", serviceEnvVar)
	}
	if os.Geteuid() != 0 {
		return errors.New("must be run as root to install the service")
	}

	init := detectInitSystem()
	if init == initUnknown {
		return errors.New("no supported init system detected (systemd/upstart/sysv)")
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	exe, _ = filepath.EvalSymlinks(exe)

	destDir := "/usr/local/bin"
	destPath := filepath.Join(destDir, serviceName)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}
	if err := copyFileAtomic(exe, destPath, 0755); err != nil {
		return fmt.Errorf("copy binary to %s: %w", destPath, err)
	}

	args := []string{serverHost, strconv.Itoa(controlPort)}

	var ierr error
	switch init {
	case initSystemd:
		ierr = installSystemd(destPath, args)
	case initUpstart:
		ierr = installUpstart(destPath, args)
	case initSysV:
		ierr = installSysV(destPath, args)
	default:
		return errors.New("unsupported init system")
	}
	if ierr != nil {
		return fmt.Errorf("service install/start failed: %w", ierr)
	}
	return nil
}

func detectInitSystem() initSystem {
	if dirExists("/run/systemd/system") {
		if _, err := exec.LookPath("systemctl"); err == nil {
			return initSystemd
		}
	}
	if _, err := exec.LookPath("initctl"); err == nil {
		if isUpstartInitctl() {
			return initUpstart
		}
		if dirExists("/etc/init") {
			return initUpstart
		}
	}
	if dirExists("/etc/init.d") {
		return initSysV
	}
	return initUnknown
}

func isUpstartInitctl() bool {
	out, err := exec.Command("initctl", "version").CombinedOutput()
	if err == nil && bytes.Contains(bytes.ToLower(out), []byte("upstart")) {
		return true
	}
	out, err = exec.Command("initctl", "--version").CombinedOutput()
	return err == nil && bytes.Contains(bytes.ToLower(out), []byte("upstart"))
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	if filepath.Clean(src) == filepath.Clean(dst) {
		return os.Chmod(dst, mode)
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}

	_, cErr := io.Copy(out, in)
	closeErr := out.Close()
	if cErr != nil {
		_ = os.Remove(tmp)
		return cErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "<no output>"
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

func installSystemd(destPath string, args []string) error {
	unitName := serviceName + ".service"
	unitPath := filepath.Join("/etc/systemd/system", unitName)

	execLine := destPath + " " + strings.Join(args, " ")
	unit := fmt.Sprintf(`[Unit]
Description=%s (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Environment=%s=1
Nice=10
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, serviceDescription, serviceName, execLine, serviceEnvVar)

	if err := writeFileAtomic(unitPath, []byte(unit), 0644); err != nil {
		return err
	}
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCmd("systemctl", "enable", unitName); err != nil {
		return err
	}
	if err := runCmd("systemctl", "restart", unitName); err != nil {
		if err2 := runCmd("systemctl", "start", unitName); err2 != nil {
			return err
		}
	}
	return nil
}

func installUpstart(destPath string, args []string) error {
	if !dirExists("/etc/init") {
		return errors.New("/etc/init not found")
	}

	confPath := filepath.Join("/etc/init", serviceName+".conf")
	execLine := destPath + " " + strings.Join(args, " ")

	conf := fmt.Sprintf(`description "%s (%s)"

start on filesystem or runlevel [2345]
stop on runlevel [016]

respawn
respawn limit 10 5

env %s=1
exec %s
`, serviceDescription, serviceName, serviceEnvVar, execLine)

	if err := writeFileAtomic(confPath, []byte(conf), 0644); err != nil {
		return err
	}

	_ = runCmd("initctl", "reload-configuration")
	_ = runCmd("initctl", "stop", serviceName)

	if err := runCmd("initctl", "start", serviceName); err != nil {
		if _, lerr := exec.LookPath("service"); lerr == nil {
			if err2 := runCmd("service", serviceName, "start"); err2 == nil {
				return nil
			}
		}
		return err
	}
	return nil
}

func installSysV(destPath string, args []string) error {
	if !dirExists("/etc/init.d") {
		return errors.New("/etc/init.d not found")
	}

	scriptPath := filepath.Join("/etc/init.d", serviceName)
	argsStr := strings.Join(args, " ")

	script := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          %s
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: %s (%s)
### END INIT INFO

DAEMON=%s
DAEMON_ARGS="%s"
PIDFILE=/var/run/%s.pid

export %s=1

start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "%s already running"
        return 0
    fi

    if command -v start-stop-daemon >/dev/null 2>&1; then
        start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" --exec "$DAEMON" -- $DAEMON_ARGS
        return $?
    fi

    nohup "$DAEMON" $DAEMON_ARGS >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    return 0
}

stop() {
    if [ ! -f "$PIDFILE" ]; then
        echo "%s not running"
        return 0
    fi

    if command -v start-stop-daemon >/dev/null 2>&1; then
        start-stop-daemon --stop --pidfile "$PIDFILE" --retry 5
        rm -f "$PIDFILE"
        return 0
    fi

    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    return 0
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "%s is running"
        return 0
    fi
    echo "%s is stopped"
    return 3
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status) status ;;
    *) echo "Usage: $0 {start|stop|restart|status}"; exit 2 ;;
esac
`, serviceName, serviceDescription, serviceName, destPath, argsStr, serviceName, serviceEnvVar,
		serviceName, serviceName, serviceName, serviceName)

	if err := writeFileAtomic(scriptPath, []byte(script), 0755); err != nil {
		return err
	}

	if _, err := exec.LookPath("update-rc.d"); err == nil {
		_ = runCmd("update-rc.d", serviceName, "defaults")
	} else if _, err := exec.LookPath("chkconfig"); err == nil {
		_ = runCmd("chkconfig", "--add", serviceName)
		_ = runCmd("chkconfig", serviceName, "on")
	}

	if err := runCmd(scriptPath, "restart"); err != nil {
		_ = runCmd(scriptPath, "start")
	}
	return nil
}
