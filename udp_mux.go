// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/transport/v2"
)

// UDPMux allows multiple connections to go over a single UDP port
type UDPMux interface {
	io.Closer
	GetConn(ufrag string) (net.PacketConn, error)
	RemoveConnByUfrag(ufrag string)
	GetListenAddresses() []net.Addr
}

// UDPMuxDefault is an implementation of the interface
type UDPMuxDefault struct {
	params UDPMuxParams

	closedChan chan struct{}
	closeOnce  sync.Once

	conns map[string]*udpMuxedConn

	addressMapMu sync.RWMutex
	addressMap   map[udpMuxedConnAddr]*udpMuxedConn

	// Buffer pool to recycle buffers for net.UDPAddr encodes/decodes
	pool *sync.Pool

	mu sync.Mutex
}

// UDPMuxParams are parameters for UDPMux.
type UDPMuxParams struct {
	Logger  logging.LeveledLogger
	UDPConn net.PacketConn

	// Required for gathering local addresses
	// in case a un UDPConn is passed which does not
	// bind to a specific local address.
	Net transport.Net
}

// NewUDPMuxDefault creates an implementation of UDPMux
func NewUDPMuxDefault(params UDPMuxParams) *UDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}

	m := &UDPMuxDefault{
		addressMap: map[udpMuxedConnAddr]*udpMuxedConn{},
		params:     params,
		conns:      make(map[string]*udpMuxedConn),
		closedChan: make(chan struct{}, 1),
		pool: &sync.Pool{
			New: func() interface{} {
				// Big enough buffer to fit both packet and address
				return newBufferHolder(receiveMTU)
			},
		},
	}

	go m.connWorker()

	return m
}

// LocalAddr returns the listening address of this UDPMuxDefault
func (m *UDPMuxDefault) LocalAddr() net.Addr {
	return m.params.UDPConn.LocalAddr()
}

// GetListenAddresses returns the list of addresses that this mux is listening on
func (m *UDPMuxDefault) GetListenAddresses() []net.Addr {
	return []net.Addr{m.LocalAddr()}
}

// GetConn returns a PacketConn given the connection's ufrag and network address
// creates the connection if an existing one can't be found
func (m *UDPMuxDefault) GetConn(ufrag string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	if conn, ok := m.getConn(ufrag); ok {
		return conn, nil
	}

	c := m.createMuxedConn(ufrag)
	go func() {
		<-c.CloseChannel()
		m.RemoveConnByUfrag(ufrag)
	}()

	m.conns[ufrag] = c

	return c, nil
}

// RemoveConnByUfrag stops and removes the muxed packet connection
func (m *UDPMuxDefault) RemoveConnByUfrag(ufrag string) {
	var removedConn *udpMuxedConn

	// Keep lock section small to avoid deadlock with conn lock
	m.mu.Lock()
	if c, ok := m.conns[ufrag]; ok {
		delete(m.conns, ufrag)
		removedConn = c
	}
	m.mu.Unlock()

	if removedConn == nil {
		// No need to lock if no connection was found
		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	addresses := removedConn.getAddresses()
	for _, addr := range addresses {
		delete(m.addressMap, addr)
	}
}

// IsClosed returns true if the mux had been closed
func (m *UDPMuxDefault) IsClosed() bool {
	select {
	case <-m.closedChan:
		return true
	default:
		return false
	}
}

// Close the mux, no further connections could be created
func (m *UDPMuxDefault) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, c := range m.conns {
			_ = c.Close()
		}

		m.conns = make(map[string]*udpMuxedConn)

		close(m.closedChan)

		_ = m.params.UDPConn.Close()
	})
	return err
}

func (m *UDPMuxDefault) writeTo(buf []byte, rAddr net.Addr) (n int, err error) {
	return m.params.UDPConn.WriteTo(buf, rAddr)
}

func (m *UDPMuxDefault) registerConnForAddress(conn *udpMuxedConn, addr udpMuxedConnAddr) {
	if m.IsClosed() {
		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	existing, ok := m.addressMap[addr]
	if ok {
		existing.removeAddress(addr)
	}
	m.addressMap[addr] = conn

	m.params.Logger.Debugf("Registered %s for %s", addr, conn.params.Key)
}

func (m *UDPMuxDefault) createMuxedConn(key string) *udpMuxedConn {
	c := newUDPMuxedConn(&udpMuxedConnParams{
		Mux:       m,
		Key:       key,
		AddrPool:  m.pool,
		LocalAddr: m.LocalAddr(),
		Logger:    m.params.Logger,
	})
	return c
}

func (m *UDPMuxDefault) connWorker() {
	logger := m.params.Logger

	defer func() {
		_ = m.Close()
	}()

	buf := make([]byte, receiveMTU)
	for {
		n, addr, err := m.params.UDPConn.ReadFrom(buf)
		if m.IsClosed() {
			return
		} else if err != nil {
			if os.IsTimeout(err) {
				continue
			} else if !errors.Is(err, io.EOF) {
				logger.Errorf("Failed to read UDP packet: %v", err)
			}

			return
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			logger.Errorf("Underlying PacketConn did not return a UDPAddr")
			return
		}

		// If we have already seen this address dispatch to the appropriate destination
		m.addressMapMu.Lock()
		destinationConn := m.addressMap[newUDPMuxedConnAddr(udpAddr)]
		m.addressMapMu.Unlock()

		// If we haven't seen this address before but is a STUN packet lookup by ufrag
		if destinationConn == nil && stun.IsMessage(buf[:n]) {
			msg := &stun.Message{
				Raw: append([]byte{}, buf[:n]...),
			}

			if err = msg.Decode(); err != nil {
				m.params.Logger.Warnf("Failed to handle decode ICE from %s: %v", addr.String(), err)
				continue
			}

			attr, stunAttrErr := msg.Get(stun.AttrUsername)
			if stunAttrErr != nil {
				m.params.Logger.Warnf("No Username attribute in STUN message from %s", addr.String())
				continue
			}

			ufrag := strings.Split(string(attr), ":")[0]

			m.mu.Lock()
			destinationConn, _ = m.getConn(ufrag)
			m.mu.Unlock()
		}

		if destinationConn == nil {
			m.params.Logger.Tracef("Dropping packet from %s, addr: %s", udpAddr, addr)
			continue
		}

		if err = destinationConn.writePacket(buf[:n], udpAddr); err != nil {
			m.params.Logger.Errorf("Failed to write packet: %v", err)
		}
	}
}

func (m *UDPMuxDefault) getConn(ufrag string) (val *udpMuxedConn, ok bool) {
	val, ok = m.conns[ufrag]
	return
}

type bufferHolder struct {
	next *bufferHolder
	buf  []byte
	addr *net.UDPAddr
}

func newBufferHolder(size int) *bufferHolder {
	return &bufferHolder{
		buf: make([]byte, size),
	}
}

func (b *bufferHolder) reset() {
	b.next = nil
	b.addr = nil
}
