// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/ice/v2/internal/fakenet"
	stunx "github.com/pion/ice/v2/internal/stun"
	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/turn/v2"
)

const (
	stunGatherTimeout = time.Second * 5
)

// Close a net.Conn and log if we have a failure
func closeConnAndLog(c io.Closer, log logging.LeveledLogger, msg string, args ...interface{}) {
	if c == nil || (reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()) {
		log.Warnf("Connection is not allocated: "+msg, args...)
		return
	}

	log.Warnf(msg)
	if err := c.Close(); err != nil {
		log.Warnf("Failed to close connection: %v", err)
	}
}

func hostStr(h interface{}) string {
	if ip, ok := h.(net.IP); ok {
		return ip.String()
	}
	return h.(string)
}

func (a *Agent) gatherIPsAndHosts(networkTypes []NetworkType) ([]interface{}, error) {
	localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, networkTypes, a.includeLoopback)
	if err != nil {
		return nil, err
	}

	var hosts []interface{}

	for _, ip := range localIPs {
		hosts = append(hosts, ip)
	}

	for _, host := range a.additionalHosts {
		hosts = append(hosts, host)
	}

	return hosts, nil
}

// GatherCandidates initiates the trickle based gathering process.
func (a *Agent) GatherCandidates() error {
	var gatherErr error

	if runErr := a.run(a.context(), func(ctx context.Context, agent *Agent) {
		if a.gatheringState != GatheringStateNew {
			gatherErr = ErrMultipleGatherAttempted
			return
		} else if a.onCandidateHdlr.Load() == nil {
			gatherErr = ErrNoOnCandidateHandler
			return
		}

		a.gatherCandidateCancel() // Cancel previous gathering routine
		ctx, cancel := context.WithCancel(ctx)
		a.gatherCandidateCancel = cancel
		done := make(chan struct{})
		a.gatherCandidateDone = done

		go a.gatherCandidates(ctx, done)
	}); runErr != nil {
		return runErr
	}
	return gatherErr
}

func (a *Agent) gatherCandidates(ctx context.Context, done chan struct{}) {
	defer close(done)
	if err := a.setGatheringState(GatheringStateGathering); err != nil { //nolint:contextcheck
		a.log.Warnf("Failed to set gatheringState to GatheringStateGathering: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, t := range a.candidateTypes {
		switch t {
		case CandidateTypeHost:
			wg.Add(1)
			go func() {
				a.gatherCandidatesLocal(ctx, a.networkTypes)
				wg.Done()
			}()
		case CandidateTypeServerReflexive:
			wg.Add(1)
			go func() {
				if a.udpMuxSrflx != nil {
					a.gatherCandidatesSrflxUDPMux(ctx, a.urls, a.networkTypes)
				} else {
					a.gatherCandidatesSrflx(ctx, a.urls, a.networkTypes)
				}
				wg.Done()
			}()
			if a.extIPMapper != nil && a.extIPMapper.candidateType == CandidateTypeServerReflexive {
				wg.Add(1)
				go func() {
					a.gatherCandidatesSrflxMapped(ctx, a.networkTypes)
					wg.Done()
				}()
			}
		case CandidateTypeRelay:
			wg.Add(1)
			go func() {
				a.gatherCandidatesRelay(ctx, a.urls)
				wg.Done()
			}()
		case CandidateTypePeerReflexive, CandidateTypeUnspecified:
		}
	}

	// Block until all STUN and TURN URLs have been gathered (or timed out)
	wg.Wait()

	if err := a.setGatheringState(GatheringStateComplete); err != nil { //nolint:contextcheck
		a.log.Warnf("Failed to set gatheringState to GatheringStateComplete: %v", err)
	}
}

func (a *Agent) gatherCandidatesLocal(ctx context.Context, networkTypes []NetworkType) { //nolint:gocognit
	networks := map[string]struct{}{}
	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			networks[tcp] = struct{}{}
		} else {
			networks[udp] = struct{}{}
		}
	}

	hosts, err := a.gatherIPsAndHosts(networkTypes)
	if err != nil {
		a.log.Warnf("unable to get local hosts: %s", err)
		return
	}

	if _, ok := networks[udp]; ok {
		if a.udpMux != nil {
			a.gatherCandidatesLocalUDPMux(ctx, hosts)
		} else if a.udpRandom {
			a.gatherCandidatesLocalUDPRandom(ctx, hosts)
		}
	}

	if _, ok := networks[tcp]; ok {
		if a.tcpMux != nil {
			a.gatherCandidatesLocalTCPMux(ctx, hosts)
		}
	}
}

func (a *Agent) gatherCandidatesLocalUDPRandom(ctx context.Context, hosts []interface{}) {
	conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), udp, &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})
	if err != nil {
		a.log.Warnf("Failed to listen: %s", err)
		return
	}

	connPort := conn.LocalAddr().(*net.UDPAddr).Port

	for _, host := range hosts {
		hostConfig := CandidateHostConfig{
			Network:   udp,
			Address:   hostStr(host),
			Port:      connPort,
			Component: ComponentRTP,
		}

		err = a.createAndAddCandidate(ctx, conn, &hostConfig)
		if err != nil {
			a.log.Warnf("failed to create and add UDP candidate: %s: %v", host, err)
			continue
		}
	}
}

func (a *Agent) gatherCandidatesLocalUDPMux(ctx context.Context, hosts []interface{}) {
	localAddr := a.udpMux.(*UDPMuxDefault).LocalAddr().(*net.UDPAddr)

	if !localAddr.IP.IsUnspecified() {
		hosts = []interface{}{localAddr.IP}
	}

	conn, err := a.udpMux.GetConn(a.localUfrag)
	if err != nil {
		a.log.Warnf("failed to get UDP connection by ufrag: %s", err)
		return
	}

	for _, host := range hosts {
		hostConfig := CandidateHostConfig{
			Network:   udp,
			Address:   hostStr(host),
			Port:      localAddr.Port,
			Component: ComponentRTP,
		}

		err = a.createAndAddCandidate(ctx, conn, &hostConfig)
		if err != nil {
			a.log.Warnf("failed to create and add UDP candidate: %s: %v", host, err)
			continue
		}
	}
}

func (a *Agent) gatherCandidatesLocalTCPMux(ctx context.Context, hosts []interface{}) {
	localAddr := a.tcpMux.(*TCPMuxDefault).LocalAddr().(*net.TCPAddr)

	if !localAddr.IP.IsUnspecified() {
		hosts = []interface{}{localAddr.IP}
	}

	conn, err := a.tcpMux.GetConnByUfrag(a.localUfrag)
	if err != nil {
		a.log.Warnf("failed to get TCP connection by ufrag: %s", err)
		return
	}

	for _, host := range hosts {
		hostConfig := CandidateHostConfig{
			Network:   tcp,
			Address:   hostStr(host),
			Port:      localAddr.Port,
			Component: ComponentRTP,
			TCPType:   TCPTypePassive,
		}

		err = a.createAndAddCandidate(ctx, conn, &hostConfig)
		if err != nil {
			a.log.Warnf("failed to create and add TCP candidate: %s: %v", host, err)
			continue
		}
	}
}

func (a *Agent) gatherCandidatesSrflxMapped(ctx context.Context, networkTypes []NetworkType) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		network := networkType.String()
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), network, &net.UDPAddr{IP: nil, Port: 0})
			if err != nil {
				a.log.Warnf("Failed to listen %s: %v", network, err)
				return
			}

			lAddr, ok := conn.LocalAddr().(*net.UDPAddr)
			if !ok {
				closeConnAndLog(conn, a.log, "1:1 NAT mapping is enabled but LocalAddr is not a UDPAddr")
				return
			}

			mappedIP, err := a.extIPMapper.findExternalIP(lAddr.IP.String())
			if err != nil {
				closeConnAndLog(conn, a.log, "1:1 NAT mapping is enabled but no external IP is found for %s", lAddr.IP.String())
				return
			}

			srflxConfig := CandidateServerReflexiveConfig{
				Network:   network,
				Address:   mappedIP.String(),
				Port:      lAddr.Port,
				Component: ComponentRTP,
				RelAddr:   lAddr.IP.String(),
				RelPort:   lAddr.Port,
			}
			c, err := NewCandidateServerReflexive(&srflxConfig)
			if err != nil {
				closeConnAndLog(conn, a.log, "failed to create server reflexive candidate: %s %s %d: %v",
					network,
					mappedIP.String(),
					lAddr.Port,
					err)
				return
			}

			if err := a.addCandidate(ctx, c, conn); err != nil {
				if closeErr := c.close(); closeErr != nil {
					a.log.Warnf("Failed to close candidate: %v", closeErr)
				}
				a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
			}
		}()
	}
}

func (a *Agent) gatherCandidatesSrflxUDPMux(ctx context.Context, urls []*stun.URI, networkTypes []NetworkType) { //nolint:gocognit
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		for i := range urls {
			for _, listenAddr := range []net.Addr{} {
				udpAddr, ok := listenAddr.(*net.UDPAddr)
				if !ok {
					a.log.Warn("Failed to cast udpMuxSrflx listen address to UDPAddr")
					continue
				}
				wg.Add(1)
				go func(url stun.URI, network string, localAddr *net.UDPAddr) {
					defer wg.Done()

					hostPort := fmt.Sprintf("%s:%d", url.Host, url.Port)
					serverAddr, err := a.net.ResolveUDPAddr(network, hostPort)
					if err != nil {
						a.log.Debugf("Failed to resolve STUN host: %s: %v", hostPort, err)
						return
					}

					xorAddr, err := a.udpMuxSrflx.GetXORMappedAddr(serverAddr, stunGatherTimeout)
					if err != nil {
						a.log.Warnf("Failed get server reflexive address %s %s: %v", network, url, err)
						return
					}

					conn, err := a.udpMuxSrflx.GetConnForURL(a.localUfrag, url.String(), localAddr)
					if err != nil {
						a.log.Warnf("Failed to find connection in UDPMuxSrflx %s %s: %v", network, url, err)
						return
					}

					ip := xorAddr.IP
					port := xorAddr.Port

					srflxConfig := CandidateServerReflexiveConfig{
						Network:   network,
						Address:   ip.String(),
						Port:      port,
						Component: ComponentRTP,
						RelAddr:   localAddr.IP.String(),
						RelPort:   localAddr.Port,
					}
					c, err := NewCandidateServerReflexive(&srflxConfig)
					if err != nil {
						closeConnAndLog(conn, a.log, "failed to create server reflexive candidate: %s %s %d: %v", network, ip, port, err)
						return
					}

					if err := a.addCandidate(ctx, c, conn); err != nil {
						if closeErr := c.close(); closeErr != nil {
							a.log.Warnf("Failed to close candidate: %v", closeErr)
						}
						a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
					}
				}(*urls[i], networkType.String(), udpAddr)
			}
		}
	}
}

func (a *Agent) gatherCandidatesSrflx(ctx context.Context, urls []*stun.URI, networkTypes []NetworkType) { //nolint:gocognit
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		for i := range urls {
			wg.Add(1)
			go func(url stun.URI, network string) {
				defer wg.Done()

				hostPort := fmt.Sprintf("%s:%d", url.Host, url.Port)
				serverAddr, err := a.net.ResolveUDPAddr(network, hostPort)
				if err != nil {
					a.log.Debugf("Failed to resolve STUN host: %s: %v", hostPort, err)
					return
				}

				conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), network, &net.UDPAddr{IP: nil, Port: 0})
				if err != nil {
					closeConnAndLog(conn, a.log, "failed to listen for %s: %v", serverAddr.String(), err)
					return
				}
				// If the agent closes midway through the connection
				// we end it early to prevent close delay.
				cancelCtx, cancelFunc := context.WithCancel(ctx)
				defer cancelFunc()
				go func() {
					select {
					case <-cancelCtx.Done():
						return
					case <-a.done:
						_ = conn.Close()
					}
				}()

				xorAddr, err := stunx.GetXORMappedAddr(conn, serverAddr, stunGatherTimeout)
				if err != nil {
					closeConnAndLog(conn, a.log, "failed to get server reflexive address %s %s: %v", network, url, err)
					return
				}

				ip := xorAddr.IP
				port := xorAddr.Port

				lAddr := conn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
				srflxConfig := CandidateServerReflexiveConfig{
					Network:   network,
					Address:   ip.String(),
					Port:      port,
					Component: ComponentRTP,
					RelAddr:   lAddr.IP.String(),
					RelPort:   lAddr.Port,
				}
				c, err := NewCandidateServerReflexive(&srflxConfig)
				if err != nil {
					closeConnAndLog(conn, a.log, "failed to create server reflexive candidate: %s %s %d: %v", network, ip, port, err)
					return
				}

				if err := a.addCandidate(ctx, c, conn); err != nil {
					if closeErr := c.close(); closeErr != nil {
						a.log.Warnf("Failed to close candidate: %v", closeErr)
					}
					a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
				}
			}(*urls[i], networkType.String())
		}
	}
}

func (a *Agent) gatherCandidatesRelay(ctx context.Context, urls []*stun.URI) { //nolint:gocognit
	var wg sync.WaitGroup
	defer wg.Wait()

	network := NetworkTypeUDP4.String()
	for i := range urls {
		switch {
		case urls[i].Scheme != stun.SchemeTypeTURN && urls[i].Scheme != stun.SchemeTypeTURNS:
			continue
		case urls[i].Username == "":
			a.log.Errorf("Failed to gather relay candidates: %v", ErrUsernameEmpty)
			return
		case urls[i].Password == "":
			a.log.Errorf("Failed to gather relay candidates: %v", ErrPasswordEmpty)
			return
		}

		wg.Add(1)
		go func(url stun.URI) {
			defer wg.Done()
			turnServerAddr := fmt.Sprintf("%s:%d", url.Host, url.Port)
			var (
				locConn       net.PacketConn
				err           error
				relAddr       string
				relPort       int
				relayProtocol string
			)

			switch {
			case url.Proto == stun.ProtoTypeUDP && url.Scheme == stun.SchemeTypeTURN:
				if locConn, err = a.net.ListenPacket(network, "0.0.0.0:0"); err != nil {
					a.log.Warnf("Failed to listen %s: %v", network, err)
					return
				}

				relAddr = locConn.LocalAddr().(*net.UDPAddr).IP.String() //nolint:forcetypeassert
				relPort = locConn.LocalAddr().(*net.UDPAddr).Port        //nolint:forcetypeassert
				relayProtocol = udp
			case a.proxyDialer != nil && url.Proto == stun.ProtoTypeTCP &&
				(url.Scheme == stun.SchemeTypeTURN || url.Scheme == stun.SchemeTypeTURNS):
				conn, connectErr := a.proxyDialer.Dial(NetworkTypeTCP4.String(), turnServerAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to dial TCP address %s via proxy dialer: %v", turnServerAddr, connectErr)
					return
				}

				relAddr = conn.LocalAddr().(*net.TCPAddr).IP.String() //nolint:forcetypeassert
				relPort = conn.LocalAddr().(*net.TCPAddr).Port        //nolint:forcetypeassert
				if url.Scheme == stun.SchemeTypeTURN {
					relayProtocol = tcp
				} else if url.Scheme == stun.SchemeTypeTURNS {
					relayProtocol = "tls"
				}
				locConn = turn.NewSTUNConn(conn)

			case url.Proto == stun.ProtoTypeTCP && url.Scheme == stun.SchemeTypeTURN:
				tcpAddr, connectErr := a.net.ResolveTCPAddr(NetworkTypeTCP4.String(), turnServerAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to resolve TCP address %s: %v", turnServerAddr, connectErr)
					return
				}

				conn, connectErr := a.net.DialTCP(NetworkTypeTCP4.String(), nil, tcpAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to dial TCP address %s: %v", turnServerAddr, connectErr)
					return
				}

				relAddr = conn.LocalAddr().(*net.TCPAddr).IP.String() //nolint:forcetypeassert
				relPort = conn.LocalAddr().(*net.TCPAddr).Port        //nolint:forcetypeassert
				relayProtocol = tcp
				locConn = turn.NewSTUNConn(conn)
			case url.Proto == stun.ProtoTypeUDP && url.Scheme == stun.SchemeTypeTURNS:
				udpAddr, connectErr := a.net.ResolveUDPAddr(network, turnServerAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to resolve UDP address %s: %v", turnServerAddr, connectErr)
					return
				}

				udpConn, dialErr := a.net.DialUDP("udp", nil, udpAddr)
				if dialErr != nil {
					a.log.Warnf("Failed to dial DTLS address %s: %v", turnServerAddr, dialErr)
					return
				}

				conn, connectErr := dtls.ClientWithContext(ctx, udpConn, &dtls.Config{
					ServerName:         url.Host,
					InsecureSkipVerify: a.insecureSkipVerify, //nolint:gosec
				})
				if connectErr != nil {
					a.log.Warnf("Failed to create DTLS client: %v", turnServerAddr, connectErr)
					return
				}

				relAddr = conn.LocalAddr().(*net.UDPAddr).IP.String() //nolint:forcetypeassert
				relPort = conn.LocalAddr().(*net.UDPAddr).Port        //nolint:forcetypeassert
				relayProtocol = "dtls"
				locConn = &fakenet.PacketConn{Conn: conn}
			case url.Proto == stun.ProtoTypeTCP && url.Scheme == stun.SchemeTypeTURNS:
				tcpAddr, resolvErr := a.net.ResolveTCPAddr(NetworkTypeTCP4.String(), turnServerAddr)
				if resolvErr != nil {
					a.log.Warnf("Failed to resolve relay address %s: %v", turnServerAddr, resolvErr)
					return
				}

				tcpConn, dialErr := a.net.DialTCP(NetworkTypeTCP4.String(), nil, tcpAddr)
				if dialErr != nil {
					a.log.Warnf("Failed to connect to relay: %v", dialErr)
					return
				}

				conn := tls.Client(tcpConn, &tls.Config{
					ServerName:         url.Host,
					InsecureSkipVerify: a.insecureSkipVerify, //nolint:gosec
				})

				if hsErr := conn.HandshakeContext(ctx); hsErr != nil {
					if closeErr := tcpConn.Close(); closeErr != nil {
						a.log.Errorf("Failed to close relay connection: %v", closeErr)
					}
					a.log.Warnf("Failed to connect to relay: %v", hsErr)
					return
				}

				relAddr = conn.LocalAddr().(*net.TCPAddr).IP.String() //nolint:forcetypeassert
				relPort = conn.LocalAddr().(*net.TCPAddr).Port        //nolint:forcetypeassert
				relayProtocol = "tls"
				locConn = turn.NewSTUNConn(conn)
			default:
				a.log.Warnf("Unable to handle URL in gatherCandidatesRelay %v", url)
				return
			}

			client, err := turn.NewClient(&turn.ClientConfig{
				TURNServerAddr: turnServerAddr,
				Conn:           locConn,
				Username:       url.Username,
				Password:       url.Password,
				LoggerFactory:  a.loggerFactory,
				Net:            a.net,
			})
			if err != nil {
				closeConnAndLog(locConn, a.log, "failed to create new TURN client %s %s", turnServerAddr, err)
				return
			}

			if err = client.Listen(); err != nil {
				client.Close()
				closeConnAndLog(locConn, a.log, "failed to listen on TURN client %s %s", turnServerAddr, err)
				return
			}

			relayConn, err := client.Allocate()
			if err != nil {
				client.Close()
				closeConnAndLog(locConn, a.log, "failed to allocate on TURN client %s %s", turnServerAddr, err)
				return
			}

			rAddr := relayConn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
			relayConfig := CandidateRelayConfig{
				Network:       network,
				Component:     ComponentRTP,
				Address:       rAddr.IP.String(),
				Port:          rAddr.Port,
				RelAddr:       relAddr,
				RelPort:       relPort,
				RelayProtocol: relayProtocol,
				OnClose: func() error {
					client.Close()
					return locConn.Close()
				},
			}
			relayConnClose := func() {
				if relayConErr := relayConn.Close(); relayConErr != nil {
					a.log.Warnf("Failed to close relay %v", relayConErr)
				}
			}
			candidate, err := NewCandidateRelay(&relayConfig)
			if err != nil {
				relayConnClose()

				client.Close()
				closeConnAndLog(locConn, a.log, "failed to create relay candidate: %s %s: %v", network, rAddr.String(), err)
				return
			}

			if err := a.addCandidate(ctx, candidate, relayConn); err != nil {
				relayConnClose()

				if closeErr := candidate.close(); closeErr != nil {
					a.log.Warnf("Failed to close candidate: %v", closeErr)
				}
				a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
			}
		}(*urls[i])
	}
}
