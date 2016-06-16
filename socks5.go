package socks5

import (
	"fmt"
	"github.com/araddon/gou"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	socks5Version = uint8(5)
	ipv4Address   = uint8(1)
	fqdnAddress   = uint8(3)
	ipv6Address   = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	hostUnreachableErr      = fmt.Errorf("hostUnreachable")
	addrTypeNotSupportedErr = fmt.Errorf("addrTypeNotSupported")
)

type AddrSpec struct {
	addrType  uint8
	FQDN      string
	IP        net.IP
	Port      int
	ProxyHost string
}

func (addr *AddrSpec) HostAndPort() string {
	if addr.ProxyHost != "" {
		return addr.FQDN + ":" + strconv.Itoa(addr.Port) + ";" + addr.ProxyHost
	}
	return addr.FQDN + ":" + strconv.Itoa(addr.Port)
}

var (
	hostToIpCache     = make(map[string]net.IP)
	hostToIpCacheSync sync.RWMutex
	ipToHostCache     = make(map[string]string)
	ipToHostCacheSync sync.RWMutex
)

func ResolveToHost(ip net.IP) string {
	if addr, err := net.LookupAddr(ip.String()); err == nil {
		return addr[0]
	} else {
		gou.Debugf("Unabled to find host from ip (%s)", ip.String())
		return ip.String()
	}
}
func ResolveToHostCaching(ip net.IP) string {
	hostToIpCacheSync.Lock()
	defer hostToIpCacheSync.Unlock()

	if host, exists := ipToHostCache[ip.String()]; exists {
		return host
	}
	host := ResolveToHost(ip)
	ipToHostCache[ip.String()] = host
	return host

}

func ResolveToIp(host string) (net.IP, error) {
	if addr, err := net.ResolveIPAddr("ip", host); err == nil {
		return addr.IP, nil
	} else {
		gou.Errorf("Failed to resolve host=%s; err=%v", host, err)
		return nil, err
	}
}

func ResolveToIpCaching(host string) (net.IP, error) {
	hostToIpCacheSync.Lock()
	defer hostToIpCacheSync.Unlock()
	if ip, exists := hostToIpCache[host]; exists {
		return ip, nil
	}
	if ip, err := ResolveToIp(host); err == nil {
		hostToIpCache[host] = ip
		return ip, nil
	} else {
		return nil, err
	}

}
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	d.addrType = addrType[0]

	// Handle on a per type basis
	switch d.addrType {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)
		d.FQDN = ResolveToHost(d.IP)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)
		d.FQDN = ResolveToHostCaching(d.IP)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)
		if ip, err := ResolveToIpCaching(d.FQDN); err == nil {
			d.IP = ip
		} else {
			return nil, hostUnreachableErr
		}

	default:
		return nil, addrTypeNotSupportedErr
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.addrType == fqdnAddress && addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	//gou.Debugf("addrType=%d; n=%d; err=%v; body=%s", addrType, n, err, string(addrBody))
	return err
}

// Handle the Socks5 protocol (https://www.ietf.org/rfc/rfc1928.txt).
// Doesnt support bind or associate commands.
// Automatically responsed to the server with a noauth required reply.
//
// If the protocol is negotiated successfully,
//    returns with an open connection to the remote location
//    and AddrSpec (remote host, ip, and port)
func HandleProtocol(local net.Conn) (net.Conn, *AddrSpec, error) {
	header := []byte{0, 0, 0, 0}
	if _, err := local.Read(header); err != nil {
		return nil, nil, fmt.Errorf("Reading version %v", err)
	}
	if header[0] != socks5Version {
		sendReply(local, serverFailure, nil)
		return nil, nil, fmt.Errorf("Wrong version. Expected %d. Actual %d.", socks5Version, header[0])
	}
	local.Write([]byte{socks5Version, 0}) //No authentication required

	header = []byte{0, 0, 0}
	local.Read(header)
	if header[0] != socks5Version {
		sendReply(local, serverFailure, nil)
		return nil, nil, fmt.Errorf("Wrong version. Expected %d. Actual %d.", socks5Version, header[0])
	}

	addr, err := readAddrSpec(local)
	if err != nil {
		switch err {
		case hostUnreachableErr:
			sendReply(local, hostUnreachable, nil)
		case addrTypeNotSupportedErr:
			sendReply(local, addrTypeNotSupported, nil)
		default:
			sendReply(local, serverFailure, nil)
		}
		return nil, nil, fmt.Errorf("Reading address: %v", err)
	}

	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port))
	if err != nil {
		sendReply(local, connectionRefused, addr)
		return nil, nil, fmt.Errorf("Dialing %v", err)
	}
	sendReply(local, successReply, addr)
	return remote, addr, err

}
