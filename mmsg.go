package kping

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

const (
	sizeofICMPFilter = 0x4
	sysSENDMMSG      = 0x133
)

type message struct {
	Buffers [][]byte
	OOB     []byte
	Addr    net.Addr

	N     int
	NN    int
	Flags int
}

type mmsghdr struct {
	Hdr msghdr
	Len uint32
	Pad [4]byte
}

type mmsghdrs []mmsghdr

// 1500 > UIO_MAXIOV(linux default: 1024)
var vsCache = make([][]iovec, 1500)
var saCache = make([][]byte, 1500)

func init() {
	for i := 0; i < 1500; i++ {
		vsCache[i] = make([]iovec, 200)
		saCache[i] = make([]byte, syscall.SizeofSockaddrInet6)
	}
}

func (hs mmsghdrs) rPack(ms []message, parseFn func([]byte, string) (net.Addr, error), marshalFn func(net.Addr) []byte) error {
	for i := range hs {
		vs := vsCache[i][0:len(ms[i].Buffers)]
		sa := saCache[i]
		hs[i].Hdr.pack(vs, ms[i].Buffers, ms[i].OOB, sa)
	}
	return nil
}

func (hs mmsghdrs) pack(ms []message, parseFn func([]byte, string) (net.Addr, error), marshalFn func(net.Addr) []byte) error {
	for i := range hs {
		vs := make([]iovec, len(ms[i].Buffers))
		var sa []byte
		if parseFn != nil {
			sa = make([]byte, syscall.SizeofSockaddrInet6)
		}
		if marshalFn != nil {
			sa = marshalFn(ms[i].Addr)
		}
		hs[i].Hdr.pack(vs, ms[i].Buffers, ms[i].OOB, sa)
	}
	return nil
}

func (hs mmsghdrs) unpack(ms []message, parseFn func([]byte, string) (net.Addr, error), hint string) error {
	for i := range hs {
		ms[i].N = int(hs[i].Len)
		ms[i].NN = hs[i].Hdr.controllen()
		ms[i].Flags = hs[i].Hdr.flags()
		if parseFn != nil {
			var err error
			ms[i].Addr, err = parseFn(hs[i].Hdr.name(), hint)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type iovec struct {
	Base *byte
	Len  uint64
}

func (v *iovec) set(b []byte) {
	v.Base = (*byte)(unsafe.Pointer(&b[0]))
	v.Len = uint64(len(b))
}

func marshalInetAddr(a net.Addr) []byte {
	ip, port := a.(*net.IPAddr).IP, 0
	if ip4 := ip.To4(); ip4 != nil {
		b := make([]byte, syscall.SizeofSockaddrInet4)
		nativeEndian.PutUint16(b[:2], uint16(syscall.AF_INET))
		binary.BigEndian.PutUint16(b[2:4], uint16(port))
		copy(b[4:8], ip4)
		return b
	}
	return nil
}

func parseInetAddr(b []byte, network string) (net.Addr, error) {
	if len(b) < 2 {
		return nil, errors.New("invalid address")
	}
	var ip net.IP
	if len(b) < syscall.SizeofSockaddrInet4 {
		return nil, errors.New("short address")
	}
	ip = make(net.IP, net.IPv4len)
	copy(ip, b[4:8])
	return &net.IPAddr{IP: ip}, nil
}

func recvmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(syscall.SYS_RECVMMSG, s, uintptr(unsafe.Pointer(&hs[0])), uintptr(len(hs)), uintptr(flags), 0, 0)
	if errno == 0 {
		return int(n), nil
	}
	return int(n), syscall.Errno(errno)
}

func sendmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(sysSENDMMSG, s, uintptr(unsafe.Pointer(&hs[0])), uintptr(len(hs)), uintptr(flags), 0, 0)
	if errno == 0 {
		return int(n), nil
	}
	return int(n), syscall.Errno(errno)
}
