package kping

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
)

var (
	nativeEndian binary.ByteOrder
)

type rawConn struct {
	fd           int
	readBuffer   int64
	writeBuffer  int64
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func init() {
	i := uint32(1)
	b := (*[4]byte)(unsafe.Pointer(&i))
	if b[0] == 1 {
		nativeEndian = binary.LittleEndian
	} else {
		nativeEndian = binary.BigEndian
	}
}

func newRawConn(sourceIP string, readBuffer, writeBuffer int64, readTimeout, writeTimeout time.Duration) (rc *rawConn, err error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}

	sockaddr := &syscall.SockaddrInet4{}
	sourceIPAddr, err := net.ResolveIPAddr("ip4", sourceIP)
	if err != nil {
		return nil, err
	}
	ip4 := sourceIPAddr.IP.To4()
	copy(sockaddr.Addr[:], ip4)

	if err := syscall.Bind(fd, sockaddr); err != nil {
		return nil, err
	}

	rc = &rawConn{
		fd:           fd,
		readBuffer:   readBuffer,
		writeBuffer:  writeBuffer,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
	}

	if readBuffer > 0 {
		if err := rc.setReadBuffer(int(readBuffer)); err != nil {
			return nil, fmt.Errorf("set read buffer failed: %v", err)
		}
	}

	if writeBuffer > 0 {
		if err := rc.setWriteBuffer(int(writeBuffer)); err != nil {
			return nil, fmt.Errorf("set write buffer failed: %v", err)
		}
	}

	if readTimeout > 0 {
		tv := syscall.Timeval{
			Sec:  0,
			Usec: int64(readTimeout / time.Microsecond),
		}
		if err := rc.setReadTimeout(&tv); err != nil {
			return nil, fmt.Errorf("set read timeout failed: %v", err)
		}
	}

	if writeTimeout > 0 {
		tv := syscall.Timeval{
			Sec:  0,
			Usec: int64(writeTimeout / time.Microsecond),
		}
		if err := rc.setWriteTimeout(&tv); err != nil {
			return nil, fmt.Errorf("set write timeout failed: %v", err)
		}
	}

	if err := rc.setTOS(0x0); err != nil {
		return nil, fmt.Errorf("set TTL failed: %v", err)
	}

	if err := rc.setTTL(64); err != nil {
		return nil, fmt.Errorf("set TTL failed: %v", err)
	}

	if err := rc.setReuseaddr(); err != nil {
		return nil, fmt.Errorf("setReuseaddr failed: %v", err)
	}

	return rc, nil
}

func (rc *rawConn) setWriteBuffer(size int) (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(rc.fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size))
}

func (rc *rawConn) setReadBuffer(size int) (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(rc.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size))
}

func (rc *rawConn) setTOS(tos int) (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(rc.fd, syscall.SOL_SOCKET, syscall.IP_TOS, tos))
}

func (rc *rawConn) setTTL(ttl int) (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(rc.fd, syscall.SOL_SOCKET, syscall.IP_TTL, ttl))
}

func (rc *rawConn) setTimeStampns() (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(rc.fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1))
}

func (rc *rawConn) setReuseaddr() (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(rc.fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1))
}

func (rc *rawConn) setReadTimeout(tv *syscall.Timeval) (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptTimeval(rc.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, tv))
}

func (rc *rawConn) setWriteTimeout(tv *syscall.Timeval) (err error) {
	return os.NewSyscallError("setsockopt", syscall.SetsockoptTimeval(rc.fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, tv))
}

func (rc *rawConn) setICMPFilter(filter *ipv4.ICMPFilter) (err error) {
	v := (*[sizeofICMPFilter]byte)(unsafe.Pointer(filter))[:sizeofICMPFilter]
	return os.NewSyscallError("setsockopt", setsockopt(uintptr(rc.fd), syscall.SOL_RAW, 0x1, v))
}

func (rc *rawConn) close() (err error) {
	return syscall.Close(rc.fd)
}

var hsCache = make([]mmsghdrs, 100) // ReadBatch parallel < 100

func init() {
	for i := 0; i < len(hsCache); i++ {
		hsCache[i] = make(mmsghdrs, 1024)
	}
}

func (rc *rawConn) readBatch(ms []message, index int, flags int) (num int, err error) {
	hs := hsCache[index][0:len(ms)]
	parseFn := parseInetAddr
	if err := hs.rPack(ms, parseFn, nil); err != nil {
		return 0, err
	}
	var operr error
	num, operr = recvmmsg(uintptr(rc.fd), hs, flags)
	if operr != nil {
		return num, os.NewSyscallError("recvmmsg", operr)
	}
	if err := hs[:num].unpack(ms[:num], parseFn, "ipv4"); err != nil {
		return num, err
	}
	return num, nil
}

func (rc *rawConn) writeBatch(ms []message, flags int) (num int, err error) {
	hs := make(mmsghdrs, len(ms))
	if err := hs.pack(ms, nil, marshalInetAddr); err != nil {
		return 0, err
	}
	var operr error
	num, operr = sendmmsg(uintptr(rc.fd), hs, flags)
	if operr != nil {
		return num, os.NewSyscallError("sendmmsg", operr)
	}
	if err := hs[:num].unpack(ms[:num], nil, ""); err != nil {
		return num, err
	}
	return num, nil
}

func setsockopt(s uintptr, level, name int, b []byte) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, s, uintptr(level), uintptr(name), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if errno == 0 {
		return nil
	}
	return syscall.Errno(errno)
}
