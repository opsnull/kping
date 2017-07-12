package kping

import (
	"syscall"
	"unsafe"
)

type msghdr struct {
	Name       *byte
	Namelen    uint32
	Pad        [4]byte
	Iov        *iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	Pad2  [4]byte
}

func (h *msghdr) pack(vs []iovec, bs [][]byte, oob []byte, sa []byte) {
	for i := range vs {
		vs[i].set(bs[i])
	}
	h.setIov(vs)
	if len(oob) > 0 {
		h.setControl(oob)
	}
	if sa != nil {
		h.Name = (*byte)(unsafe.Pointer(&sa[0]))
		h.Namelen = uint32(len(sa))
	}
}

func (h *msghdr) name() []byte {
	if h.Name != nil && h.Namelen > 0 {
		return (*[syscall.SizeofSockaddrInet6]byte)(unsafe.Pointer(h.Name))[:h.Namelen]
	}
	return nil
}

func (h *msghdr) controllen() int {
	return int(h.Controllen)
}

func (h *msghdr) flags() int {
	return int(h.Flags)
}

func (h *msghdr) setIov(vs []iovec) {
	h.Iov = &vs[0]
	h.Iovlen = uint64(len(vs))
}

func (h *msghdr) setControl(b []byte) {
	h.Control = (*byte)(unsafe.Pointer(&b[0]))
	h.Controllen = uint64(len(b))
}
