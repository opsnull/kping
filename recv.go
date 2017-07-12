package kping

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

const (
	// bits number of nanosecond
	timeSliceLength = 8
	// init value of ICMP packet id and seq
	icmpIDSeqInitNum = 10000
)

// recv receive ICMP packet
func (p *Pinger) recv(index int, wg *sync.WaitGroup) {
	defer wg.Done()

	options := []interface{}{
		afpacket.OptFrameSize(1 << 11), // not used for v3.
		afpacket.OptBlockSize(1 << 20),
		afpacket.OptNumBlocks(p.ReadBlockMB),
		afpacket.OptPollTimeout(p.ReadTimeout),
		afpacket.OptInterface(p.Iface),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	}
	tpacket, err := afpacket.NewTPacket(options...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %v\n", index, p.ReadParallel, err)
		return
	}
	defer tpacket.Close()

	// bpf filter
	filter := fmt.Sprintf("ip and dst %s and icmp[icmptype] = icmp-echoreply and icmp[4:2] >= %d and icmp[6:2] >= %d", p.SourceIP, icmpIDSeqInitNum, icmpIDSeqInitNum)
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 128, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %v\n", index, p.ReadParallel, err)
		return
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	if tpacket.SetBPF(bpfIns); err != nil {
		fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %v\n", index, p.ReadParallel, err)
		return
	}

	runtime.LockOSThread()
	tpacket.SetFanout(afpacket.FanoutLoadBalance, 123)

	ipCount := 0
	stime := time.Now()
L:
	for {
		select {
		case <-p.sendDone:
			break L
		default:
		}
		data, ci, err := tpacket.ZeroCopyReadPacketData()
		if err == io.EOF {
			fmt.Fprintf(os.Stderr, "kping recv: %d(%d) NextPacket: io.EOF, break for loop\n", index, p.ReadParallel)
			break
		} else if err != nil {
			if err == afpacket.ErrTimeout || err == afpacket.ErrPoll {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "kping recv: %d(%d) NextPacket: unknown error: %v, ignored\n", index, p.ReadParallel, err)
				continue
			}
		}
		/*
			fmt.Fprintf(os.Stderr, "%s\n", data)
			OUTPUT:
			PACKET: 52 bytes, wire length 52 cap length 52 @ 2017-07-04 23:43:39.708919 +0800 CST
			- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..38..] SrcMAC=ee:ff:ff:ff:ff:ff DstMAC=00:16:3e:04:79:3e EthernetType=IPv4 Length=0}
			- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..18..] Version=4 IHL=5 TOS=20 Length=38 Id=13672 Flags= FragOffset=0 TTL=51 Protocol=ICMPv4 Checksum=63803 SrcIP=222.37.36.141 DstIP=115.28.227.80 Options=[] Padding=[]}
			- Layer 3 (08 bytes) = ICMPv4   {Contents=[..8..] Payload=[..10..] TypeCode=EchoReply Checksum=51683 Id=10003 Seq=10001}
			- Layer 4 (10 bytes) = Payload  10 byte(s)
		*/
		if ci.Length < 50 { // 50: Ethernet(14)+IPv4(20)+ICMPv4(8)+Payload(>=8)
			fmt.Fprintf(os.Stderr, "kping recv: %d(%d) packet length %d < 50 Bytes, ignored: \n%s\n", index, p.ReadParallel, ci.Length, data)
			continue
		}
		ip := net.IPv4(data[26], data[27], data[28], data[29]).String()
		bytes := data[34:]
		/*
			bytes[0]: type
			bytes[1]: code
			bytes[2:4]: checkSum
			bytes[4:6]: id
			bytes[6:8]: seq
			bytes[8:16]: payload: timestamp
		*/
		seq := int(binary.BigEndian.Uint16(bytes[6:8]))

		// calculate RTT
		var nsec int64
		for i := uint8(0); i < timeSliceLength; i++ {
			nsec += int64(bytes[8 : 8+timeSliceLength][i]) << ((7 - i) * timeSliceLength)
		}
		sendTime := time.Unix(nsec/1000000000, nsec%1000000000)
		rtt := ci.Timestamp.Sub(sendTime)

		p.ipEventChan <- &ipEvent{
			ip:      ip,
			seq:     seq,
			recvRTT: rtt,
		}
		ipCount++
	}
	fmt.Fprintf(os.Stderr, "kping recv: %d(%d) done, ipCount: %d, usedTime: %s\n", index, p.ReadParallel, ipCount, time.Since(stime))
}
