package kping

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const (
	// bits number of nanosecond
	timeSliceLength = 8
	// init value of ICMP packet id and seq
	icmpIDSeqInitNum = 10000
)

func (p *kping) batchRecv(index int, wg *sync.WaitGroup) {
	defer wg.Done()

	recvBatch := p.batchRecvOpts.BatchSize
	recvParallel := p.batchRecvOpts.Parallel
	stime := time.Now()
	rms := make([]message, 0, recvBatch)
	for i := 0; i < int(recvBatch); i++ {
		msg := message{
			Buffers: [][]byte{make([]byte, 100)},
			N:       0,
		}
		rms = append(rms, msg)
	}
L:
	for {
		select {
		case <-p.sendDone:
			break L
		default:
		}
		stime2 := time.Now()
		num, err := p.rawConn.readBatch(rms, index, 0) // blocking read
		durTime := time.Since(stime2)
		if durTime > 400*time.Millisecond {
			fmt.Fprintf(os.Stderr, "kping recv: %d(%d) readBatch %d(%d), usedTime: %s\n", index, recvParallel, recvBatch, num, durTime)
		}
		if err != nil {
			if err2, ok := err.(*os.SyscallError); ok {
				if err3, ok := err2.Err.(syscall.Errno); ok && err3.Temporary() {
					//time.Sleep(20 * time.Millisecond)
				}
			} else {
				fmt.Fprintf(os.Stderr, "kping recv: %d(%d) readBatch failed: %v\n", index, recvParallel, err)
			}
			continue
		}
		for _, msg := range rms[0:num] {
			ip := net.IPv4(msg.Buffers[0][12], msg.Buffers[0][13], msg.Buffers[0][14], msg.Buffers[0][15]).String()
			hdrlen := int(msg.Buffers[0][0]&0x0f) << 2
			bytes := msg.Buffers[0][hdrlen:msg.N]
			if len(bytes) < 16 {
				fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %s IMCP message length %d < 16 Bytes, ignored\n", index, recvParallel, ip, len(bytes))
				continue
			}
			/*
				bytes[0]: type
				bytes[1]: code
				bytes[2:4]: checkSum
				bytes[4:6]: id
				bytes[6:8]: seq
				bytes[8:16]: payload: timestamp
			*/
			msgType := ipv4.ICMPType(bytes[0])
			if msgType != ipv4.ICMPTypeEchoReply {
				continue
			}
			id := int(binary.BigEndian.Uint16(bytes[4:6]))
			seq := int(binary.BigEndian.Uint16(bytes[6:8]))
			// ignore mismatch id or seq packet
			if id < icmpIDSeqInitNum || seq < icmpIDSeqInitNum {
				continue
			}
			// calculate RTT
			var nsec int64
			for i := uint8(0); i < timeSliceLength; i++ {
				nsec += int64(bytes[8 : 8+timeSliceLength][i]) << ((7 - i) * timeSliceLength)
			}
			sendTime := time.Unix(nsec/1000000000, nsec%1000000000)
			durTime := time.Since(stime2)
			rtt := time.Since(sendTime.Add(durTime))
			p.ipEventChan <- &ipEvent{
				ip:      ip,
				seq:     seq,
				recvRTT: rtt,
			}
		}
	}
	fmt.Fprintf(os.Stderr, "kping recv: %d(%d) done, usedTime: %s\n", index, recvParallel, time.Since(stime))
}

func (p *kping) afpacketRecv(index int, wg *sync.WaitGroup) {
	defer wg.Done()

	recvParallel := p.afpacketRecvOpts.Parallel
	options := []interface{}{
		afpacket.OptFrameSize(1 << 11), // not used for v3.
		afpacket.OptBlockSize(1 << 20),
		afpacket.OptNumBlocks(p.afpacketRecvOpts.BlockMB),
		afpacket.OptPollTimeout(p.afpacketRecvOpts.Timeout),
		afpacket.OptInterface(p.afpacketRecvOpts.Iface),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	}
	tpacket, err := afpacket.NewTPacket(options...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %v\n", index, recvParallel, err)
		return
	}
	defer tpacket.Close()

	// bpf filter
	filter := fmt.Sprintf("ip and dst %s and icmp[icmptype] = icmp-echoreply and icmp[4:2] >= %d and icmp[6:2] >= %d", p.sourceIP, icmpIDSeqInitNum, icmpIDSeqInitNum)
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, int(p.afpacketRecvOpts.SnapLength), filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %v\n", index, recvParallel, err)
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
		fmt.Fprintf(os.Stderr, "kping recv: %d(%d) %v\n", index, recvParallel, err)
		return
	}

	// LoadBalance Fanout
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
			fmt.Fprintf(os.Stderr, "kping recv: %d(%d) NextPacket: io.EOF, break for loop\n", index, recvParallel)
			break
		} else if err != nil {
			if err == afpacket.ErrTimeout || err == afpacket.ErrPoll {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "kping recv: %d(%d) NextPacket: unknown error: %v, ignored\n", index, recvParallel, err)
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
			fmt.Fprintf(os.Stderr, "kping recv: %d(%d) packet length %d < 50 Bytes, ignored: \n%s\n", index, recvParallel, ci.Length, data)
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
	fmt.Fprintf(os.Stderr, "kping recv: %d(%d) done, ipCount: %d, usedTime: %s\n", index, recvParallel, ipCount, time.Since(stime))
}

func (p *kping) pfringRecv(index int, wg *sync.WaitGroup) {
	defer wg.Done()

	recvParallel := p.pfringRecvOpts.Parallel
	stime := time.Now()
L:
	for {
		select {
		case <-p.sendDone:
			break L
		default:
		}
		packet, err := p.packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "kping recv: NextPacket: unknown error: %v, ignored\n", err)
			continue
		}
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ip4Layer == nil {
			fmt.Fprintf(os.Stderr, "kping recv: not ipv4 packet, ignored\n")
			continue
		}
		ci := packet.Metadata().CaptureInfo
		if ci.Length < 50 {
			fmt.Fprintf(os.Stderr, "kping recv: %d(%d) packet length %d < 50 Bytes, ignored: \n", index, recvParallel, ci.Length)
			continue
		}
		ip4 := ip4Layer.(*layers.IPv4)
		ip := ip4.SrcIP.String()
		bytes := ip4.Payload
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
	}
	fmt.Fprintf(os.Stderr, "kping recv: %d done, usedTime: %s\n", index, time.Since(stime))
}
