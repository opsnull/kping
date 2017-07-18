package kping

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// send ICMP packet
func (p *kping) send(index int, addrBatchChan chan addrBatch) {
	stime := time.Now()
	// create ICMP Echo packet
	t := make([]byte, p.size)
	b := icmp.Echo{ID: icmpIDSeqInitNum + index, Data: t}
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &b,
	}
	// message cache
	wms := make([]message, 0, p.sendOpts.BatchSize)
L:
	for {
		var ab addrBatch
		var ok bool
		select {
		case <-p.context.Done():
			break L // send timeout
		case ab, ok = <-addrBatchChan:
			if !ok {
				break L // send done
			}
		}
		// get lock, at most one sent goroutine working
		p.sendLock.Lock()
		stime2 := time.Now()
		b.Seq = icmpIDSeqInitNum + ab.seq
		// fill icmp payload with current timestamp
		nsec := time.Now().UnixNano()
		for i := uint64(0); i < uint64(p.size); i++ {
			if i < timeSliceLength {
				t[i] = byte((nsec >> ((7 - i) * timeSliceLength)) & 0xff)
			} else {
				t[i] = 1
			}
		}
		bytes, _ := (&m).Marshal(nil)
		// reuse message cache
		wms2 := wms[0:0:len(ab.addrs)]
		for _, addr := range ab.addrs {
			msg := message{
				Buffers: [][]byte{bytes},
				Addr:    addr,
			}
			wms2 = append(wms2, msg)
		}
		var num int
		var err error
		for {
			// blocking write mult message
			num, err = p.rawConn.writeBatch(wms2, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "kping send: %d(%d), seq: %d, writeBatch failed: %v\n", index, p.sendOpts.Parallel, ab.seq, err)
				continue
			}
			break
		}
		if num != len(wms2) {
			fmt.Fprintf(os.Stderr, "kping send: %d(%d), seq: %d, writeBatch parted: %d(%d)\n", index, p.sendOpts.Parallel, ab.seq, len(wms2), num)
		}
		durTime := time.Since(stime2)
		if durTime > 50*time.Millisecond {
			fmt.Fprintf(os.Stderr, "kping send: %d(%d), seq: %d, writeBatch %d(%d), usedTime: %s\n", index, p.sendOpts.Parallel, ab.seq, len(wms2), num, durTime)
		}
		for _, msg := range wms2[0:num] {
			addr := msg.Addr.String()
			durTime := time.Since(stime2)
			p.ipEventChan <- &ipEvent{
				ip:           addr,
				seq:          b.Seq,
				sendDuration: durTime,
			}
		}
		// wait a little time
		time.Sleep(p.sendOpts.WaitTimeout)
		p.sendLock.Unlock()
	}
	fmt.Fprintf(os.Stderr, "kping send: %d(%d) done, usedTime: %s\n", index, p.sendOpts.Parallel, time.Since(stime))
}
