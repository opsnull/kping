package kping

import (
	"fmt"
	"os"
	"time"
)

// process icmp packets
func (p *kping) process() {
	stime := time.Now()
	for event := range p.ipEventChan {
		_, ok := p.stats[event.ip]
		if !ok {
			p.stats[event.ip] = &Statistic{
				ipEvents: make(map[int]ipEvent, p.count),
				RTTs:     make([]float64, 0, p.count*2),
			}
		}

		event2, ok := p.stats[event.ip].ipEvents[event.seq]
		if !ok {
			event2 = ipEvent{
				ip:  event.ip,
				seq: event.seq,
			}
		}

		if event.sendDuration != 0 {
			p.stats[event.ip].PacketsSent++
			event2.sendDuration = event.sendDuration
		} else if event.recvRTT != 0 {
			p.stats[event.ip].PacketsRecv++
			event2.recvRTT = event.recvRTT
		}
		p.stats[event.ip].ipEvents[event.seq] = event2

		if event2.recvRTT != 0 && event2.sendDuration != 0 {
			rtt := float64(event2.recvRTT) / float64(time.Millisecond)
			if rtt <= 0.01 {
				rtt = 2
			}
			rtts := p.stats[event.ip].RTTs
			rtts = append(rtts, rtt)
			p.stats[event.ip].RTTs = rtts
		}
	}

	fmt.Fprintf(os.Stderr, "kping process: done, ipCount: %d, usedTime: %s\n", len(p.stats), time.Since(stime))
}
