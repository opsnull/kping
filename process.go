package kping

import (
	"fmt"
	"os"
	"time"
)

// process icmp packets
func (p *Pinger) process() {
	stime := time.Now()
	for event := range p.ipEventChan {
		_, ok := p.Stats[event.ip]
		if !ok {
			p.Stats[event.ip] = &Statistic{
				ipEvents: make(map[int]ipEvent, p.Count),
				Rtts:     make([]float64, 0, p.Count*2),
			}
		}

		event2, ok := p.Stats[event.ip].ipEvents[event.seq]
		if !ok {
			event2 = ipEvent{
				ip:  event.ip,
				seq: event.seq,
			}
		}

		if event.sendDuration != 0 {
			p.Stats[event.ip].PacketsSent++
			event2.sendDuration = event.sendDuration
		} else if event.recvRTT != 0 {
			p.Stats[event.ip].PacketsRecv++
			event2.recvRTT = event.recvRTT
		}
		p.Stats[event.ip].ipEvents[event.seq] = event2

		if event2.recvRTT != 0 && event2.sendDuration != 0 {
			rtt := float64(event2.recvRTT) / float64(time.Millisecond)
			if rtt <= 0.01 {
				rtt = 2
			}
			Rtts := p.Stats[event.ip].Rtts
			Rtts = append(Rtts, rtt)
			p.Stats[event.ip].Rtts = Rtts
		}
	}

	fmt.Fprintf(os.Stderr, "kping process: done, ipCount: %d, usedTime: %s\n", len(p.Stats), time.Since(stime))
}
