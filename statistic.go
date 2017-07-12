package kping

import (
	"fmt"
	"math"
	"os"
)

// statistic ping result
func (p *Pinger) statistic() (statistics map[string]*Statistic) {
	statistics = make(map[string]*Statistic, p.ipCount)
	// number of rtt value
	rttStatistic := make(map[string]int, 15)
	for addr, statistic := range p.Stats {
		// fix sent&recv number
		if statistic.PacketsSent > p.Count {
			statistic.PacketsSent = p.Count
		}
		if statistic.PacketsRecv > p.Count {
			statistic.PacketsRecv = p.Count
		}
		statistic.PacketLoss = float64(statistic.PacketsSent-statistic.PacketsRecv) / float64(statistic.PacketsSent) * 100
		if len(statistic.Rtts) <= 0 {
			rttStatistic["==0"]++
		} else {
			rttStatistic[">0"]++
			if len(statistic.Rtts) >= 100 {
				rttStatistic[">=100"]++
			}
			if len(statistic.Rtts) >= 90 && len(statistic.Rtts) < 100 {
				rttStatistic[">=90"]++
			}
			if len(statistic.Rtts) >= 80 && len(statistic.Rtts) < 90 {
				rttStatistic[">=80"]++
			}
			if len(statistic.Rtts) >= 60 && len(statistic.Rtts) < 80 {
				rttStatistic[">=60"]++
			}
			if len(statistic.Rtts) >= 40 && len(statistic.Rtts) < 60 {
				rttStatistic[">=40"]++
			}
			if len(statistic.Rtts) >= 20 && len(statistic.Rtts) < 40 {
				rttStatistic[">=20"]++
			}
			// first: calculate avg value
			var sum float64
			for _, rtt := range statistic.Rtts {
				sum += rtt
			}
			avg := sum / float64(len(statistic.Rtts))

			// second: delete bad value
			RttNew := make([]float64, 0, len(statistic.Rtts))
			for _, rtt := range statistic.Rtts {
				if rtt <= 5*avg && rtt < 500 {
					RttNew = append(RttNew, rtt)
				}
			}
			// third: calculate again
			var min, max float64
			if len(RttNew) > 0 {
				min = RttNew[0]
				max = RttNew[0]
			}
			sum = 0
			for _, rtt := range RttNew {
				if rtt < min {
					min = rtt
				}
				if rtt > max {
					max = rtt
				}
				sum += rtt
			}
			statistic.MaxRtt = max
			statistic.MinRtt = min
			if len(RttNew) > 0 {
				statistic.AvgRtt = sum / float64(len(RttNew))
				var sumsquares float64
				for _, rtt := range RttNew {
					sumsquares += (rtt - statistic.AvgRtt) * (rtt - statistic.AvgRtt)
				}
				statistic.StdDevRtt = math.Sqrt(float64(sumsquares / float64(len(RttNew))))
			}
		}
		statistics[addr] = statistic
	}
	fmt.Fprintf(os.Stderr, "kping statistic: rtt numbers:\n")
	for k, v := range rttStatistic {
		fmt.Fprintf(os.Stderr, "\t%s: %d\n", k, v)
	}
	return statistics
}
