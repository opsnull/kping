package kping

import (
	"fmt"
	"math"
	"os"
)

// statistic ping result
func (p *kping) statistic() (statistics map[string]*Statistic) {
	statistics = make(map[string]*Statistic, p.ipCount)
	// number of rtt value
	rttStatistic := make(map[string]int, 15)
	for addr, statistic := range p.stats {
		// fix sent & recv number
		if statistic.SentNum > p.count {
			statistic.SentNum = p.count
		}
		if statistic.RecvNum > p.count {
			statistic.RecvNum = p.count
		}
		statistic.LostNum = float64(statistic.SentNum-statistic.RecvNum) / float64(statistic.SentNum) * 100
		if len(statistic.RTTs) <= 0 {
			rttStatistic["==0"]++
		} else {
			rttStatistic[">0"]++
			if len(statistic.RTTs) >= 100 {
				rttStatistic[">=100"]++
			}
			if len(statistic.RTTs) >= 90 && len(statistic.RTTs) < 100 {
				rttStatistic[">=90"]++
			}
			if len(statistic.RTTs) >= 80 && len(statistic.RTTs) < 90 {
				rttStatistic[">=80"]++
			}
			if len(statistic.RTTs) >= 60 && len(statistic.RTTs) < 80 {
				rttStatistic[">=60"]++
			}
			if len(statistic.RTTs) >= 40 && len(statistic.RTTs) < 60 {
				rttStatistic[">=40"]++
			}
			if len(statistic.RTTs) >= 20 && len(statistic.RTTs) < 40 {
				rttStatistic[">=20"]++
			}
			// first: calculate avg value
			var sum float64
			for _, rtt := range statistic.RTTs {
				sum += rtt
			}
			avg := sum / float64(len(statistic.RTTs))

			// second: delete bad value
			rttsNew := make([]float64, 0, len(statistic.RTTs))
			for _, rtt := range statistic.RTTs {
				if rtt <= 5*avg && rtt < 500 {
					rttsNew = append(rttsNew, rtt)
				}
			}
			// third: calculate again
			var min, max float64
			if len(rttsNew) > 0 {
				min = rttsNew[0]
				max = rttsNew[0]
			}
			sum = 0
			for _, rtt := range rttsNew {
				if rtt < min {
					min = rtt
				}
				if rtt > max {
					max = rtt
				}
				sum += rtt
			}
			statistic.MaxRTT = max
			statistic.MinRTT = min
			if len(rttsNew) > 0 {
				statistic.AvgRTT = sum / float64(len(rttsNew))
				var sumsquares float64
				for _, rtt := range rttsNew {
					sumsquares += (rtt - statistic.AvgRTT) * (rtt - statistic.AvgRTT)
				}
				statistic.StdDevRTT = math.Sqrt(float64(sumsquares / float64(len(rttsNew))))
			}
		}
		statistics[addr] = statistic
	}
	fmt.Fprintf(os.Stderr, "kping statistic: RTT numbers:\n")
	for k, v := range rttStatistic {
		fmt.Fprintf(os.Stderr, "\t%s: %d\n", k, v)
	}
	return statistics
}
