package kping

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type ipEvent struct {
	ip           string
	seq          int
	sendDuration time.Duration
	recvRTT      time.Duration
}

// Statistic ping statistic of single ip
type Statistic struct {
	PacketsRecv int64
	PacketsSent int64
	Rtts        []float64
	PacketLoss  float64
	MinRtt      float64
	MaxRtt      float64
	AvgRtt      float64
	StdDevRtt   float64

	ipEvents map[int]ipEvent // key: ICMP seq
}

// Pinger repsent kping
// the max value of ReadBatch and WriteBatch is UIO_MAXIOV，linux defaults to 1024
type Pinger struct {
	SourceIP string        // ping source IP
	Count    int64         // ping count, must < 55536
	Size     uint64        // ping ICMP packet payload bytes, must > 8
	Timeout  time.Duration // ping total timeout
	Interval time.Duration // ping interval

	ReadTimeout  time.Duration // read timeout
	ReadParallel int64         // read goroutine number
	ReadBlockMB  int64         // af_packet: total block size

	WriteBatch    int64         // batchWrite ICMP packet number, must < 1024
	WriteBuffer   int64         // write buffer size
	WriteTimeout  time.Duration // write timeout
	WriteParallel int64         // write goroutine number
	WriteWaitTime time.Duration // batchWrite interval

	Stats map[string]*Statistic // key: ip

	tpacket     *afpacket.TPacket
	rawConn     *rawConn
	addrs       []*net.IPAddr
	ipCount     int64
	context     context.Context
	cancel      context.CancelFunc
	recvReady   chan bool
	sendDone    chan bool
	sendLock    *sync.Mutex
	ipEventChan chan *ipEvent
}

// NewPinger create a new Pinger
func NewPinger(sourceIP, iface string, interval, timeout, readTimeout, writeTimeout, writeWaitTime time.Duration,
	count, size, writeBatch, writeBuffer, writeParallel, readBlockMB, readParallel int64) *Pinger {
	if uint64(size) < timeSliceLength {
		size = timeSliceLength
	}
	return &Pinger{
		SourceIP:      sourceIP,
		Iface:         iface,
		Count:         count,
		Size:          uint64(size),
		Timeout:       timeout,
		Interval:      interval,
		ReadTimeout:   readTimeout,
		ReadBlockMB:   readBlockMB,
		ReadParallel:  readParallel,
		WriteBatch:    writeBatch,
		WriteBuffer:   writeBuffer,
		WriteTimeout:  writeTimeout,
		WriteParallel: writeParallel,
		WriteWaitTime: writeWaitTime,
		recvReady:     make(chan bool),
		sendDone:      make(chan bool),
		sendLock:      new(sync.Mutex),
	}
}

// AddAddrs add ip addresses to pinger
func (p *Pinger) AddAddrs(ipaddrs []string) error {
	p.addrs = make([]*net.IPAddr, 0, len(ipaddrs))
	p.Stats = make(map[string]*Statistic, len(ipaddrs))
	for _, ipaddr := range ipaddrs {
		addr, err := net.ResolveIPAddr("ip4", ipaddr)
		if err != nil {
			return fmt.Errorf("invalid IP: %s", ipaddr)
		}
		p.addrs = append(p.addrs, addr)
		p.ipCount++
	}
	return nil
}

type addrBatch struct {
	seq   int
	addrs []*net.IPAddr
}

// Run flood ping, then calculate statistic per IP
func (p *Pinger) Run() (statistics map[string]*Statistic, err error) {
	// send&recv, so buffer size is double
	p.ipEventChan = make(chan *ipEvent, p.ipCount*p.Count*2)

	ctx, cancel := context.WithTimeout(context.TODO(), p.Timeout)
	p.context = ctx
	p.cancel = cancel

	// create raw socket connection
	rawConn, err := newRawConn(p.Source, p.ReadBuffer, p.WriteBuffer, p.ReadTimeout, p.WriteTimeout)
	if err != nil {
		return nil, err
	}
	p.rawConn = rawConn

	// receive packets
	go func() {
		defer close(p.ipEventChan)

		fmt.Fprintf(os.Stderr, "kping recv: started, parallel: %d, ipCount: %d\n", p.ReadParallel, p.ipCount)
		wg := new(sync.WaitGroup)
		stime := time.Now()
		for i := 0; i < int(p.ReadParallel); i++ {
			wg.Add(1)
			index := i
			go p.recv(index, wg) // when sent done, goroutine return
		}

		// receive ready
		close(p.recvReady)

		wg.Wait()
		fmt.Fprintf(os.Stderr, "kping recv: all done, parallel: %d, ipCount: %d, usedTime: %s\n", p.ReadParallel, p.ipCount, time.Since(stime))
	}()

	// send packets
	go func() {
		defer p.cancel()
		defer close(p.sendDone)
		defer p.rawConn.close()

		// wait receive ready
		<-p.recvReady

		stime := time.Now()
		addrBatchChan := make(chan addrBatch)
		fmt.Fprintf(os.Stderr, "kping send: started, parallel: %d, ipCount: %d, \n", p.WriteParallel, p.ipCount)

		// cocurenccy send packets
		for i := 0; i < int(p.WriteParallel); i++ {
			index := i
			go p.send(index, addrBatchChan) // after close addrBatchChan, goroutine return
		}

		// caculate batch number
		var batchNum = 0
		if p.ipCount%p.WriteBatch == 0 {
			batchNum = int(p.ipCount / p.WriteBatch)
		} else {
			batchNum = int(p.ipCount/p.WriteBatch + 1)
		}

		// fill address for each batch
		addrBatchs := make([]addrBatch, batchNum)
		for i := range addrBatchs {
			addrBatchs[i] = addrBatch{
				addrs: make([]*net.IPAddr, 0, p.WriteBatch),
			}
		}
		for i, addr := range p.addrs {
			j := i / int(p.WriteBatch)
			batch := addrBatchs[j]
			batch.addrs = append(batch.addrs, addr)
			addrBatchs[j] = batch
		}

		// 多发送 10 个包
		for n := 0; n < int(p.Count+10); n++ {
			stime := time.Now()
			for _, batch := range addrBatchs {
				batch.seq = n
				addrBatchChan <- batch
			}
			time.Sleep(p.Interval)
			fmt.Fprintf(os.Stderr, "kping send: seq %d(%d) done, usedTime: %s\n", n, p.Count+10, time.Since(stime))
		}

		// sent done, sleep 1s
		close(addrBatchChan)
		fmt.Fprintf(os.Stderr, "kping send: all done, parallel: %d, ipCount: %d, usedTime: %s\n", p.WriteParallel, p.ipCount, time.Since(stime))
		time.Sleep(1 * time.Second)
	}()

	p.process()
	statistics = p.statistic()
	return statistics, nil
}
