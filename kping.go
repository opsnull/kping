package kping

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"golang.org/x/net/ipv4"
)

type ipEvent struct {
	ip           string
	seq          int
	sendDuration time.Duration
	recvRTT      time.Duration
}

// Statistic ping statistic of IP
type Statistic struct {
	PacketsRecv int64     // recv packets number
	PacketsSent int64     // sent packets number
	PacketLost  float64   // lost packets number
	RTTs        []float64 // RTT of each recv packet
	MinRTT      float64   // minimum RTT of RTTs
	MaxRTT      float64   // maxmum RTT of RTTs
	AvgRTT      float64   // average RTT of RTTs
	StdDevRTT   float64   // stddev of RTTs

	ipEvents map[int]ipEvent // key: ICMP seq
}

// SendOptions batch send options
type SendOptions struct {
	BatchSize   int64         // batch send ICMP packet number, must < 1024
	BufferSize  int64         // batch send buffer size
	Parallel    int64         // send goroutine number
	Timeout     time.Duration // send timeout
	WaitTimeout time.Duration // batch send interval
}

// DefaultSendOptions default batch send options
var DefaultSendOptions = SendOptions{
	BatchSize:   1024,
	BufferSize:  10 * 1024 * 1024,
	Parallel:    30,
	Timeout:     100 * time.Second,
	WaitTimeout: 20 * time.Millisecond,
}

// AfPacketRecvOptions af_packet recv options
type AfPacketRecvOptions struct {
	Parallel   int64         // recv goroutine number
	BlockMB    int64         // af_packet: total block size
	Timeout    time.Duration // af_packet: poll timeout
	Iface      string        // recv interface name, eg: "eth0"
	SnapLength int64         // snap byte number
}

// DefaultAfPacketRecvOptions default af_packet recv options
var DefaultAfPacketRecvOptions = AfPacketRecvOptions{
	Parallel:   1,
	BlockMB:    128,
	Timeout:    100 * time.Millisecond,
	Iface:      "eth0",
	SnapLength: 128,
}

// BatchRecvOptions batch recv options
type BatchRecvOptions struct {
	BatchSize  int64         // batch recv ICMP packet number, must < 1024
	BufferSize int64         // batch recv buffer size
	Parallel   int64         // recv goroutine number
	Timeout    time.Duration // recv timeout
}

// DefaultBatchRecvOptions default batch recv options
var DefaultBatchRecvOptions = BatchRecvOptions{
	BatchSize:  100,
	BufferSize: 10 * 1024 * 1024,
	Parallel:   10,
	Timeout:    100 * time.Millisecond,
}

// PFRingRecvOptions pf_ring recv options
type PFRingRecvOptions struct {
	Iface      string // recv interface name, eg: "eth0"
	SnapLength int64  // snap byte number
	Parallel   int64  // recv goroutine number
}

// DefaultPFRingRecvOptions default pf_ring recv options
var DefaultPFRingRecvOptions = PFRingRecvOptions{
	Iface:      "eth0",
	SnapLength: 128,
	Parallel:   1,
}

// DefaultRecvMode default recv mode
var DefaultRecvMode = "afpacket"

// Pinger repsent kping methods
type Pinger interface {
	// SetRecvMode set recv mode, oneof: afpacket(default)|batch|pfring
	SetRecvMode(recvMode string) error
	// SetAfPacketRecvOptions set af_packet recv options if recvMode is "afpacket" (default)
	SetAfPacketRecvOptions(options AfPacketRecvOptions) error
	// SetBatchRecvOptions set batch recv options if recvMode is "batch"
	SetBatchRecvOptions(options BatchRecvOptions) error
	// SetPFRingRecvOptions set pf_ring recv options if recvMode is "pfring"
	SetPFRingRecvOptions(options PFRingRecvOptions) error
	// SetSendOptions set send options
	SetSendOptions(options SendOptions) error
	// AddIPs add IP addrs to pinger
	AddIPs(addrs []string) error
	// Run flood ping, then calculate statistic of each IP
	Run() (statistics map[string]*Statistic, err error)
}

// NewPinger return a new pinger
func NewPinger(sourceIP string, count, size int64, timeout, interval time.Duration) (p Pinger, err error) {
	p = &kping{
		sourceIP:         sourceIP,
		count:            count,
		size:             size,
		timeout:          timeout,
		interval:         interval,
		recvMode:         DefaultRecvMode,
		sendOpts:         DefaultSendOptions,
		afpacketRecvOpts: DefaultAfPacketRecvOptions,
		batchRecvOpts:    DefaultBatchRecvOptions,
		pfringRecvOpts:   DefaultPFRingRecvOptions,
		recvReady:        make(chan bool),
		sendDone:         make(chan bool),
		sendLock:         new(sync.Mutex),
	}
	return p, nil
}

type kping struct {
	sourceIP string        // ping source IP
	count    int64         // ping count, must < 55536
	size     int64         // ping ICMP packet payload bytes, must > 8
	timeout  time.Duration // ping total timeout
	interval time.Duration // ping interval
	recvMode string

	sendOpts         SendOptions
	afpacketRecvOpts AfPacketRecvOptions
	batchRecvOpts    BatchRecvOptions
	pfringRecvOpts   PFRingRecvOptions

	rawConn      *rawConn
	ring         *pfring.Ring
	packetSource *gopacket.PacketSource
	stats        map[string]*Statistic // key: ip
	addrs        []*net.IPAddr
	ipCount      int64
	context      context.Context
	cancel       context.CancelFunc
	recvReady    chan bool
	sendDone     chan bool
	sendLock     *sync.Mutex
	ipEventChan  chan *ipEvent
}

func (p *kping) SetRecvMode(mode string) (err error) {
	switch mode {
	case "afpacket", "pfring", "batch":
		p.recvMode = mode
	default:
		return fmt.Errorf("unknown recv mode: %s, should be oneof: afpacket|pfring|batch", p.recvMode)
	}
	return nil
}

func (p *kping) SetAfPacketRecvOptions(options AfPacketRecvOptions) error {
	p.afpacketRecvOpts = options
	return nil
}

func (p *kping) SetBatchRecvOptions(options BatchRecvOptions) error {
	p.batchRecvOpts = options
	return nil
}

func (p *kping) SetPFRingRecvOptions(options PFRingRecvOptions) error {
	p.pfringRecvOpts = options
	return nil
}

func (p *kping) SetSendOptions(options SendOptions) error {
	p.sendOpts = options
	return nil
}

func (p *kping) AddIPs(ipaddrs []string) error {
	p.addrs = make([]*net.IPAddr, 0, len(ipaddrs))
	p.stats = make(map[string]*Statistic, len(ipaddrs))
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

func (p *kping) Run() (statistics map[string]*Statistic, err error) {
	// used by send & recv, so buffer size is double
	p.ipEventChan = make(chan *ipEvent, p.ipCount*p.count*2)

	// set context
	ctx, cancel := context.WithTimeout(context.TODO(), p.timeout)
	p.context = ctx
	p.cancel = cancel

	// create raw socket connection
	rawConn, err := newRawConn(p.sourceIP, p.batchRecvOpts.BufferSize, p.sendOpts.BufferSize, p.batchRecvOpts.Timeout, p.sendOpts.Timeout)
	if err != nil {
		return nil, err
	}
	defer rawConn.close()

	if p.recvMode == "batch" {
		// filter ICMP Echo & Reply type packet
		filter := ipv4.ICMPFilter{}
		filter.SetAll(false)
		filter.Accept(ipv4.ICMPTypeEchoReply)
		if err := rawConn.setICMPFilter(&filter); err != nil {
			return nil, fmt.Errorf("setICMPFilter failed: %v", err)
		}
	} else if p.recvMode == "pfring" {
		ring, err := pfring.NewRing(p.pfringRecvOpts.Iface, uint32(p.pfringRecvOpts.SnapLength), 0)
		if err != nil {
			return nil, fmt.Errorf("pfring: NewRing failed: %v", err)
		}
		filter := fmt.Sprintf("ip and dst %s and icmp[icmptype] = icmp-echoreply and icmp[4:2] > %d and icmp[6:2] > %d", p.sourceIP, icmpIDSeqInitNum, icmpIDSeqInitNum)
		if err := ring.SetBPFFilter(filter); err != nil {
			return nil, fmt.Errorf("pfring: set bpf filter failed: %v, filter: %s", err, filter)
		}
		if err := ring.SetSocketMode(pfring.ReadOnly); err != nil {
			return nil, fmt.Errorf("pfring: set socket mode failed: %v", err)
		}
		if err := ring.SetDirection(pfring.ReceiveOnly); err != nil {
			return nil, fmt.Errorf("pfring: set direction failed: %v", err)
		}
		if err := ring.Enable(); err != nil {
			return nil, fmt.Errorf("pfring: enable failed: %v", err)
		}
		p.ring = ring
		defer p.ring.Close()

		packetSource := gopacket.NewPacketSource(p.ring, layers.LinkTypeEthernet)
		packetSource.NoCopy = true
		p.packetSource = packetSource
	}

	// receive packets
	go func() {
		defer close(p.ipEventChan)

		fmt.Fprintf(os.Stderr, "kping recv: started, ipCount: %d\n", p.ipCount)
		wg := new(sync.WaitGroup)
		stime := time.Now()

		var recvParallel int64
		var recvFunc func(index int, wg *sync.WaitGroup)
		switch p.recvMode {
		case "afpacket":
			recvParallel = p.afpacketRecvOpts.Parallel
			recvFunc = p.afpacketRecv
		case "pfring":
			recvParallel = p.pfringRecvOpts.Parallel
			recvFunc = p.pfringRecv
		case "batch":
			recvParallel = p.batchRecvOpts.Parallel
			recvFunc = p.batchRecv
		default:
			panic(fmt.Sprintf("ping recv: unknown recvMode: %s", p.recvMode))

		}
		for i := 0; i < int(recvParallel); i++ {
			wg.Add(1)
			index := i
			go recvFunc(index, wg)
		}

		// receive ready
		close(p.recvReady)

		wg.Wait()
		fmt.Fprintf(os.Stderr, "kping recv: all done, ipCount: %d, usedTime: %s\n", p.ipCount, time.Since(stime))
	}()

	// send packets
	go func() {
		defer p.cancel()
		defer close(p.sendDone)

		// wait receive ready
		<-p.recvReady

		stime := time.Now()
		addrBatchChan := make(chan addrBatch)
		fmt.Fprintf(os.Stderr, "kping send: started, ipCount: %d, \n", p.ipCount)

		// cocurenccy send packets
		for i := 0; i < int(p.sendOpts.Parallel); i++ {
			index := i
			go p.send(index, addrBatchChan) // after close addrBatchChan, goroutine return
		}

		// caculate batch number
		var batchNum = 0
		if p.ipCount%p.sendOpts.BatchSize == 0 {
			batchNum = int(p.ipCount / p.sendOpts.BatchSize)
		} else {
			batchNum = int(p.ipCount/p.sendOpts.BatchSize + 1)
		}

		// fill address for each batch
		addrBatchs := make([]addrBatch, batchNum)
		for i := range addrBatchs {
			addrBatchs[i] = addrBatch{
				addrs: make([]*net.IPAddr, 0, p.sendOpts.BatchSize),
			}
		}
		for i, addr := range p.addrs {
			j := i / int(p.sendOpts.BatchSize)
			batch := addrBatchs[j]
			batch.addrs = append(batch.addrs, addr)
			addrBatchs[j] = batch
		}

		// send extra 10 packets
		for n := 0; n < int(p.count+10); n++ {
			stime := time.Now()
			for _, batch := range addrBatchs {
				batch.seq = n
				addrBatchChan <- batch
			}
			time.Sleep(p.interval)
			fmt.Fprintf(os.Stderr, "kping send: seq %d(%d) done, usedTime: %s\n", n, p.count+10, time.Since(stime))
		}

		// sent done, sleep 1s
		close(addrBatchChan)
		fmt.Fprintf(os.Stderr, "kping send: all done, ipCount: %d, usedTime: %s\n", p.ipCount, time.Since(stime))
		time.Sleep(1 * time.Second)
	}()

	p.process()
	statistics = p.statistic()
	return statistics, nil
}
