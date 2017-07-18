/*Package kping implements large scale & high performance ICMP ping.

Example:

	pinger, err := NewPinger("10.0.0.1", 100, 10, 1*time.Minute, 100*time.Millisecond)
	if err != nil {
		logger.Fatalln(err)
	}
	if err := pinger.SetRecvMode("afpacket"); err != nil{
		logger.Fatalln(err)
	}
	recvOpts := AfPacketRecvOptions{
		Parallel: 2,
		BlockMB:  256,
		Timeout:  100 * time.Millisecond,
		Iface:    "eth1",
	}
	if err := pinger.SetAfPacketRecvOptins(recvOpts); err != nil {
		logger.Fatalln(err)
	}
	if err := pinger.AddIPs([]string{"114.114.114.114", "8.8.8.8"}); err != nil {
		logger.Fatalln(err)
	}
	statistics, err : = pinger.Run()
	if err != nil {
		logger.Fatalln(err)
	}
	for _, statistic := range statistics {
		fmt.Printf("%v\n", statistic)
	}

*/
package kping
