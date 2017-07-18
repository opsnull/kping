/*Package kping implements large scale & high performance ICMP ping.

Example:

	pinger, err := NewPinger("10.0.0.1", 100, 10, 1*time.Minute, 100*time.Millisecond)
	if err != nil {
		logger.Fatalln(err)
	}

	if sendOpts, err := SendOptions(1024, 10*1024*1024, 30, 100*time.Second, 20*time.Millsecond); err != nil{
		logger.Fatalln(err)
	} else if err := pinger.SetOptions(sendOpts) {
		logger.Fatalln(err)
	}

	if err := pinger.SetRecvMode("afpacket"); err != nil{
		logger.Fatalln(err)
	}

	if recvOpts, err := AfPacketRecvOptions(2, 256, 128, "eth1", 100*time.Millsecond); err != nil{
		logger.Fatalln(err)
	} else if err := pinger.SetOptions(recvOpts) {
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
