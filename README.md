# kping

Package kping implements large scale & high performance ICMP flood ping.

It can send up to 1024 ICMP packets in one system call (sendmmsg), and provides three methods for receiving packets quickly: batch, afpacket, pfring.

See API document on [godoc](https://godoc.org/github.com/opsnull/kping)

Warning: **WORKING IN PROGRESS**

# Example (using af_packet recv mode)

The simplest example:

``` go
// Create a new Pinger
pinger, err := NewPinger("10.0.0.1", 100, 10, 1*time.Minute, 100*time.Millisecond)
if err != nil {
    logger.Fatalln(err)
}

// Add IP addresses to Pinger
if err := pinger.AddIPs([]string{"114.114.114.114", "8.8.8.8"}); err != nil {
    logger.Fatalln(err)
}

// Run !
statistics, err : = pinger.Run()
if err != nil {
    logger.Fatalln(err)
}

// Print result
for ip, statistic := range statistics {
    fmt.Printf("%s: %v\n", ip, statistic)
}
```

You can customize and optimize the send & receive options based on your system:

``` go
// Create a new Pinger
pinger, err := NewPinger("10.0.0.1", 100, 10, 1*time.Minute, 100*time.Millisecond)
if err != nil {
    logger.Fatalln(err)
}

// Set send options
if sendOpts, err := SendOptions(1024, 10*1024*1024, 30, 100*time.Second, 20*time.Millsecond); err != nil{
    logger.Fatalln(err)
} else if err := pinger.SetOptions(sendOpts); err != nil {
    logger.Fatalln(err)
}

// Set Recv mode: afpacket | pfring | batch
if err := pinger.SetRecvMode("afpacket"); err != nil{
    logger.Fatalln(err)
}

// Set afpacket recv mode options
if recvOpts, err := AfPacketRecvOptions(2, 256, 128, "eth1", 100*time.Millsecond); err != nil{
    logger.Fatalln(err)
} else if err := pinger.SetOptions(recvOpts) {
    logger.Fatalln(err)
}

// Add IP addresses to Pinger
if err := pinger.AddIPs([]string{"114.114.114.114", "8.8.8.8"}); err != nil {
    logger.Fatalln(err)
}

// Run !
statistics, err : = pinger.Run()
if err != nil {
    logger.Fatalln(err)
}

// Print result
for ip, statistic := range statistics {
    fmt.Printf("%s: %v\n", ip, statistic)
}
```

## License

Copyright 2017 zhangjun (geekard@qq.com)

Apache License 2.0，[LICENSE](LICENSE).

