pktdev: Packet Character Device
===============================

**Under development**

Pktdev is a virtual network device for Shell/Command-based packet processing with high performance.
Pktdev abstracts each NIC port as a common character device such as `/dev/pkt/p2p1` and APIs for receiving and sending packets are only  `read(2)` and `write(2)` system calls in the same manner a serial device.
Packet processing applications is developed combining with 1. OS commands(`dd`, `cat`, etc), 2. UNIX PIPE(`|`), 3. Redirections(`<`, `>`) and 4. `Pktdev`.

#### Features

* Support Linux 3.16 and newer kernel
* Running on vanilla kernel and NIC driver
* Multiple core packet sending
* TX performance (2014/8, Intel Core i7 3770 + Intel 82599 NIC)
  * Multiple core (best case): 12.5 Mpps using 4 CPU core
  * Single core: XX Mpps
* RX performance
  * Multiple core: XX Gbps (XX Mpps)

#### Development platform

Linux ([David Miller's -next networking tree](https://kernel.googlesource.com/pub/scm/linux/kernel/git/davem/net-next/))

#### Install
```bash
$ git clone git@github.com:sora/pktdev.git
$ cd pktdev
$ make
$ sudo insmod ./pktdev.ko interface="p2p1" tx_cpus="4" txring_size="32"
$ sudo chmod 777 /dev/pkt/p2p1
$ (cd cmd; make)
$ cmd/pktgen_stdout -s 60 -n 10 -m 10 > /dev/pkt/p2p1
```

#### Parameters

Name        | about
------------|--------------------------------------
interface   | Target network interface
tx_cpus     | Number of CPU cores for transmission
txring_size | Tx buffer size for each CPU cores

#### Applications

```bash
# one-way bridging
$ dd -i /dev/pkt/p2p1 -o /dev/pkt/p2p2

# capture
$ dd -i /dev/pkt/p2p1 -o recv.pkt

# traffic replay
$ dd -i ./recv.pkt -o /dev/pkt/p2p1

# pktgen (64byte, 14.88Mpps)
$ cmd/pktgen_stdout -s 60 -n 41 -m 36295 > /dev/pkt/p2p1

# mirroring (todo)
$ cmd/btoa /dev/pkt/p2p1 | tee cmd/atob /dev/pkt/p2p1 | cmd/atob dev/pkt/p2p2

# One-liner VLAN packet filtering (todo)
$ cmd/btoa /dev/pkt/p2p1 | grep '8100 00 02' | cmd/atob /dev/pkt/p2p2

# capture traffic with pcapng format (todo)
$ cmd/pktdump -i /dev/rpkt/p2p1 -o recv.pcapng
```

#### packet format (version 1)

````bash
0                      16 (bit)
+-----------------------+
|  Magic code (0x3776)  |
+-----------------------+
|      Frame length     |
+-----------------------+
|                       |
|      Packet data      |
|                       |
+-----------------------+
````

#### Performance technics

![pktdev-tx3](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx3.png)


#### TX overview

![pktdev-tx](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx.png)
![pktdev-tx2](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx2.png)


#### Todo

* Rx with multiple core
* support `skb->xmit_more`
