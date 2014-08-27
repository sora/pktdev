pktdev: Packet Character Device
===============================


#### How to use
```bash
$ git clone git@github.com:sora/pktdev.git
$ cd pktdev
$ make
$ sudo insmod ./pktdev.ko interface="p2p1" tx_cpus="4" txring_size="32"
$ sudo chmod 777 /dev/pkt/p2p1
$ (cd exp; make)
$ exp/pktgen_stdout -s 60 -n 10 -m 10 > /dev/pkt/p2p1
```

#### packet format (version 1)

````bash
0                      16 (bit)
+-----------------------+
|  Magic code (0x3776)  |
+-----------------------+
|      Frame length     |
+-----------------------+
|                       |
|      Packet data      |
|                       |
+-----------------------+
````

#### Performance technics

![pktdev-tx3](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx3.png)


#### TX overview

![pktdev-tx](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx.png)
![pktdev-tx2](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx2.png)
