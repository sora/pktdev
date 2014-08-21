pktdev
======

#### How to use
```bash
$ git clone git@github.com:sora/pktdev.git
$ cd pktdev
$ make
$ sudo insmod ./pktdev.ko  interface="p2p1" tx_cpus="4" txring_size="128"
$ sudo chmod 777 /dev/pkt/p2p1
$ (cd exp; make)
$ exp/wr-64b-595pkt /dev/pkt/p2p1
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

#### TX overview

![pktdev-tx](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx.png)
![pktdev-tx2](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx2.png)
