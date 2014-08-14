pktdev
======

#### How to use
```bash
$ git clone git@github.com:sora/pktdev.git
$ cd pktdev
$ make
$ sudo insmod ./pktdev.ko interface=“p2p1”
$ sudo chmod 777 /dev/pkt/p2p1
$ (cd exp; make)
$ exp/wr-64b-595pkt /dev/pkt/p2p1
```

## TX overview

![pktdev-tx](https://raw.githubusercontent.com/wiki/sora/pktdev/i/pktdev-tx.png)
