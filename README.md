pktdev
======

#### How to use
```bash
$ git clone git@github.com:sora/pktdev.git
$ cd pktdev
$ make
$ sudo insmod ./pktdev0.ko if=“p2p1”
$ sudo chmod 777 /dev/pkt/p2p1
$ ./exp/wr /dev/pkt/p2p1
```
