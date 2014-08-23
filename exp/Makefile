default: pktgen_stdout btoa atob wr-1518b-41pkt wr-64b-50pkt wr-64b-595pkt
	gcc -O -o pktgen_stdout pktgen_stdout.c
	gcc -O -o btoa btoa.c
	gcc -O -o atob atob.c
	gcc -O -o wr-64b-50pkt wr-64b-50pkt.c
	gcc -O -o wr-64b-595pkt wr-64b-595pkt.c
	gcc -O -o wr-1518b-41pkt wr-1518b-41pkt.c

clean:
	rm -f *.o pktgen_stdout btoa atob wr-1518b-41pkt wr-64b-50pkt wr-64b-595pkt
