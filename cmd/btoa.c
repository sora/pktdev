#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define PKTDEV_HDRLEN    (4)
#define ETH_HDRLEN       (14)

int main(int argc, char **argv)
{
	unsigned char ibuf[2000], obuf[6000];
	int fd, i;
	unsigned short magic, pktlen;
	int olen;

	if (argc != 2) {
		printf("Usage: ./btoa /dev/pkt/eth0\n");
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open pktdev device: %s\n", argv[1]);
		return 1;
	}

	while (1) {
		if (read(fd, ibuf, PKTDEV_HDRLEN) <= 0)
			break;
		magic = *(short *)&ibuf[0];
		pktlen = *(short *)&ibuf[2];
		if (magic != 0x3776) {
			printf("format error: magic code %X %X\n", magic, pktlen);
			return 1;
		}
		if ((pktlen < 40) || (pktlen > 9014)) {
			printf("format size: pktlen %X\n", pktlen);
			return 1;
		}

		if (read(fd, ibuf, pktlen) <= 0)
			break;
		sprintf(obuf, "%02X%02X%02X%02X%02X%02X %02X%02X%02X%02X%02X%02X %02X%02X",
				ibuf[ 0], ibuf[ 1], ibuf[ 2], ibuf[ 3], ibuf[ 4], ibuf[ 5],
				ibuf[ 6], ibuf[ 7], ibuf[ 8], ibuf[ 9], ibuf[10], ibuf[11],
				ibuf[12], ibuf[13]);
		olen = strlen(obuf);
		for (i = ETH_HDRLEN; i < pktlen; i++) {
			sprintf(obuf + olen + ((i - ETH_HDRLEN) * 3), " %02X", ibuf[i]);
		}
		strcat(obuf, "\n");
		write (1, obuf, strlen(obuf));
	}
	return 0;
}
