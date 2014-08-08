#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PKTDEV_HDRLEN    (4)
#define ETH_HDRLEN       (14)

int main()
{
	unsigned char ibuf[2000], obuf[6000];
	int i;
	unsigned short magic, pktlen;
	int olen;

	while (1) {
		if (read(0, ibuf, PKTDEV_HDRLEN) <= 0)
			break;
		//magic = *(short *)&ibuf[0];
		//pktlen = *(short *)&ibuf[2];
		magic = (ibuf[0] << 8) | ibuf[1];
		pktlen = (ibuf[2] << 8) | ibuf[3];
		if (magic != 0x3776) {
			printf("format error: magic code %X %X\n", magic, pktlen);
			return 1;
		}
		if ((pktlen < 60) || (pktlen > 1518)) {
			printf("format size: pktlen %X\n", pktlen);
			return 1;
		}
		
		if (read(0, ibuf, pktlen) <= 0)
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

