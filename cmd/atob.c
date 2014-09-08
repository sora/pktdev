#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	unsigned char obuf[6000];
	int fd, ret, linelen = 0, pktlen;
	size_t linecap = 0;
	char *line = NULL, c, *cp, pos;

	if (argc != 2) {
		printf("Usage: ./atob /dev/pkt/eth0\n");
		return 1;
	}

	fd = open(argv[1], O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open pktdev device: %s\n", argv[1]);
		return 1;
	}

	while ((linelen = getline(&line, &linecap, stdin)) != -1) {
		pos = 0;
		pktlen = 0;
		cp = line;
		while ((c = *(cp++)) != '\n') {

			// skip space
			if (c == ' ')
					continue;

			// conver to upper char
			if (c >= 'a' && c <= 'z')
					c -= 0x20;

			// is hexdigit?
			if (c >= '0' && c <= '9') {
				if (pos == 0) {
					obuf[pktlen] = (c - '0') << 4;
					pos = 1;
				} else {
					obuf[pktlen] |= (c - '0');
					++pktlen;
					pos = 0;
				}
			} else if (c >= 'A' && c <= 'F') {
				if (pos == 0) {
					obuf[pktlen] = (c - 'A' + 10) << 4;
					pos = 1;
				} else {
					obuf[pktlen] |= (c - 'A' + 10);
					++pktlen;
					pos = 0;
				}
			} else {
				fprintf(stderr, "data format error: c=%c\n", c);
				ret = 1;
				goto out;
			}
		}

		if (pos == 1) {
			fprintf(stderr, "data format error: pos=%d\n", (int)pos);
			ret = 1;
			goto out;
		}
		if ((pktlen < 40) || (pktlen > 9014)) {
			fprintf(stderr, "packet size error: %d\n", pktlen);
			ret = 1;
			goto out;
		}
		write(fd, obuf, pktlen);
		ret = 0;
	}

out:
	close(fd);

	if (line)
		free(line);

	return ret;
}
