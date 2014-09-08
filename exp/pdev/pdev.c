#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#define PKTDEV_MAGIC       (0x3776)
#define PKTDEV_HDR_SZ      (4)

#define MAX_PKT_SZ         (9014)
#define MIN_PKT_SZ         (60)
#define PKT_BUF_SZ         (1024*1024*32)
#define RING_THRESHOLD     (MAX_PKT_SZ*2)

#define MAX_CPUS           (31)
#define XMIT_BUDGET        (0xFF)

/* debug */
static int debug = 0;
#define D(...)    if(debug) fprintf(stderr, __VA_ARGS__)


struct thdata {
	pthread_t th;
	sem_t start;
	unsigned int *pkt_count;
	bool exit_flg;
};

struct ring {
	unsigned char *start_ptr;		/* buf start */
	unsigned char *end_ptr;			/* buf end */
	unsigned char *write_ptr;		/* write ptr */
	unsigned char *read_ptr;		/* read ptr */
};


static inline void my_clock_gettime(struct timespec *);
void *thread_worker(void *);
void thread_init(struct thdata *, unsigned int *);
int ringbuf_init(struct ring *, unsigned int);
void main_worker(unsigned int *);
static inline unsigned short get_pktlen(const unsigned char *);
static inline int get_free_space(const struct ring *);
static inline unsigned char *aligened(const unsigned char *);

/* global variables */
static struct thdata *th_a;
static struct ring *ra;

static inline void my_clock_gettime(struct timespec *ts)
{
#ifdef __MACH__
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), REALTIME_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	ts->tv_sec = mts.tv_sec;
	ts->tv_nsec = mts.tv_nsec;
#else
	clock_gettime(CLOCK_REALTIME, ts);
#endif
}

void thread_init(struct thdata *thd, unsigned int *cnt)
{
	thd->pkt_count = cnt;
	thd->exit_flg = false;
	sem_init(&thd->start, 0, 0);
	pthread_create(&thd->th, NULL, thread_worker, thd);
}

int ringbuf_init(struct ring *ring, unsigned int size)
{
	ring->start_ptr = calloc(1, size);
	if (ring->start_ptr == NULL)
		return -1;
	ring->end_ptr   = ring->start_ptr + size;
	ring->read_ptr  = ring->start_ptr;
	ring->write_ptr = ring->start_ptr;

	return 0;
}

static inline unsigned short get_pktlen(const unsigned char *pkt)
{
	// check magic code header
	if (((pkt[0] << 8) | pkt[1]) != PKTDEV_MAGIC) {
		fprintf(stderr, "format error: magic code %X\n", (int)((pkt[0] << 8) | pkt[1]));
		return 1;
	}
	return ((pkt[2] << 8) | pkt[3]); // frame_len
}

static inline int get_free_space(const struct ring *ring)
{
	unsigned int space;

	if (ring->read_ptr > ring->write_ptr)
		space = ring->read_ptr - ring->write_ptr;
	else
		space = PKT_BUF_SZ - (ring->write_ptr - ring->read_ptr);

	return space;
}

static inline unsigned char *aligened(const unsigned char *ptr)
{
	return (unsigned char *)(((uintptr_t)ptr + 3) & 0xfffffffffffffffc);
}

void *thread_worker(void *thd)
{
	const unsigned char *tp;
	unsigned short pktlen;
	unsigned int tmplen, len;
	struct thdata *priv = (struct thdata *)thd;

	sem_wait(&priv->start);

	while (1) {
		//D("loop: rd_cnt:%d\n", *priv->pkt_count);
		if (ra->read_ptr != ra->write_ptr) {
			tp = ra->read_ptr;

			pktlen = get_pktlen(tp);
			if ((pktlen > MAX_PKT_SZ) || (pktlen < MIN_PKT_SZ)) {
				fprintf(stderr, "[rd] invalid packet size: %X\n", (int)pktlen);
				break;
			}

			len = PKTDEV_HDR_SZ + pktlen;
			if ((tp + len) > ra->end_ptr) {
				tmplen = ra->end_ptr - tp;
				write(1, tp, tmplen);
				write(1, ra->start_ptr, len - tmplen);
			} else {
				write(1, tp, len);
			}
			tp += len;
			if (tp >= ra->end_ptr)
				tp -= (ra->end_ptr - ra->start_ptr);

			ra->read_ptr = aligened(tp);
			++(*priv->pkt_count);
			D("[rd] st:%p, ed:%p, rd:%p, wr:%p, rd_cnt:%d\n",
					ra->start_ptr, ra->end_ptr, ra->read_ptr, ra->write_ptr, *priv->pkt_count);
		} else {
			if (priv->exit_flg) {
				D("pthread_exit\n");
				pthread_exit(0);
			}
		}
	}

	return NULL;
}

void main_worker(unsigned int *pkt_count)
{
	unsigned short pktlen;
	unsigned char *tp;
	unsigned int tmplen;

	while (1) {

		if (read(0, ra->write_ptr, PKTDEV_HDR_SZ) <= 0) {
			D("No input data\n");
			break;
		}

		if (get_free_space(ra) < RING_THRESHOLD) {
			D("free_space: %d\n", get_free_space(ra));
			continue;
		}

		tp = ra->write_ptr;

		pktlen = get_pktlen(tp);
		if ((pktlen > MAX_PKT_SZ) || (pktlen < MIN_PKT_SZ)) {
			fprintf(stderr, "[wr] invalid packet size: %X\n", (int)pktlen);
		}
		tp += PKTDEV_HDR_SZ;

		if ((tp + pktlen) > ra->end_ptr) {
			tmplen = ra->end_ptr - tp;
			read(0, tp, tmplen);
			read(0, ra->start_ptr, pktlen - tmplen);
		} else {
			read(0, tp, pktlen);
		}
		tp += pktlen;
		if (tp >= ra->end_ptr)
			tp -= (ra->end_ptr - ra->start_ptr);

		ra->write_ptr = aligened(tp);
		++(*pkt_count);
		D("[wr] st:%p, ed:%p, rd:%p, wr:%p, wr_cnt:%d\n",
				ra->start_ptr, ra->end_ptr, ra->read_ptr, ra->write_ptr, *pkt_count);
	}
}

int main(int argc, char *argv[])
{
	unsigned int wr_cnt = 0, rd_cnt = 0;
	struct timespec ts0, ts1;
	long laptime;
	int ret = 0;

	if (argc != 1) {
		fprintf(stderr, "Usage: cat from | ring > to\n");
		return 1;
	}

	th_a = malloc(sizeof(struct thdata));
	thread_init(th_a, &rd_cnt);

	ra = malloc(sizeof(struct ring));
	ringbuf_init(ra, PKT_BUF_SZ);

	sem_post(&th_a->start);

	my_clock_gettime(&ts0);
	main_worker(&wr_cnt);

	while (1) {
		if ((wr_cnt == rd_cnt) || rd_cnt != 0) {
			th_a->exit_flg = true;
			break;
		}
	}

	D("pthread_join\n");
	pthread_join(th_a->th, NULL);
	my_clock_gettime(&ts1);
	laptime = (ts1.tv_sec - ts0.tv_sec) * 1000 * 1000 + (ts1.tv_nsec - ts0.tv_nsec) / 1000;

	fprintf(stderr, "laptime: %ld us\n", laptime);

	if (th_a) {
		free(th_a);
		th_a = NULL;
	}
	if (ra->start_ptr) {
		free(ra->start_ptr);
		ra->start_ptr = NULL;
	}
	if (ra) {
		free(ra);
		ra = NULL;
	}

	return ret;
}

