#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/semaphore.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/interrupt.h>

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/errno.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>

#include <linux/workqueue.h>
#include <linux/if_packet.h>

#define VERSION  "0.0.0"
#define DRV_NAME "pkt"

#define PKTDEV_MAGIC      (0x3776)
#define PKTDEV_BIN_HDR_SZ (4)

#define MAX_PKT_SZ (9014)
#define MIN_PKT_SZ (60)
#define PKT_BUF_SZ (1024*1024*4)


#define func_enter() pr_debug("entering %s\n", __func__);

#define _SKP  0x20
static const unsigned char _atob[] = {
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 0-7 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 8-15 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 16-23 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 24-31 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 32-39 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 40-47 */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,     /* 48-55 */
	0x08, 0x09, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 56-63 */
	_SKP, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, _SKP,     /* 64-71 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 72-79 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 80-87 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 88-95 */
	_SKP, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, _SKP,     /* 96-103 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 104-111 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 112-119 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 120-127 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 128-135 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 136-143 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 144-151 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 152-159 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 160-167 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 168-175 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 176-183 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 184-191 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 192-199 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 200-207 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 208-215 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 216-223 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 224-231 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 232-239 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 240-247 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP };   /* 248-255 */

static const short _btoa[] = {
	0x3030, 0x3130, 0x3230, 0x3330, 0x3430, 0x3530, 0x3630, 0x3730,     /* 0-7 */
	0x3830, 0x3930, 0x4130, 0x4230, 0x4330, 0x4430, 0x4530, 0x4630,     /* 8-15 */
	0x3031, 0x3131, 0x3231, 0x3331, 0x3431, 0x3531, 0x3631, 0x3731,     /* 16-23 */
	0x3831, 0x3931, 0x4131, 0x4231, 0x4331, 0x4431, 0x4531, 0x4631,     /* 24-31 */
	0x3032, 0x3132, 0x3232, 0x3332, 0x3432, 0x3532, 0x3632, 0x3732,     /* 32-39 */
	0x3832, 0x3932, 0x4132, 0x4232, 0x4332, 0x4432, 0x4532, 0x4632,     /* 40-47 */
	0x3033, 0x3133, 0x3233, 0x3333, 0x3433, 0x3533, 0x3633, 0x3733,     /* 48-55 */
	0x3833, 0x3933, 0x4133, 0x4233, 0x4333, 0x4433, 0x4533, 0x4633,     /* 56-63 */
	0x3034, 0x3134, 0x3234, 0x3334, 0x3434, 0x3534, 0x3634, 0x3734,     /* 64-71 */
	0x3834, 0x3934, 0x4134, 0x4234, 0x4334, 0x4434, 0x4534, 0x4634,     /* 72-79 */
	0x3035, 0x3135, 0x3235, 0x3335, 0x3435, 0x3535, 0x3635, 0x3735,     /* 80-87 */
	0x3835, 0x3935, 0x4135, 0x4235, 0x4335, 0x4435, 0x4535, 0x4635,     /* 88-95 */
	0x3036, 0x3136, 0x3236, 0x3336, 0x3436, 0x3536, 0x3636, 0x3736,     /* 96-103 */
	0x3836, 0x3936, 0x4136, 0x4236, 0x4336, 0x4436, 0x4536, 0x4636,     /* 104-111 */
	0x3037, 0x3137, 0x3237, 0x3337, 0x3437, 0x3537, 0x3637, 0x3737,     /* 112-119 */
	0x3837, 0x3937, 0x4137, 0x4237, 0x4337, 0x4437, 0x4537, 0x4637,     /* 120-127 */
	0x3038, 0x3138, 0x3238, 0x3338, 0x3438, 0x3538, 0x3638, 0x3738,     /* 128-135 */
	0x3838, 0x3938, 0x4138, 0x4238, 0x4338, 0x4438, 0x4538, 0x4638,     /* 136-143 */
	0x3039, 0x3139, 0x3239, 0x3339, 0x3439, 0x3539, 0x3639, 0x3739,     /* 144-151 */
	0x3839, 0x3939, 0x4139, 0x4239, 0x4339, 0x4439, 0x4539, 0x4639,     /* 152-159 */
	0x3041, 0x3141, 0x3241, 0x3341, 0x3441, 0x3541, 0x3641, 0x3741,     /* 160-167 */
	0x3841, 0x3941, 0x4141, 0x4241, 0x4341, 0x4441, 0x4541, 0x4641,     /* 168-175 */
	0x3042, 0x3142, 0x3242, 0x3342, 0x3442, 0x3542, 0x3642, 0x3742,     /* 176-183 */
	0x3842, 0x3942, 0x4142, 0x4242, 0x4342, 0x4442, 0x4542, 0x4642,     /* 184-191 */
	0x3043, 0x3143, 0x3243, 0x3343, 0x3443, 0x3543, 0x3643, 0x3743,     /* 192-199 */
	0x3843, 0x3943, 0x4143, 0x4243, 0x4343, 0x4443, 0x4543, 0x4643,     /* 200-207 */
	0x3044, 0x3144, 0x3244, 0x3344, 0x3444, 0x3544, 0x3644, 0x3744,     /* 208-215 */
	0x3844, 0x3944, 0x4144, 0x4244, 0x4344, 0x4444, 0x4544, 0x4644,     /* 216-223 */
	0x3045, 0x3145, 0x3245, 0x3345, 0x3445, 0x3545, 0x3645, 0x3745,     /* 224-231 */
	0x3845, 0x3945, 0x4145, 0x4245, 0x4345, 0x4445, 0x4545, 0x4645,     /* 232-239 */
	0x3046, 0x3146, 0x3246, 0x3346, 0x3446, 0x3546, 0x3646, 0x3746,     /* 240-247 */
	0x3846, 0x3946, 0x4146, 0x4246, 0x4346, 0x4446, 0x4546, 0x4646 };   /* 248-255 */


static struct semaphore pktdev_sem;
static wait_queue_head_t write_q;
static wait_queue_head_t read_q;

/* workqueue */
static struct workqueue_struct *pd_wq;
struct work_struct work1;


/* receive and transmitte buffer */
struct _pbuf_dma {
	unsigned char   *rx_start_ptr;		/* rx buf start */
	unsigned char   *rx_end_ptr;		/* rx buf end */
	unsigned char   *rx_write_ptr;		/* rx write ptr */
	unsigned char   *rx_read_ptr;		/* rx read ptr */
	unsigned char   *txbuf_start;		/* tx buf start */
	unsigned char   *txbuf_end;		/* tx buf end */
	unsigned char   *txbuf_wr;		/* tx write ptr */
	unsigned char   *txbuf_rd;		/* tx read ptr */
	unsigned char   *txring_start;		/* tx buf start */
	unsigned char   *txring_end;		/* tx buf end */
	unsigned char   *txring_wr;		/* tx write ptr */
	unsigned char   *txring_rd;		/* tx read ptr */
} static pbuf0={0,0,0,0,0,0,0,0,0,0,0,0};

static int txring_free;
static int txq_len = 0;
struct net_device* device = NULL;

/* Module parameters, defaults. */
static int debug = 0;
static char *interface = "p2p1";

#define debug_wq()   pr_info("start: %p, end: %p, wr: %p, rd: %p, free: %d\n", pbuf0.txring_start, pbuf0.txring_end, pbuf0.txring_wr, pbuf0.txring_rd, txring_free);


static int pktdev_pack_rcv(struct sk_buff *skb, struct net_device *dev,
				struct packet_type *pt, struct net_device *dev2);
static int pktdev_open(struct inode *inode, struct file *filp);
static ssize_t pktdev_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos);
static int packet_direct_xmit(struct sk_buff *skb);
static ssize_t pktdev_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos);
static int pktdev_release(struct inode *inode, struct file *filp);
static unsigned int pktdev_poll( struct file* filp, poll_table* wait );
static long pktdev_ioctl(struct file *filp,
				unsigned int cmd, unsigned long arg);
static int pktdev_update_txring_free(void);


static int pktdev_pack_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *dev2)
{
	int i, frame_len;
	unsigned char *p;

	func_enter();

	if (skb->pkt_type == PACKET_OUTGOING)	 // DROP loopback PACKET
		goto lend;

	frame_len = (skb->len)*3+31;

	if (debug) {
		pr_info( "Test protocol: Packet Received with length: %u\n", skb->len+18 );
	}

	if ( down_interruptible( &pktdev_sem ) ) {
		pr_info( "down_interruptible for read failed\n" );
		return -ERESTARTSYS;
	}

	if ( (pbuf0.rx_write_ptr + frame_len + 0x10) > pbuf0.rx_end_ptr ) {
		memcpy( pbuf0.rx_start_ptr, pbuf0.rx_read_ptr, (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr ));
		pbuf0.rx_write_ptr -= (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr );
		pbuf0.rx_read_ptr = pbuf0.rx_start_ptr;
	}

	p = skb_mac_header(skb);
	for ( i = 0; i < 14; ++i ) {
		*(unsigned short *)pbuf0.rx_write_ptr = _btoa[ p[i] ];
		pbuf0.rx_write_ptr += 2;
		if ( pbuf0.rx_write_ptr > pbuf0.rx_end_ptr )
			pbuf0.rx_write_ptr -= (pbuf0.rx_end_ptr - pbuf0.rx_start_ptr + 1);
		if ( i == 5 || i== 11 || i == 13 ) {
			*pbuf0.rx_write_ptr++ = ' ';
		}
	}
	p = skb->data;
	for ( i = 0; i < (skb->len) ; ++i) {
		*(unsigned short *)pbuf0.rx_write_ptr = _btoa[ p[i] ];
		pbuf0.rx_write_ptr += 2;
		if ( pbuf0.rx_write_ptr > pbuf0.rx_end_ptr )
			pbuf0.rx_write_ptr -= (pbuf0.rx_end_ptr - pbuf0.rx_start_ptr + 1);
		if ( likely( i != ((skb->len) - 1 ) ) ) {
			*pbuf0.rx_write_ptr++ = ' ';
		} else {
			*pbuf0.rx_write_ptr++ = '\n';
		}
		if ( pbuf0.rx_write_ptr > pbuf0.rx_end_ptr )
			pbuf0.rx_write_ptr -= (pbuf0.rx_end_ptr - pbuf0.rx_start_ptr + 1);
	}

	wake_up_interruptible( &read_q );

	up( &pktdev_sem );

lend:
	/* Don't mangle buffer if shared */
	if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
		return 0;

	kfree_skb(skb);
	return skb->len;
}

static int pktdev_open(struct inode *inode, struct file *filp)
{

	func_enter();

//	rtnl_lock();
//	dev_set_promiscuity(device, 1);
//	rtnl_unlock();

	return 0;
}

static int pktdev_update_txring_free(void)
{
	if (pbuf0.txring_rd > pbuf0.txring_wr)
		txring_free = pbuf0.txring_rd - pbuf0.txring_wr;
	else
		txring_free = PKT_BUF_SZ - (pbuf0.txring_wr - pbuf0.txring_rd);

	return 0;
}

static ssize_t pktdev_read(struct file *filp, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int copy_len, available_read_len;

	func_enter();

	if ( wait_event_interruptible( read_q, ( pbuf0.rx_read_ptr != pbuf0.rx_write_ptr ) ) )
		return -ERESTARTSYS;

	available_read_len = (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr);

	if ( count > available_read_len )
		copy_len = available_read_len;
	else
		copy_len = count;

	if ( copy_to_user( buf, pbuf0.rx_read_ptr, copy_len ) ) {
		pr_info( "copy_to_user failed\n" );
		return -EFAULT;
	}

	pbuf0.rx_read_ptr += copy_len;

	return copy_len;
}

/* from af_packet.c */
static int packet_direct_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	const struct net_device_ops *ops = dev->netdev_ops;
	netdev_features_t features;
	struct netdev_queue *txq;
	int ret = NETDEV_TX_BUSY;
	u16 queue_map;

	if (unlikely(!netif_running(dev) || !netif_carrier_ok(dev))) {
		goto drop;
	}

	features = netif_skb_features(skb);
	if (skb_needs_linearize(skb, features) && __skb_linearize(skb)) {
		goto drop;
	}

	queue_map = skb_get_queue_mapping(skb);
	txq = netdev_get_tx_queue(dev, queue_map);

	local_bh_disable();

	HARD_TX_LOCK(dev, txq, smp_processor_id());

	if (!netif_xmit_frozen_or_drv_stopped(txq)) {
		ret = ops->ndo_start_xmit(skb, dev);
		if (ret == NETDEV_TX_OK)
			txq_trans_update(txq);
	}

	HARD_TX_UNLOCK(dev, txq);

	local_bh_enable();

	if (!dev_xmit_complete(ret))
		kfree_skb(skb);

	return ret;
drop:
	atomic_long_inc(&dev->tx_dropped);
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

/*
 * pktdev_tx_body():
 *
 * Packet format (binary):
 * 0                      16 (bit)
 * +-----------------------+
 * |  Magic code (0x3776)  |
 * +-----------------------+
 * |      Frame length     |
 * +-----------------------+
 * |                       |
 * |      Packet data      |
 * |                       |
 * +-----------------------+
 */
static void pktdev_tx_body(struct work_struct *work)
{
	int ret, tmplen;
	struct sk_buff *tx_skb = NULL;
	unsigned short magic, frame_len;
	unsigned char *txring_wr_snapshot, *tmp_txring_rd;

	func_enter();

	txring_wr_snapshot = pbuf0.txring_wr;

tx_loop:

//	debug_wq();

	if (pbuf0.txring_rd == txring_wr_snapshot)
		goto tx_end;

	tmp_txring_rd = pbuf0.txring_rd;

	// check magic code header
	magic = (tmp_txring_rd[0] << 8) | tmp_txring_rd[1];
	if (unlikely(magic != PKTDEV_MAGIC)) {
		pr_info("[wq] format error: magic code %X, rd %p, wr %p\n",
		(int)magic, tmp_txring_rd, pbuf0.txring_wr );
		goto err;
	}

	// check frame_len header
	frame_len = (tmp_txring_rd[2] << 8) | tmp_txring_rd[3];
	if (unlikely( (frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ) )) {
		pr_info("[wq] data size error: %X, rd %p, wr %p\n",
		(int)frame_len, tmp_txring_rd, pbuf0.txring_wr);
		goto err;
	}

	tmp_txring_rd += 4;
	if (tmp_txring_rd > pbuf0.txring_end)
		tmp_txring_rd -= (pbuf0.txring_end - pbuf0.txring_start);

	// alloc skb
	tx_skb = netdev_alloc_skb(device, frame_len);
	if (likely(tx_skb)) {
		tx_skb->dev = device;

		// fill packet
		skb_put(tx_skb, frame_len);
		if ((tmp_txring_rd + frame_len) > pbuf0.txring_end) {
			tmplen = pbuf0.txring_end - tmp_txring_rd;
			memcpy(tx_skb->data, tmp_txring_rd, tmplen);
			memcpy(tx_skb->data + tmplen, pbuf0.txring_start, (frame_len - tmplen));
		} else {
			memcpy(tx_skb->data, tmp_txring_rd, frame_len);
		}

		// sending
		ret = packet_direct_xmit(tx_skb);
		if (ret) {
			if (ret == 0x10) {    // TX_BUSY
				//pr_info( "fail packet_direct_xmit=%d\n", ret );
				goto tx_fail;
			}
		}

		tmp_txring_rd += frame_len;
		if (tmp_txring_rd > pbuf0.txring_end)
		 	tmp_txring_rd -= (pbuf0.txring_end - pbuf0.txring_start);
		pbuf0.txring_rd =
			(unsigned char *)((uintptr_t)(tmp_txring_rd + 3) & 0xfffffffffffffffc);
		pktdev_update_txring_free();
	}

tx_fail:
	wake_up_interruptible(&write_q);

	goto tx_loop;

tx_end:
err:
	--txq_len;
	return;
}

static ssize_t pktdev_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int has_fragment_data = 0;
	unsigned int len, tmplen, fragment_len;
	unsigned short magic, frame_len;
	static unsigned char fragment[MAX_PKT_SZ];
	unsigned char *tmp_txring_wr;

	func_enter();

	if ((count >= PKT_BUF_SZ) || (count < MIN_PKT_SZ))
		return -ENOSPC;

	// blocking
	queue_work(pd_wq, &work1);

	if (wait_event_interruptible(write_q, (txring_free > 524288))) {
		pr_info("block: max: %d, txring_free %d, txring_rd: %p, txring_wr: %p\n",
				(int)PKT_BUF_SZ, txring_free, pbuf0.txring_rd, pbuf0.txring_wr);
		return -ERESTARTSYS;
	}

	pbuf0.txbuf_wr = pbuf0.txbuf_start;
	pbuf0.txbuf_rd = pbuf0.txbuf_start;

	// fragment data
	if (has_fragment_data) {
		memcpy(pbuf0.txbuf_wr, fragment, fragment_len);
		pbuf0.txbuf_wr += fragment_len;
		has_fragment_data = 0;
	}

	if (copy_from_user(pbuf0.txbuf_wr, buf, count)) {
		pr_info( "copy_from_user failed.\n" );
		return -EFAULT;
	}

copy_to_ring:

	// check magic code header
	magic = (pbuf0.txbuf_rd[0] << 8) | pbuf0.txbuf_rd[1];
	if (magic != PKTDEV_MAGIC) {
		pr_info("[wr] data format error: magic code: %X\n", (int)magic);
		return -EFAULT;
	}

	// check frame_len header
	frame_len = (pbuf0.txbuf_rd[2] << 8) | pbuf0.txbuf_rd[3];
	if ((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ)) {
		pr_info("[wr] data size error: %X\n", (int)frame_len);
		return -EFAULT;
	}

	len = PKTDEV_BIN_HDR_SZ + frame_len;

	// copy fragment data to tmp buf
	fragment_len = count - (pbuf0.txbuf_rd - pbuf0.txbuf_start);
	if (len > fragment_len) {
		has_fragment_data = 1;
		memcpy(fragment, pbuf0.txbuf_rd, fragment_len);
		goto copy_end;
	}

	// txbuf to txring
	tmp_txring_wr = pbuf0.txring_wr;
	if ((tmp_txring_wr + len) > pbuf0.txring_end) {
		tmplen = pbuf0.txring_end - tmp_txring_wr;
		memcpy(tmp_txring_wr, pbuf0.txbuf_rd, tmplen);
		memcpy(pbuf0.txring_start, (pbuf0.txbuf_rd + tmplen), (len - tmplen));
		tmp_txring_wr = pbuf0.txring_start + (len - tmplen);
	} else {
		memcpy(tmp_txring_wr, pbuf0.txbuf_rd, len);
	 	tmp_txring_wr+= len;
	}
	pbuf0.txbuf_rd += len;

	// update ring write pointer with memory alignment
	pbuf0.txring_wr =
		(unsigned char *)((uintptr_t)(tmp_txring_wr + 3) & 0xfffffffffffffffc);
	pktdev_update_txring_free();

	if (count == (pbuf0.txbuf_rd - pbuf0.txbuf_start))
		goto copy_end;

	goto copy_to_ring;

copy_end:
	// send process
	if (++txq_len < 30)
		queue_work(pd_wq, &work1);

	//debug_wq();

	return count;
}

static int pktdev_release(struct inode *inode, struct file *filp)
{

		func_enter();

//	rtnl_lock();
//	dev_set_promiscuity(device, -1);
//	rtnl_unlock();

	return 0;
}

static unsigned int pktdev_poll( struct file* filp, poll_table* wait )
{
	unsigned int retmask = 0;

	func_enter();

	poll_wait( filp, &read_q,  wait );
//	poll_wait( filp, &write_q, wait );

	if ( pbuf0.rx_read_ptr != pbuf0.rx_write_ptr ) {
		retmask |= ( POLLIN  | POLLRDNORM );
	}

	return retmask;
}

static long pktdev_ioctl(struct file *filp,
			unsigned int cmd, unsigned long arg)
{
	func_enter();

	return  -ENOTTY;
}

static struct file_operations pktdev_fops = {
	.owner		= THIS_MODULE,
	.read		= pktdev_read,
	.write		= pktdev_write,
	.poll		= pktdev_poll,
	.compat_ioctl	= pktdev_ioctl,
	.open		= pktdev_open,
	.release	= pktdev_release,
};

static struct miscdevice pktdev_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DRV_NAME,
	.fops = &pktdev_fops,
};

static struct packet_type pktdev_pack =
{
	__constant_htons(ETH_P_ALL),
	NULL,
	pktdev_pack_rcv,

	(void *) 1,
	NULL
};

static int __init pktdev_init(void)
{
	int ret;
	static char name[16];

	pr_info("%s\n", __func__);

	device = dev_get_by_name(&init_net, interface);
	if ( !device ) {
		pr_warn( "Could not find %s\n", interface );
		ret = -1;
		goto error;
	}

	/* workqueue */
//	pd_wq = alloc_workqueue("pktdev", WQ_UNBOUND, 0);
	pd_wq = create_singlethread_workqueue("pktdev");
	if (!pd_wq) {
		pr_err( "alloc_workqueue failed\n" );
		ret = -ENOMEM;
		goto out;
	}
	INIT_WORK( &work1, pktdev_tx_body );

	/* Set receive buffer */
	if ( ( pbuf0.rx_start_ptr = kmalloc(PKT_BUF_SZ, GFP_KERNEL) ) == 0 ) {
		pr_info( "fail to kmalloc\n" );
		ret = -1;
		goto error;
	}
	pbuf0.rx_end_ptr = (pbuf0.rx_start_ptr + PKT_BUF_SZ - 1);
	pbuf0.rx_write_ptr = pbuf0.rx_start_ptr;
	pbuf0.rx_read_ptr  = pbuf0.rx_start_ptr;

	/* Set transmitte buffer */
	if ( ( pbuf0.txbuf_start = kmalloc(PKT_BUF_SZ, GFP_KERNEL) ) == 0 ) {
		pr_info( "fail to kmalloc\n" );
		ret = -1;
		goto error;
	}
	pbuf0.txbuf_end = (pbuf0.txbuf_start + PKT_BUF_SZ - 1);
	pbuf0.txbuf_wr  = pbuf0.txbuf_start;
	pbuf0.txbuf_rd  = pbuf0.txbuf_start;

	/* Set transmitte buffer */
	if ( ( pbuf0.txring_start = kmalloc(PKT_BUF_SZ, GFP_KERNEL) ) == 0 ) {
		pr_info( "fail to kmalloc\n" );
		ret = -1;
		goto error;
	}
	pbuf0.txring_end = (pbuf0.txring_start + PKT_BUF_SZ - 1);
	pbuf0.txring_wr  = pbuf0.txring_start;
	pbuf0.txring_rd  = pbuf0.txring_start;

	txring_free = PKT_BUF_SZ;

	/* register character device */
	sprintf( name, "%s/%s", DRV_NAME, interface );
	pktdev_dev.name = name;
	ret = misc_register(&pktdev_dev);
	if (ret) {
		pr_info( "fail to misc_register (MISC_DYNAMIC_MINOR)\n" );
		goto error;
	}

	sema_init( &pktdev_sem, 1 );
	init_waitqueue_head( &read_q );
	init_waitqueue_head( &write_q );

	pktdev_pack.dev = device;
	dev_add_pack(&pktdev_pack);

	return 0;

error:
	if ( pbuf0.rx_start_ptr ) {
		kfree( pbuf0.rx_start_ptr );
		pbuf0.rx_start_ptr = NULL;
	}

	if ( pbuf0.txbuf_start ) {
		kfree( pbuf0.txbuf_start );
		pbuf0.txbuf_start = NULL;
	}

	if ( pbuf0.txring_start ) {
		kfree( pbuf0.txring_start );
		pbuf0.txring_start = NULL;
	}

out:
	return ret;
}

static void __exit pktdev_cleanup(void)
{
	func_enter();

	misc_deregister(&pktdev_dev);

	/* workqueue */
	if (pd_wq) {
		flush_workqueue(pd_wq);
		destroy_workqueue(pd_wq);
		pd_wq = NULL;
	}

	dev_remove_pack(&pktdev_pack);

	if ( pbuf0.rx_start_ptr ) {
		kfree( pbuf0.rx_start_ptr );
		pbuf0.rx_start_ptr = NULL;
	}

	if ( pbuf0.txbuf_start ) {
		kfree( pbuf0.txbuf_start );
		pbuf0.txbuf_start = NULL;
	}

	if ( pbuf0.txring_start ) {
		kfree( pbuf0.txring_start );
		pbuf0.txring_start = NULL;
	}
}

module_init(pktdev_init);
module_exit(pktdev_cleanup);

MODULE_AUTHOR("Yohei Kuga <sora@haeena.net>");
MODULE_DESCRIPTION("Packet Character device");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debug mode");
module_param( interface , charp , S_IRUGO);
MODULE_PARM_DESC( interface, "interface" );
