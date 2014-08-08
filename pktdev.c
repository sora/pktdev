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
#include <linux/vmalloc.h>
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

#define MAX_PKT_SZ  (9014)
#define MIN_PKT_SZ  (60)
#define PKT_BUF_SZ  (1024*1024*4)
#define PKT_RING_SZ (1024*1024*32)


#define func_enter() pr_debug("entering %s\n", __func__);

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
	unsigned short ethhdr_len, data_len;

	func_enter();

	if (skb->pkt_type == PACKET_OUTGOING)	 // DROP loopback PACKET
		goto lend;

	if (debug) {
		pr_info("Test protocol: Packet Received with length: %u\n", skb->len+18);
	}

	if (down_interruptible(&pktdev_sem)) {
		pr_info("down_interruptible for read failed\n");
		return -ERESTARTSYS;
	}

	ethhdr_len = (unsigned short)skb->mac_len;
	data_len = (unsigned short)skb->len;

	if ((pbuf0.rx_write_ptr + PKTDEV_BIN_HDR_SZ + ethhdr_len + data_len) >
		 pbuf0.rx_end_ptr) {
		memcpy(pbuf0.rx_start_ptr, pbuf0.rx_read_ptr,
			(pbuf0.rx_write_ptr - pbuf0.rx_read_ptr ));
		pbuf0.rx_write_ptr -= (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr);
		pbuf0.rx_read_ptr = pbuf0.rx_start_ptr;
	}

	*(unsigned short *)pbuf0.rx_write_ptr = PKTDEV_MAGIC;
	pbuf0.rx_write_ptr += 2;
	*(unsigned short *)pbuf0.rx_write_ptr = ethhdr_len + data_len;
	pbuf0.rx_write_ptr += 2;
	memcpy(pbuf0.rx_write_ptr, skb_mac_header(skb), (int)ethhdr_len);
	pbuf0.rx_write_ptr += ethhdr_len;
	memcpy(pbuf0.rx_write_ptr, skb->data, (int)data_len);
	pbuf0.rx_write_ptr += data_len;

	wake_up_interruptible(&read_q);

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

	rtnl_lock();
	dev_set_promiscuity(device, 1);
	rtnl_unlock();

	pktdev_update_txring_free();

	if (debug) {
		pr_info("entering %s\n", __func__);
		pr_info("[op] block: max: %d, start: %p, end: %p, txring_free %d, txring_rd: %p, txring_wr: %p\n",
			(int)PKT_BUF_SZ, pbuf0.txring_start, pbuf0.txring_end, txring_free,
			pbuf0.txring_rd, pbuf0.txring_wr);
	}

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

	if (wait_event_interruptible(read_q,
		(pbuf0.rx_read_ptr != pbuf0.rx_write_ptr)))
		return -ERESTARTSYS;

	available_read_len = (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr);

	if (count > available_read_len)
		copy_len = available_read_len;
	else
		copy_len = count;

	if (copy_to_user(buf, pbuf0.rx_read_ptr, copy_len)) {
		pr_info("copy_to_user failed\n");
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
	unsigned char *tmp_txring_rd;

	func_enter();

	//txring_wr_snapshot = pbuf0.txring_wr;

tx_loop:

	if (pbuf0.txring_rd == pbuf0.txring_wr)
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
	if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
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
			if (ret == NETDEV_TX_BUSY) {
				//pr_info( "fail packet_direct_xmit=%d\n", ret );
				goto tx_fail;
			}
		}

		tmp_txring_rd += frame_len;
		if (tmp_txring_rd > pbuf0.txring_end)
		 	tmp_txring_rd -= (pbuf0.txring_end - pbuf0.txring_start);
		pbuf0.txring_rd =
			(unsigned char *)((uintptr_t)tmp_txring_rd & 0xfffffffffffffffc);
	}

	if (waitqueue_active(&write_q)) {           // if pktdev_wirte is blocked:
		pktdev_update_txring_free();              //   - update blocking condition
		wake_up_interruptible(&write_q);          //   - try to wake up blocking
	}

tx_fail:
	goto tx_loop;

tx_end:
err:
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

	if (wait_event_interruptible(write_q, (txring_free > 524288))) {
		pr_info("[wa] block: max: %d, start: %p, end: %p, txring_free %d, txring_rd: %p, txring_wr: %p\n",
				(int)PKT_BUF_SZ, pbuf0.txring_start, pbuf0.txring_end, txring_free,
				pbuf0.txring_rd, pbuf0.txring_wr);
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
	if (unlikely(magic != PKTDEV_MAGIC)) {
		pr_info("[wr] data format error: magic code: %X\n", (int)magic);
		return -EFAULT;
	}

	// check frame_len header
	frame_len = (pbuf0.txbuf_rd[2] << 8) | pbuf0.txbuf_rd[3];
	if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
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
		(unsigned char *)((uintptr_t)tmp_txring_wr & 0xfffffffffffffffc);
	pktdev_update_txring_free();

	if (count == (pbuf0.txbuf_rd - pbuf0.txbuf_start))
		goto copy_end;

	goto copy_to_ring;

copy_end:

	// send process
	if(!work_busy(&work1))
		queue_work(pd_wq, &work1);

	return count;
}

static int pktdev_release(struct inode *inode, struct file *filp)
{

	func_enter();

	rtnl_lock();
	dev_set_promiscuity(device, -1);
	rtnl_unlock();

	if (debug) {
		pr_info("entering %s\n", __func__);
		pr_info("[cl] block: max: %d, start: %p, end: %p, txring_free %d, txring_rd: %p, txring_wr: %p\n",
				(int)PKT_BUF_SZ, pbuf0.txring_start, pbuf0.txring_end, txring_free,
				pbuf0.txring_rd, pbuf0.txring_wr);
	}

	return 0;
}

static unsigned int pktdev_poll(struct file* filp, poll_table* wait)
{
	unsigned int retmask = 0;

	func_enter();

	poll_wait(filp, &read_q,  wait);
//	poll_wait( filp, &write_q, wait );

	if (pbuf0.rx_read_ptr != pbuf0.rx_write_ptr) {
		retmask |= (POLLIN  | POLLRDNORM);
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
	if (!device) {
		pr_warn("Could not find %s\n", interface);
		ret = -1;
		goto error;
	}

	/* workqueue */
//	pd_wq = alloc_workqueue("pktdev", WQ_UNBOUND, 0);
	pd_wq = create_singlethread_workqueue("pktdev");
	if (!pd_wq) {
		pr_err("alloc_workqueue failed\n");
		ret = -ENOMEM;
		goto out;
	}
	INIT_WORK(&work1, pktdev_tx_body);

	/* Set receive buffer */
	if ((pbuf0.rx_start_ptr = vmalloc(PKT_RING_SZ)) == 0) {
		pr_info("fail to vmalloc\n");
		ret = -1;
		goto error;
	}
	pbuf0.rx_end_ptr = (pbuf0.rx_start_ptr + PKT_RING_SZ - 1);
	pbuf0.rx_write_ptr = pbuf0.rx_start_ptr;
	pbuf0.rx_read_ptr  = pbuf0.rx_start_ptr;

	/* Set transmitte buffer */
	if ((pbuf0.txbuf_start = kmalloc(PKT_BUF_SZ, GFP_KERNEL)) == 0) {
		pr_info("fail to kmalloc\n");
		ret = -1;
		goto error;
	}
	pbuf0.txbuf_end = (pbuf0.txbuf_start + PKT_BUF_SZ - 1);
	pbuf0.txbuf_wr  = pbuf0.txbuf_start;
	pbuf0.txbuf_rd  = pbuf0.txbuf_start;

	/* Set transmitte buffer */
	if ((pbuf0.txring_start = vmalloc(PKT_RING_SZ)) == 0) {
		pr_info("fail to vmalloc\n");
		ret = -1;
		goto error;
	}
	pbuf0.txring_end = (pbuf0.txring_start + PKT_RING_SZ - 1);
	pbuf0.txring_wr  = pbuf0.txring_start;
	pbuf0.txring_rd  = pbuf0.txring_start;

	txring_free = PKT_BUF_SZ;

	/* register character device */
	sprintf(name, "%s/%s", DRV_NAME, interface);
	pktdev_dev.name = name;
	ret = misc_register(&pktdev_dev);
	if (ret) {
		pr_info("fail to misc_register (MISC_DYNAMIC_MINOR)\n");
		goto error;
	}

	sema_init(&pktdev_sem, 1);
	init_waitqueue_head(&read_q);
	init_waitqueue_head(&write_q);

	pktdev_pack.dev = device;
	dev_add_pack(&pktdev_pack);

	return 0;

error:
	if (pbuf0.rx_start_ptr) {
		vfree(pbuf0.rx_start_ptr);
		pbuf0.rx_start_ptr = NULL;
	}

	if (pbuf0.txbuf_start) {
		kfree(pbuf0.txbuf_start);
		pbuf0.txbuf_start = NULL;
	}

	if (pbuf0.txring_start) {
		vfree(pbuf0.txring_start);
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

	if (pbuf0.rx_start_ptr) {
		vfree(pbuf0.rx_start_ptr);
		pbuf0.rx_start_ptr = NULL;
	}

	if (pbuf0.txbuf_start) {
		kfree(pbuf0.txbuf_start);
		pbuf0.txbuf_start = NULL;
	}

	if (pbuf0.txring_start) {
		vfree(pbuf0.txring_start);
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
MODULE_PARM_DESC(interface, "interface");
