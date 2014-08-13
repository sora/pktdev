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
#include <linux/kthread.h>
#include <linux/if_packet.h>
#include <linux/delay.h>

#define VERSION  "0.0.0"
#define DRV_NAME "pkt"

#define PKTDEV_MAGIC      (0x3776)
#define PKTDEV_BIN_HDR_SZ (4)

#define MAX_PKT_SZ  (9014)
#define MIN_PKT_SZ  (60)
#define PKT_BUF_SZ  (1024*1024*4)
#define PKT_RING_SZ (1024*1024*16)

#define MAX_CPUS    (31)

#define func_enter() pr_debug("entering %s\n", __func__);

static struct semaphore pktdev_sem;
static wait_queue_head_t write_q;
static wait_queue_head_t read_q;

/* workqueue */
static struct workqueue_struct *pd_wq;
static struct work_struct do_xmit;

struct pktdev_thread {
	unsigned int cpu;
	struct task_struct *tsk;
	unsigned char *ring_ptr;
	struct list_head list;
	struct completion start_done;
};
static struct pktdev_thread pktdev_threads;

struct _txring {
	unsigned int  cpu;		/* cpu id */
	unsigned char *start_ptr;		/* tx buf start */
	unsigned char *end_ptr;		/* tx buf end */
	unsigned char *write_ptr;		/* tx write ptr */
	unsigned char *read_ptr;		/* tx read ptr */
	unsigned int  available;		/* txring free space */
} static txring[MAX_CPUS];

static unsigned int num_cpus;

/* receive and transmitte buffer */
struct _pbuf {
	unsigned char *rx_start_ptr;		/* rx buf start */
	unsigned char *rx_end_ptr;		/* rx buf end */
	unsigned char *rx_write_ptr;		/* rx write ptr */
	unsigned char *rx_read_ptr;		/* rx read ptr */
	unsigned char *txbuf_start;		/* tx buf start */
	unsigned char *txbuf_end;		/* tx buf end */
	unsigned char *txbuf_wr;		/* tx write ptr */
	unsigned char *txbuf_rd;		/* tx read ptr */
} static pbuf0 = {0,0,0,0,0,0,0,0};

struct net_device* device = NULL;

/* Module parameters, defaults. */
static int debug = 0;
static char *interface = "p2p1";

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
			(int)PKT_BUF_SZ, txring[0].start_ptr, txring[0].end_ptr, txring[0].available,
			txring[0].read_ptr, txring[0].write_ptr);
	}

	return 0;
}

static int pktdev_update_txring_free(void)
{
	if (txring[0].read_ptr > txring[0].write_ptr)
		txring[0].available = txring[0].read_ptr - txring[0].write_ptr;
	else
		txring[0].available = PKT_BUF_SZ - (txring[0].write_ptr - txring[0].read_ptr);

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

	//txring_wr_snapshot = txring[0].write_ptr;

tx_loop:

	if (txring[0].read_ptr == txring[0].write_ptr)
		goto tx_end;

	tmp_txring_rd = txring[0].read_ptr;

	// check magic code header
	magic = *(unsigned short *)&tmp_txring_rd[0];
	if (unlikely(magic != PKTDEV_MAGIC)) {
		pr_info("[wq] format error: magic code %X, rd %p, wr %p\n",
		(int)magic, tmp_txring_rd, txring[0].write_ptr );
		goto err;
	}

	// check frame_len header
	frame_len = *(unsigned short *)&tmp_txring_rd[2];
	if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
		pr_info("[wq] data size error: %X, rd %p, wr %p\n",
			(int)frame_len, tmp_txring_rd, txring[0].write_ptr);
		goto err;
	}

	tmp_txring_rd += 4;
	if (tmp_txring_rd > txring[0].end_ptr)
		tmp_txring_rd -= (txring[0].end_ptr - txring[0].start_ptr);

	// alloc skb
	tx_skb = netdev_alloc_skb(device, frame_len);
	if (likely(tx_skb)) {
		tx_skb->dev = device;

		// fill packet
		skb_put(tx_skb, frame_len);
		if ((tmp_txring_rd + frame_len) > txring[0].end_ptr) {
			tmplen = txring[0].end_ptr - tmp_txring_rd;
			memcpy(tx_skb->data, tmp_txring_rd, tmplen);
			memcpy(tx_skb->data + tmplen, txring[0].start_ptr, (frame_len - tmplen));
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
		if (tmp_txring_rd > txring[0].end_ptr)
		 	tmp_txring_rd -= (txring[0].end_ptr - txring[0].start_ptr);
		txring[0].read_ptr =
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

	if (wait_event_interruptible(write_q, (txring[0].available > 524288))) {
		pr_info("[wa] block: max: %d, start: %p, end: %p, txring_free %d, txring_rd: %p, txring_wr: %p\n",
				(int)PKT_BUF_SZ, txring[0].start_ptr, txring[0].end_ptr, txring[0].available,
				txring[0].read_ptr, txring[0].write_ptr);
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
	magic = *(unsigned short *)&pbuf0.txbuf_rd[0];
	if (unlikely(magic != PKTDEV_MAGIC)) {
		pr_info("[wr] data format error: magic code: %X\n", (int)magic);
		return -EFAULT;
	}

	// check frame_len header
	frame_len = *(unsigned short *)&pbuf0.txbuf_rd[2];
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
	tmp_txring_wr = txring[0].write_ptr;
	if ((tmp_txring_wr + len) > txring[0].end_ptr) {
		tmplen = txring[0].end_ptr - tmp_txring_wr;
		memcpy(tmp_txring_wr, pbuf0.txbuf_rd, tmplen);
		memcpy(txring[0].start_ptr, (pbuf0.txbuf_rd + tmplen), (len - tmplen));
		tmp_txring_wr = txring[0].start_ptr + (len - tmplen);
	} else {
		memcpy(tmp_txring_wr, pbuf0.txbuf_rd, len);
	 	tmp_txring_wr+= len;
	}
	pbuf0.txbuf_rd += len;

	// update ring write pointer with memory alignment
	txring[0].write_ptr =
		(unsigned char *)((uintptr_t)tmp_txring_wr & 0xfffffffffffffffc);
	pktdev_update_txring_free();

	if (count == (pbuf0.txbuf_rd - pbuf0.txbuf_start))
		goto copy_end;

	goto copy_to_ring;

copy_end:

	// send process
	if(!work_busy(&do_xmit))
		queue_work_on(txring[0].cpu, pd_wq, &do_xmit);

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
				(int)PKT_BUF_SZ, txring[0].start_ptr, txring[0].end_ptr, txring[0].available,
				txring[0].read_ptr, txring[0].write_ptr);
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

/* malloc transmittion ring buffer */
static int pktdev_create_txring(int cpu)
{
	if ((txring[cpu].start_ptr = vmalloc_node(PKT_RING_SZ,
			cpu_to_node(cpu))) == 0) {
		pr_info("fail to vmalloc: cpu=%d\n", cpu);
		return -ENOMEM;
	}
	txring[cpu].cpu       = cpu;
	txring[cpu].end_ptr   = (txring[cpu].start_ptr + PKT_RING_SZ - 1);
	txring[cpu].write_ptr = txring[cpu].start_ptr;
	txring[cpu].read_ptr  = txring[cpu].start_ptr;
	txring[cpu].available = PKT_BUF_SZ;

	return 0;
}

static int pktdev_thread_worker(void *arg)
{
	struct pktdev_thread *t = arg;
	int cpu = t->cpu;
	int i = 0;

	complete(&t->start_done);

	pr_info("starting pktdev/%d:  pid=%d\n", cpu, task_pid_nr(current));

	while (!kthread_should_stop()) {
		pr_info("[kthread] my cpu is %d (%d)\n", cpu, i++);
		msleep_interruptible(1000); // a sec
	}

	pr_info("kthread_exit: cpu=%d\n", cpu);

	return 0;
}

static int pktdev_create_tx_thread(int cpu)
{
	struct pktdev_thread *t;
	struct task_struct *p;

	t = kzalloc_node(sizeof(struct pktdev_thread), GFP_KERNEL,
			cpu_to_node(cpu));
	if (!t) {
		pr_info("error: out of memory, can't create new thread\n");
		return -ENOMEM;
	}
	t->cpu = cpu;
	t->ring_ptr = txring[cpu].start_ptr;
	list_add_tail(&t->list, &pktdev_threads.list);

	init_completion(&t->start_done);
	p = kthread_create_on_node(pktdev_thread_worker,
			t,
			cpu_to_node(cpu),
			"kpktdevd_%d", cpu);
	if (IS_ERR(p)) {
		pr_info("kernel_thread() failed for cpu %d\n", t->cpu);
		list_del(&t->list);
		kfree(t);
		return PTR_ERR(p);
	}
	kthread_bind(p, cpu);
	t->tsk = p;

	wake_up_process(p);
	wait_for_completion(&t->start_done);

	return 0;
}

static int __init pktdev_init(void)
{
	int ret, cpu, i = 0;
	static char name[16];
	struct pktdev_thread *t, *n;

	pr_info("%s\n", __func__);

	device = dev_get_by_name(&init_net, interface);
	if (!device) {
		pr_warn("Could not find %s\n", interface);
		ret = -1;
		goto error;
	}

	/* workqueue */
//	pd_wq = alloc_workqueue("kpktdevd", WQ_UNBOUND, 0);
	pd_wq = create_workqueue("kpktdevd");
	if (!pd_wq) {
		pr_err("alloc_workqueue failed\n");
		ret = -ENOMEM;
		goto out;
	}
	INIT_WORK(&do_xmit, pktdev_tx_body);

	// create xmit kthreads
	INIT_LIST_HEAD(&pktdev_threads.list);

	// setup xmit buffers and threads
	for_each_online_cpu(cpu) {
		int err;

		// for debug
		if (cpu != i++) {
			pr_info("[init] cpu != i: cpu=%d, i=%d\n", cpu, i);
			ret = -1;
			goto error;
		}

		// txring
		err = pktdev_create_txring(cpu);
		if (err)
			pr_info("cannot create txring for cpu %d (%d)\n", cpu, err);

		// tx thread
		err = pktdev_create_tx_thread(cpu);
		if (err)
			pr_info("cannot create thread for cpu %d (%d)\n", cpu, err);
	}

	list_for_each_entry(t, &pktdev_threads.list, list) {
		pr_info("Dump list entries: t->cpu=%d\n", t->cpu);
	}

	num_cpus = i;
	if (i < 1 || i != num_online_cpus()) {
		pr_info("[init] cpus are disabled: i=%d, num_online_cpus=%d\n",
				i, num_online_cpus());
		ret = -1;
		goto error;
	}

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
	pr_info("got error in pktdev_init()\n");

	if (pbuf0.rx_start_ptr) {
		vfree(pbuf0.rx_start_ptr);
		pbuf0.rx_start_ptr = NULL;
	}

	if (pbuf0.txbuf_start) {
		kfree(pbuf0.txbuf_start);
		pbuf0.txbuf_start = NULL;
	}

	list_for_each_entry(t, &pktdev_threads.list, list) {
		pr_info("vfree on cpu%d\n", t->cpu);
		if (txring[t->cpu].start_ptr) {
			vfree(txring[t->cpu].start_ptr);
			txring[t->cpu].start_ptr = NULL;
			t->ring_ptr = NULL;
		}
	}

	/* kthread */
	list_for_each_entry_safe(t, n, &pktdev_threads.list, list) {
		list_del(&t->list);
		kthread_stop(t->tsk);
		kfree(t);
	}

out:
	return ret;
}

static void __exit pktdev_cleanup(void)
{
	struct pktdev_thread *t, *n;

	func_enter();

	misc_deregister(&pktdev_dev);

	/* workqueue */
	if (pd_wq) {
		flush_workqueue(pd_wq);
		destroy_workqueue(pd_wq);
		pd_wq = NULL;
	}

	/* rx */
	dev_remove_pack(&pktdev_pack);

	/* buffers */
	if (pbuf0.rx_start_ptr) {
		vfree(pbuf0.rx_start_ptr);
		pbuf0.rx_start_ptr = NULL;
	}

	if (pbuf0.txbuf_start) {
		kfree(pbuf0.txbuf_start);
		pbuf0.txbuf_start = NULL;
	}

	list_for_each_entry(t, &pktdev_threads.list, list) {
		if (txring[t->cpu].start_ptr) {
			pr_info("vfree on cpu%d\n", t->cpu);
			vfree(txring[t->cpu].start_ptr);
			txring[t->cpu].start_ptr = NULL;
			t->ring_ptr = NULL;
		}
	}

	/* kthread */
	list_for_each_entry_safe(t, n, &pktdev_threads.list, list) {
		pr_info("there is pktdev_cleanup(): cpu=%d\n", t->cpu);
		list_del(&t->list);
		kthread_stop(t->tsk);
		kfree(t);
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
