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

#include <linux/kthread.h>
#include <linux/if_packet.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#define VERSION  "0.0.0"
#define DRV_NAME "pkt"

#define PKTDEV_MAGIC       (0x3776)
#define PKTDEV_HDR_SZ      (4)

#define MAX_PKT_SZ         (9014)
#define MIN_PKT_SZ         (60)
#define PKT_BUF_SZ         (1024*1024*4)
#define PKT_RING_SZ        (1024*1024*32)
#define RING_THRESHOLD     (MAX_PKT_SZ*2)

#define MAX_CPUS           (31)
#define XMIT_BUDGET        (0xFF)

#define func_enter() pr_debug("entering %s\n", __func__);

struct pktdev_thread {
	unsigned int cpu;			/* cpu id that the thread is runnig */
	struct task_struct *tsk;		/* xmit kthread */
	struct completion start_done;
	struct list_head list;
};

struct pktdev_buf {
	unsigned char *start_ptr;		/* buf start */
	unsigned char *end_ptr;			/* buf end */
	unsigned char *write_ptr;		/* write ptr */
	unsigned char *read_ptr;		/* read ptr */
};

struct pktdev_dev {
	/* target NIC port */
	struct net_device *device;

	/* number of online cpu at load module */
	unsigned int num_cpus;

	/* RX wait queue */
	wait_queue_head_t read_q;
	struct semaphore pktdev_sem;

	/* tx threads for build_skb and xmit */
	struct pktdev_thread pktdev_threads;

	/* tx ring buffers */
	struct pktdev_buf *txring;

	/* tx tmp buffer to store copy_from_user() data */
	struct pktdev_buf *txbuf;

	/* rx ring buffer from dev_add_pack */
	struct pktdev_buf rxbuf;
};


static int pktdev_pack_rcv(struct sk_buff *skb, struct net_device *dev,
				struct packet_type *pt, struct net_device *dev2);
static int pktdev_open(struct inode *inode, struct file *filp);
static ssize_t pktdev_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos);
static int pktdev_direct_xmit(struct sk_buff *skb, int cpu);
static ssize_t pktdev_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos);
static int pktdev_release(struct inode *inode, struct file *filp);
static unsigned int pktdev_poll( struct file* filp, poll_table* wait );
static long pktdev_ioctl(struct file *filp,
				unsigned int cmd, unsigned long arg);
static int pktdev_get_ring_free_space(struct pktdev_buf);


/* Module parameters, defaults. */
static int debug = 0;
static char *interface = "p2p1";
static int xmit_cpus = 4;   // :todo


/* Global variables */
static struct pktdev_dev *pdev;


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

	if (down_interruptible(&pdev->pktdev_sem)) {
		pr_info("down_interruptible for read failed\n");
		return -ERESTARTSYS;
	}

	ethhdr_len = (unsigned short)skb->mac_len;
	data_len = (unsigned short)skb->len;

	if ((pdev->rxbuf.write_ptr + PKTDEV_HDR_SZ + ethhdr_len + data_len) > pdev->rxbuf.end_ptr) {
		memcpy(pdev->rxbuf.start_ptr, pdev->rxbuf.read_ptr,
			(pdev->rxbuf.write_ptr - pdev->rxbuf.read_ptr ));
		pdev->rxbuf.write_ptr -= (pdev->rxbuf.write_ptr - pdev->rxbuf.read_ptr);
		pdev->rxbuf.read_ptr = pdev->rxbuf.start_ptr;
	}

	*(unsigned short *)pdev->rxbuf.write_ptr = PKTDEV_MAGIC;
	pdev->rxbuf.write_ptr += 2;
	*(unsigned short *)pdev->rxbuf.write_ptr = ethhdr_len + data_len;
	pdev->rxbuf.write_ptr += 2;
	memcpy(pdev->rxbuf.write_ptr, skb_mac_header(skb), (int)ethhdr_len);
	pdev->rxbuf.write_ptr += ethhdr_len;
	memcpy(pdev->rxbuf.write_ptr, skb->data, (int)data_len);
	pdev->rxbuf.write_ptr += data_len;

	wake_up_interruptible(&pdev->read_q);

	up(&pdev->pktdev_sem);

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
	dev_set_promiscuity(pdev->device, 1);
	rtnl_unlock();

	if (debug) {
		pr_info("entering %s\n", __func__);
		pr_info("[op] block: max: %d, start: %p, end: %p, txring_free %d, txring_rd: %p, txring_wr: %p\n",
			(int)PKT_BUF_SZ, pdev->txring[0].start_ptr, pdev->txring[0].end_ptr,
			pktdev_get_ring_free_space(pdev->txring[0]),
			pdev->txring[0].read_ptr, pdev->txring[0].write_ptr);
	}

	return 0;
}

static inline int pktdev_get_ring_free_space(struct pktdev_buf ring)
{
	unsigned int space;

	if (ring.read_ptr > ring.write_ptr)
		space = ring.read_ptr - ring.write_ptr;
	else
		space = PKT_RING_SZ - (ring.write_ptr - ring.read_ptr);

	return space;
}

static ssize_t pktdev_read(struct file *filp, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int copy_len, available_read_len;

	func_enter();

	if (wait_event_interruptible(pdev->read_q,
		(pdev->rxbuf.read_ptr != pdev->rxbuf.write_ptr)))
		return -ERESTARTSYS;

	available_read_len = (pdev->rxbuf.write_ptr - pdev->rxbuf.read_ptr);

	if (count > available_read_len)
		copy_len = available_read_len;
	else
		copy_len = count;

	if (copy_to_user(buf, pdev->rxbuf.read_ptr, copy_len)) {
		pr_info("copy_to_user failed\n");
		return -EFAULT;
	}

	pdev->rxbuf.read_ptr += copy_len;

	return copy_len;
}

/* from af_packet.c */
static int pktdev_direct_xmit(struct sk_buff *skb, int cpu)
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
	//printk( "queue_map=%d\n", (int)queue_map);

	local_bh_disable();

	HARD_TX_LOCK(dev, txq, cpu);

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

static inline u16 pktdev_pick_tx_queue(int cpu, struct net_device *dev)
{
	return (u16) cpu % dev->real_num_tx_queues;
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
static void pktdev_tx_body(int cpu)
{
	int ret, tmplen, budget;
	struct sk_buff *tx_skb = NULL;
	unsigned short magic, frame_len;
	struct pktdev_buf ring;

	budget = XMIT_BUDGET;
	ring = pdev->txring[cpu];

tx_loop:

	if ((pdev->txring[cpu].read_ptr == pdev->txring[cpu].write_ptr)
		|| (--budget < 0))
		goto tx_end;

	ring.read_ptr = pdev->txring[cpu].read_ptr;

	// check magic code header
	magic = *(unsigned short *)&ring.read_ptr[0];
	if (unlikely(magic != PKTDEV_MAGIC)) {
		pr_info("[cpu%d] format error: magic code %X, rd %p, wr %p\n",
		cpu, (int)magic, ring.read_ptr, pdev->txring[cpu].write_ptr);
		goto err;
	}

	// check frame_len header
	frame_len = *(unsigned short *)&ring.read_ptr[2];
	if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
		pr_info("[cpu%d] data size error: %X, rd %p, wr %p\n",
			cpu, (int)frame_len, ring.read_ptr, pdev->txring[cpu].write_ptr);
		goto err;
	}

	ring.read_ptr += PKTDEV_HDR_SZ;
	if (ring.read_ptr > ring.end_ptr)
		ring.read_ptr -= (ring.end_ptr - ring.start_ptr);

	// alloc skb
	tx_skb = netdev_alloc_skb(pdev->device, frame_len);
	if (likely(tx_skb)) {
		tx_skb->dev = pdev->device;
		tx_skb->queue_mapping = pktdev_pick_tx_queue(cpu, pdev->device);

		// fill packet
		skb_put(tx_skb, frame_len);
		if ((ring.read_ptr + frame_len) > ring.end_ptr) {
			tmplen = ring.end_ptr - ring.read_ptr;
			memcpy(tx_skb->data, ring.read_ptr, tmplen);
			memcpy(tx_skb->data + tmplen, ring.start_ptr, (frame_len - tmplen));
		} else {
			memcpy(tx_skb->data, ring.read_ptr, frame_len);
		}

		// sending
		ret = pktdev_direct_xmit(tx_skb, cpu);
		if (ret) {
			if (ret == NETDEV_TX_BUSY) {
				//pr_info( "fail pktdev_direct_xmit=%d\n", ret );
				goto tx_fail;
			}
		}

		ring.read_ptr += frame_len;
		if (ring.read_ptr > ring.end_ptr)
			ring.read_ptr -= (ring.end_ptr - ring.start_ptr);

		pdev->txring[cpu].read_ptr =
			(unsigned char *)((uintptr_t)ring.read_ptr & 0xfffffffffffffffc);
	}

tx_fail:
	goto tx_loop;

tx_end:
err:
	return;
}

/* simple hash generator :todo */
static unsigned int ii = 0;
static inline int pktdev_get_hash(unsigned char *pkt_ptr)
{
	return ii++ % 8;
}

static ssize_t pktdev_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	//int has_fragment_data = 0;
	unsigned int len, tmplen; //, fragment_len;
	unsigned short magic, frame_len;
	int cpu;
	//static unsigned char fragment[MAX_PKT_SZ];

	func_enter();

	cpu = smp_processor_id();

	// for debug
	if (unlikely((count >= PKT_BUF_SZ) || (count < MIN_PKT_SZ)))
		return -ENOSPC;

	pdev->txbuf[cpu].write_ptr = pdev->txbuf[cpu].start_ptr;
	pdev->txbuf[cpu].read_ptr = pdev->txbuf[cpu].start_ptr;

#if 0
	// fragment data
	if (has_fragment_data) {
		memcpy(pdev->txbuf[cpu].write_ptr, fragment, fragment_len);
		pdev->txbuf[cpu].write_ptr += fragment_len;
		has_fragment_data = 0;
	}
#endif

	if (copy_from_user(pdev->txbuf[cpu].write_ptr, buf, count)) {
		pr_info( "copy_from_user failed.\n" );
		return -EFAULT;
	}

	while (likely(count != (pdev->txbuf[cpu].read_ptr - pdev->txbuf[cpu].start_ptr))) {
		struct pktdev_buf ring;
		unsigned int ring_no;
		unsigned char *dbug_rd, *dbug_wr;

		// check magic code header
		magic = *(unsigned short *)&pdev->txbuf[cpu].read_ptr[0];
		if (unlikely(magic != PKTDEV_MAGIC)) {
			pr_info("[wr] data format error: magic code: %X\n", (int)magic);
			return -EFAULT;
		}

		// check frame_len header
		frame_len = *(unsigned short *)&pdev->txbuf[cpu].read_ptr[2];
		if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
			pr_info("[wr] data size error: %X\n", (int)frame_len);
			return -EFAULT;
		}

		len = PKTDEV_HDR_SZ + frame_len;

#if 0
		// copy fragment data to tmp buf
		fragment_len = count - (pdev->txbuf[cpu].read_ptr - pdev->txbuf[cpu].start_ptr);
		if (len > fragment_len) {
			has_fragment_data = 1;
			memcpy(fragment, pdev->txbuf[cpu].read_ptr, fragment_len);
			goto copy_end;
		}
#endif

		// txqueue selecter
		ring_no = pktdev_get_hash(pdev->txbuf[cpu].start_ptr); //pdev->num_cpus;
		ring = pdev->txring[ring_no];
		//pr_info("Break: cpu=%d, rd=%p, wr=%p\n", ring_no,
				//ring.read_ptr, ring.write_ptr);

		// txbuf to txring
		if (likely(pktdev_get_ring_free_space(ring) > RING_THRESHOLD)) {
			// when overwriting
			if (unlikely((ring.write_ptr + len) > ring.end_ptr)) {
				tmplen = ring.end_ptr - ring.write_ptr;
				memcpy(ring.write_ptr, pdev->txbuf[cpu].read_ptr, tmplen);
				memcpy(ring.start_ptr, (pdev->txbuf[cpu].read_ptr + tmplen), (len - tmplen));
				ring.write_ptr = ring.start_ptr + (len - tmplen);
			} else {
				memcpy(ring.write_ptr, pdev->txbuf[cpu].read_ptr, len);
				ring.write_ptr += len;
			}
			pdev->txbuf[cpu].read_ptr += len;

			// update ring write pointer with memory alignment
			pdev->txring[ring_no].write_ptr =
				(unsigned char *)((uintptr_t)ring.write_ptr & 0xfffffffffffffffc);
		} else {
			// return when a ring buffer reached the max size
			dbug_rd = ring.read_ptr;
			dbug_wr = ring.write_ptr;
			pr_info("Break: cpu=%d, rd=%p, wr=%p\n", ring_no,
					dbug_rd, dbug_wr);
			break;
		}
	}

//copy_end:
	return (pdev->txbuf[cpu].read_ptr - pdev->txbuf[cpu].start_ptr);
}

static int pktdev_release(struct inode *inode, struct file *filp)
{
	func_enter();

	rtnl_lock();
	dev_set_promiscuity(pdev->device, -1);
	rtnl_unlock();

	if (debug) {
		pr_info("entering %s\n", __func__);
		pr_info("[cl] block: max: %d, start: %p, end: %p, txring_free %d, txring_rd: %p, txring_wr: %p\n",
				(int)PKT_BUF_SZ, pdev->txring[0].start_ptr, pdev->txring[0].end_ptr,
				pktdev_get_ring_free_space(pdev->txring[0]),
				pdev->txring[0].read_ptr, pdev->txring[0].write_ptr);
	}

	return 0;
}

static unsigned int pktdev_poll(struct file* filp, poll_table* wait)
{
	unsigned int retmask = 0;

	func_enter();

	poll_wait(filp, &pdev->read_q, wait);

	if (pdev->rxbuf.read_ptr != pdev->rxbuf.write_ptr) {
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

static int pktdev_thread_worker(void *arg)
{
	struct pktdev_thread *t = arg;
	int cpu = t->cpu;
	//int i = 0;

	complete(&t->start_done);

	pr_info("starting pktdev/%d:  pid=%d\n", cpu, task_pid_nr(current));

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		//pr_info("[kthread] my cpu is %d (%d, HZ=%d)\n", cpu, i++, HZ);

		if (pdev->txring[cpu].read_ptr == pdev->txring[cpu].write_ptr) {
			schedule_timeout_interruptible(1);
			continue;
		}

		__set_current_state(TASK_RUNNING);

		pktdev_tx_body(cpu);
		if (need_resched())
			schedule();
		else
			cpu_relax();

		set_current_state(TASK_INTERRUPTIBLE);
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
	list_add_tail(&t->list, &pdev->pktdev_threads.list);

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

	return 0;
}

static int __init pktdev_init(void)
{
	int ret, cpu, i;
	static char name[16];
	struct pktdev_thread *t, *n;

	pr_info("%s\n", __func__);

	if ((pdev = kmalloc(sizeof(struct pktdev_dev), GFP_KERNEL)) == 0) {
		pr_info("fail to kmalloc: *pdev\n");
		ret = -1;
		goto error;
	}
	pdev->device = dev_get_by_name(&init_net, interface);
	if (!pdev->device) {
		pr_warn("Could not find %s\n", interface);
		ret = -1;
		goto error;
	}

	// init xmit buffers and threads
	INIT_LIST_HEAD(&pdev->pktdev_threads.list);

	// count number of cpu and create cpu id list and kthreads
	pdev->num_cpus = 0;
	for_each_online_cpu(cpu) {
		int err;

		// for debug
		if (cpu != pdev->num_cpus++) {
			pr_info("[init] cpu != i: cpu=%d, num_cpus=%d\n", cpu, pdev->num_cpus);
			ret = -1;
			goto error;
		}

		// create tx thread on each cpu
		err = pktdev_create_tx_thread(cpu);
		if (err)
			pr_info("cannot create thread for cpu %d (%d)\n", cpu, err);

	}
	if (pdev->num_cpus < 1 || pdev->num_cpus != num_online_cpus()) {
		pr_info("[init] cpus are disabled: num_cpus=%d, num_online_cpus=%d\n",
				pdev->num_cpus, num_online_cpus());
		ret = -1;
		goto error;
	}


	/* Set receive buffer */
	if ((pdev->rxbuf.start_ptr = vmalloc(PKT_RING_SZ)) == 0) {
		pr_info("fail to vmalloc\n");
		ret = -1;
		goto error;
	}
	pdev->rxbuf.end_ptr   = pdev->rxbuf.start_ptr + PKT_RING_SZ - 1;
	pdev->rxbuf.write_ptr = pdev->rxbuf.start_ptr;
	pdev->rxbuf.read_ptr  = pdev->rxbuf.start_ptr;

	/* Set transmitte buffer */
	if ((pdev->txbuf = kmalloc((sizeof(struct pktdev_buf) * pdev->num_cpus),
		GFP_KERNEL)) == 0) {
		pr_info("fail to kmalloc\n");
		ret = -1;
		goto error;
	}

	/* Set tx ring buffer */
	if ((pdev->txring = kmalloc((sizeof(struct pktdev_buf) * pdev->num_cpus),
		GFP_KERNEL)) == 0) {
		pr_info("fail to kmalloc\n");
		ret = -1;
		goto error;
	}

	/* malloc buffers on each numa memory */
	list_for_each_entry(t, &pdev->pktdev_threads.list, list) {
		cpu = t->cpu;

		// txring
		if ((pdev->txring[cpu].start_ptr = vmalloc_node(PKT_RING_SZ,
				cpu_to_node(cpu))) == 0) {
			pr_info("fail to vmalloc: cpu=%d\n", cpu);
			return -ENOMEM;
		}
		pdev->txring[cpu].end_ptr   = pdev->txring[cpu].start_ptr + PKT_RING_SZ - 1;
		pdev->txring[cpu].write_ptr = pdev->txring[cpu].start_ptr;
		pdev->txring[cpu].read_ptr  = pdev->txring[cpu].start_ptr;

		// txbuf
		if ((pdev->txbuf[cpu].start_ptr = kmalloc_node(PKT_BUF_SZ, GFP_KERNEL,
				cpu_to_node(cpu))) == 0) {
			pr_info("fail to kmalloc\n");
			ret = -1;
			goto error;
		}
		pdev->txbuf[cpu].end_ptr   = pdev->txbuf[cpu].start_ptr + PKT_BUF_SZ - 1;
		pdev->txbuf[cpu].write_ptr = pdev->txbuf[cpu].start_ptr;
		pdev->txbuf[cpu].read_ptr  = pdev->txbuf[cpu].start_ptr;

		/* wake up kthreds */
		wake_up_process(t->tsk);
		wait_for_completion(&t->start_done);
	}


	/* register character device */
	sprintf(name, "%s/%s", DRV_NAME, interface);
	pktdev_dev.name = name;
	ret = misc_register(&pktdev_dev);
	if (ret) {
		pr_info("fail to misc_register (MISC_DYNAMIC_MINOR)\n");
		goto error;
	}

	sema_init(&pdev->pktdev_sem, 1);
	init_waitqueue_head(&pdev->read_q);

	pktdev_pack.dev = pdev->device;
	dev_add_pack(&pktdev_pack);

	return 0;

error:
	pr_info("got error in pktdev_init()\n");

	if (pdev->rxbuf.start_ptr) {
		vfree(pdev->rxbuf.start_ptr);
		pdev->rxbuf.start_ptr = NULL;
	}

	for (i = 0; i < pdev->num_cpus; i++) {
		if (pdev->txbuf[i].start_ptr) {
			kfree(pdev->txbuf[i].start_ptr);
			pdev->txbuf[i].start_ptr = NULL;
		}
	}
	if (pdev->txbuf) {
		kfree(pdev->txbuf);
		pdev->txbuf = NULL;
	}

	list_for_each_entry(t, &pdev->pktdev_threads.list, list) {
		pr_info("vfree on cpu%d\n", t->cpu);
		if (pdev->txring[t->cpu].start_ptr) {
			vfree(pdev->txring[t->cpu].start_ptr);
			pdev->txring[t->cpu].start_ptr = NULL;
		}
	}

	/* kthread */
	list_for_each_entry_safe(t, n, &pdev->pktdev_threads.list, list) {
		list_del(&t->list);
		kthread_stop(t->tsk);
		kfree(t);
	}

	if (pdev) {
		kfree(pdev);
		pdev = NULL;
	}

	return ret;
}

static void __exit pktdev_cleanup(void)
{
	struct pktdev_thread *t, *n;
	int i;

	func_enter();

	misc_deregister(&pktdev_dev);

	/* rx */
	dev_remove_pack(&pktdev_pack);

	/* buffers */
	if (pdev->rxbuf.start_ptr) {
		vfree(pdev->rxbuf.start_ptr);
		pdev->rxbuf.start_ptr = NULL;
	}

	for (i = 0; i < pdev->num_cpus; i++) {
		if (pdev->txbuf[i].start_ptr) {
			kfree(pdev->txbuf[i].start_ptr);
			pdev->txbuf[i].start_ptr = NULL;
		}
	}
	if (pdev->txbuf) {
		kfree(pdev->txbuf);
		pdev->txbuf = NULL;
	}

	list_for_each_entry(t, &pdev->pktdev_threads.list, list) {
		if (pdev->txring[t->cpu].start_ptr) {
			pr_info("vfree on cpu%d\n", t->cpu);
			vfree(pdev->txring[t->cpu].start_ptr);
			pdev->txring[t->cpu].start_ptr = NULL;
		}
	}

	/* kthread */
	list_for_each_entry_safe(t, n, &pdev->pktdev_threads.list, list) {
		pr_info("there is pktdev_cleanup(): cpu=%d\n", t->cpu);
		list_del(&t->list);
		kthread_stop(t->tsk);
		kfree(t);
	}

	if (pdev) {
		kfree(pdev);
		pdev = NULL;
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
module_param(interface, charp, S_IRUGO);
MODULE_PARM_DESC(interface, "interface");
module_param(xmit_cpus, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(xmit_cpus, "xmit_cpus");
