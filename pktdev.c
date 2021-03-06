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
#define RING_THRESHOLD     (MAX_PKT_SZ*2)

#define MAX_CPUS           (31)
#define XMIT_BUDGET        (0xFF)

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define func_enter() pr_debug("entering %s\n", __func__);

#define BUF_INFO(X) \
printk("[%s]: start: %p, end: %p, rd: %p, wr: %p\n", \
		__func__, X.start_ptr, X.end_ptr, X.read_ptr, X.write_ptr);

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

	/* TX ring size on each xmit kthread */
	int txring_size;

	/* RX wait queue */
	wait_queue_head_t read_q;
	struct semaphore pktdev_sem;

	/* tx threads for build_skb and xmit */
	struct pktdev_thread pktdev_threads;

	/* tx ring buffers */
	struct pktdev_buf *txring;

	/* tx tmp buffer to store copy_from_user() data */
	struct pktdev_buf txbuf;

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
static void pktdev_free(void);


/* Module parameters, defaults. */
static int debug = 0;
static char *interface = "p2p1";
static int tx_cpus = 4;   // :todo
static int txring_size = 32;

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

static inline int get_free_space_size(const struct pktdev_buf *ring)
{
	unsigned int space;

	if (ring->read_ptr > ring->write_ptr)
		space = ring->read_ptr - ring->write_ptr;
	else
		space = pdev->txring_size - (ring->write_ptr - ring->read_ptr);

	return space;
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
			get_free_space_size(&pdev->txring[0]),
			pdev->txring[0].read_ptr, pdev->txring[0].write_ptr);
	}

	return 0;
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

static int pktdev_direct_xmit(struct sk_buff *skb, int cpu)
{
	struct net_device *dev = skb->dev;
	netdev_features_t features;
	struct netdev_queue *txq;
	int ret = NETDEV_TX_BUSY;

	if (unlikely(!netif_running(dev) || !netif_carrier_ok(dev))) {
		goto drop;
	}

	features = netif_skb_features(skb);
	if (skb_needs_linearize(skb, features) && __skb_linearize(skb)) {
		goto drop;
	}

	txq = skb_get_tx_queue(dev, skb);

	local_bh_disable();

	HARD_TX_LOCK(dev, txq, cpu);
	if (!netif_xmit_frozen_or_drv_stopped(txq))
		ret = netdev_start_xmit(skb, dev, txq, false);
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

static inline unsigned short pktdev_get_framelen(unsigned char *pkt)
{
	// check magic code header
	if (unlikely(((pkt[0] << 8) | pkt[1]) != PKTDEV_MAGIC)) {
		pr_info("format error: magic code %X\n", (int)((pkt[0] << 8) | pkt[1]));
		return 0;
	}

	return ((pkt[2] << 8) | pkt[3]); // frame_len
}

static inline unsigned char *aligened(unsigned char *p, struct pktdev_buf *buf)
{
	unsigned char *tp;

	tp = (unsigned char *)(((uintptr_t)p + 3) & 0xfffffffffffffffc);

	return (tp != buf->end_ptr) ? tp : buf->start_ptr;
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
	int ret, tmplen, limit;
	struct sk_buff *tx_skb = NULL;
	unsigned short frame_len;
	unsigned char *tp = NULL; // tmp pointer
	struct pktdev_buf *ring = &pdev->txring[cpu];

	limit = XMIT_BUDGET;

tx_loop:

	if ((ring->read_ptr == ring->write_ptr) || (--limit < 0))
		goto tx_end;

	tp = ring->read_ptr;

	frame_len = pktdev_get_framelen(tp);
	if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
		pr_info("data size error: %X\n", (int)frame_len);
		BUF_INFO(pdev->txring[cpu]);
		goto tx_err;
	}

	tp += PKTDEV_HDR_SZ;
	if (tp >= ring->end_ptr)
		tp -= (ring->end_ptr - ring->start_ptr);

	// alloc skb
	tx_skb = netdev_alloc_skb(pdev->device, frame_len);
	if (likely(tx_skb)) {
		tx_skb->dev = pdev->device;
		tx_skb->queue_mapping = pktdev_pick_tx_queue(cpu, pdev->device);

		// fill packet
		skb_put(tx_skb, frame_len);
		if ((tp + frame_len) >= ring->end_ptr) {
			tmplen = ring->end_ptr - tp;
			memcpy(tx_skb->data, tp, tmplen);
			memcpy(tx_skb->data + tmplen, ring->start_ptr, (frame_len - tmplen));
		} else {
			memcpy(tx_skb->data, tp, frame_len);
		}

		// sending
		ret = pktdev_direct_xmit(tx_skb, cpu);
		if (ret) {
			if (ret == NETDEV_TX_BUSY) {
				//pr_info( "fail pktdev_direct_xmit=%d\n", ret );
				goto tx_fail;
			}
			// todo: check other return code
		}

		tp += frame_len;
		if (tp >= ring->end_ptr)
			tp -= (ring->end_ptr - ring->start_ptr);

		pdev->txring[cpu].read_ptr = aligened(tp, ring);
	}

tx_fail:
	//pr_info("kthread: tx_fail\n");
	goto tx_loop;

tx_err:
	pr_info("kthread: tx_err\n");
	ring->read_ptr = ring->start_ptr;
	ring->write_ptr = ring->start_ptr;

tx_end:
	return;
}

/* simple hash generator :todo */
static unsigned int ii = 0;
static inline int pktdev_get_hash(unsigned char *pkt_ptr)
{
	return (ii++ % tx_cpus);
}

static ssize_t pktdev_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	//int has_fragment_data = 0;
	unsigned int len, tmplen, ring_no; //, fragment_len;
	unsigned short frame_len;
//static unsigned char fragment[MAX_PKT_SZ];
	unsigned char *tp = NULL; // tmp pointer
	struct pktdev_buf *ring = NULL;

	func_enter();

	// for debug
	if (unlikely((count >= PKT_BUF_SZ) || (count < MIN_PKT_SZ)))
		return -ENOSPC;

	pdev->txbuf.write_ptr = pdev->txbuf.start_ptr;
	pdev->txbuf.read_ptr = pdev->txbuf.start_ptr;

#if 0
	// fragment data
	if (has_fragment_data) {
		memcpy(pdev->txbuf.write_ptr, fragment, fragment_len);
		pdev->txbuf.write_ptr += fragment_len;
		has_fragment_data = 0;
	}
#endif

	if (copy_from_user(pdev->txbuf.write_ptr, buf, count)) {
		pr_info( "copy_from_user failed.\n" );
		return -EFAULT;
	}

	while (likely(count != (pdev->txbuf.read_ptr - pdev->txbuf.start_ptr))) {
		frame_len = pktdev_get_framelen(pdev->txbuf.read_ptr);
		if (unlikely((frame_len > MAX_PKT_SZ) || (frame_len < MIN_PKT_SZ))) {
			pr_info("data size error: %X\n", (int)frame_len);
			BUF_INFO(pdev->txbuf);
			return -EFAULT;
		}

		len = PKTDEV_HDR_SZ + frame_len;
#if 0
		// copy fragment data to tmp buf
		fragment_len = count - (pdev->txbuf.read_ptr - pdev->txbuf.start_ptr);
		if (len > fragment_len) {
			has_fragment_data = 1;
			memcpy(fragment, pdev->txbuf.read_ptr, fragment_len);
			goto copy_end;
		}
#endif

		// txqueue selecter
		ring_no = pktdev_get_hash(pdev->txbuf.start_ptr); //pdev->num_cpus;
		ring = &pdev->txring[ring_no];

		tp = ring->write_ptr;

		// txbuf to txring
		if (likely(get_free_space_size(ring) > RING_THRESHOLD)) {
			// when overwriting
			if (unlikely((tp + len) >= ring->end_ptr)) {
				tmplen = ring->end_ptr - tp;
				memcpy(tp, pdev->txbuf.read_ptr, tmplen);
				memcpy(ring->start_ptr, (pdev->txbuf.read_ptr + tmplen),
					(len - tmplen));
				tp = ring->start_ptr + (len - tmplen);
			} else {
				memcpy(tp, pdev->txbuf.read_ptr, len);
				tp += len;
			}
			pdev->txbuf.read_ptr += len;

			// update ring write pointer with memory alignment
			pdev->txring[ring_no].write_ptr = aligened(tp, ring);
		} else {
			// return when a ring buffer reached the max size
			break;
		}
	}

//copy_end:
	return (pdev->txbuf.read_ptr - pdev->txbuf.start_ptr);
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
				get_free_space_size(&pdev->txring[0]),
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

static void pktdev_free(void)
{
	struct pktdev_thread *t, *n;

	/* free rx ring buffer */
	if (pdev->rxbuf.start_ptr) {
		vfree(pdev->rxbuf.start_ptr);
		pdev->rxbuf.start_ptr = NULL;
	}

	/* free tx ring buffers */
	if (pdev->txbuf.start_ptr) {
		kfree(pdev->txbuf.start_ptr);
		pdev->txbuf.start_ptr = NULL;
	}

	list_for_each_entry_safe(t, n, &pdev->pktdev_threads.list, list) {
		if (pdev->txring[t->cpu].start_ptr) {
			vfree(pdev->txring[t->cpu].start_ptr);
			pdev->txring[t->cpu].start_ptr = NULL;
		}

		pr_info("there is pktdev_cleanup(): cpu=%d\n", t->cpu);
		kthread_stop(t->tsk);
		list_del(&t->list);
		kfree(t);
	}

	if (pdev->txbuf.start_ptr) {
		kfree(pdev->txbuf.start_ptr);
		pdev->txbuf.start_ptr = NULL;
	}

	if (pdev->txring) {
		kfree(pdev->txring);
		pdev->txring = NULL;
	}

	if (pdev) {
		kfree(pdev);
		pdev = NULL;
	}
}

static int __init pktdev_init(void)
{
	int ret = 0, cpu;
	static char name[16];
	struct pktdev_thread *t;

	pr_info("%s\n", __func__);

	if (tx_cpus > nr_cpu_ids) {
		pr_info("tx_cpus:%d > nr_cpu_ids:%d\n", tx_cpus, nr_cpu_ids);
		ret = -1;
		goto error;
	}

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

	/* txring size from module parameter */
	pdev->txring_size = txring_size * 1024 * 1024;
	pr_info("pdev->txring_size: %d\n", pdev->txring_size);

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

		if (pdev->num_cpus == tx_cpus)
			break;
	}

	/* Set receive buffer */
	if ((pdev->rxbuf.start_ptr = vmalloc(pdev->txring_size)) == 0) {
		pr_info("fail to vmalloc\n");
		ret = -1;
		goto error;
	}
	pdev->rxbuf.end_ptr   = pdev->rxbuf.start_ptr + pdev->txring_size - 1;
	pdev->rxbuf.write_ptr = pdev->rxbuf.start_ptr;
	pdev->rxbuf.read_ptr  = pdev->rxbuf.start_ptr;

	/* malloc transmitte buffer */
	if ((pdev->txbuf.start_ptr = kmalloc(PKT_BUF_SZ, GFP_KERNEL)) == 0) {
		pr_info("fail to kmalloc\n");
		ret = -1;
		goto error;
	}
	pdev->txbuf.end_ptr   = pdev->txbuf.start_ptr + PKT_BUF_SZ - 1;
	pdev->txbuf.write_ptr = pdev->txbuf.start_ptr;
	pdev->txbuf.read_ptr  = pdev->txbuf.start_ptr;

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
		if ((pdev->txring[cpu].start_ptr = vmalloc_node(pdev->txring_size,
				cpu_to_node(cpu))) == 0) {
			pr_info("fail to vmalloc: cpu=%d\n", cpu);
			return -ENOMEM;
		}
		pdev->txring[cpu].end_ptr   = pdev->txring[cpu].start_ptr + pdev->txring_size - 1;
		pdev->txring[cpu].write_ptr = pdev->txring[cpu].start_ptr;
		pdev->txring[cpu].read_ptr  = pdev->txring[cpu].start_ptr;

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

	pktdev_free();

	return ret;
}

static void __exit pktdev_cleanup(void)
{
	func_enter();

	misc_deregister(&pktdev_dev);

	/* rx */
	dev_remove_pack(&pktdev_pack);

	pktdev_free();
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
module_param(tx_cpus, int, S_IRUGO);
MODULE_PARM_DESC(tx_cpus, "number of kthreads for xmit");
module_param(txring_size, int, S_IRUGO);
MODULE_PARM_DESC(txring_size, "TX ring size on each xmit kthread (MB)");
