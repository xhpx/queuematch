#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_queuematch.h>

MODULE_AUTHOR("xuhongping");
MODULE_DESCRIPTION("iptables mutiple queue network device  match module.");
MODULE_LICENSE("GPL");

static int
match(const struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo,
      int offset,
      unsigned int protoff,
      int *hotdrop)
{
        const struct ipt_queuematch *info = matchinfo;
        __u16 queueid = skb->queue_mapping;
		printk(KERN_INFO "*** match queueid: %d\n", queueid);

		if (queueid == info->queueid)
			return 1;
        else
			return 0;
}

static struct ipt_match queue_match = {
        .name           = "queuematch",
        .family          =AF_INET,
        .match          = match,
        .matchsize    = sizeof(struct ipt_queuematch_info),
        .destroy        = NULL,
        .me              = THIS_MODULE,
};

static int __init init(void)
{
    printk(KERN_INFO "queuematch module loading\n");
    return xt_register_match(&queue_match);
}

static void __exit fini(void)
{
    xt_unregister_match(&queue_match);
    printk(KERN_INFO "queuematch module unloaded\n");
}

module_init(init);
module_exit(fini);

