/*
 *=============================================================================
 *
 *		File Name:	ipt_queuematch.c
 *
 *	  Description:	match the queue number  of the special multi-queue network 
 *	                card.  
 *
 *		  Version:	1.0
 *		  Created:  22/8/2016
 *		 Compiler:  gcc
 *
 *    	   Author:  XuHongping 
 *    	   E-Mail:  mohists@hotmail.com 
 *   	  Company:  BLUDON
 *=============================================================================
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_queuematch.h>

MODULE_AUTHOR("xuhongping");
MODULE_DESCRIPTION("iptables mutiple queue network device  match module.");
MODULE_LICENSE("GPL");

static bool match(const struct sk_buff *skb, struct xt_action_param *par)
{
        const struct ipt_queuematch_info *info = par->matchinfo;
        __u8 queueid = skb->queue_mapping;

		if (queueid == info->queueid)
			return 1;
        else
			return 0;
}

static struct xt_match queue_match = {
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

