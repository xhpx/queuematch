/*
 *=============================================================================
 *
 *		File Name:	libipt_queuematch.c
 *
 *	  Description:	match the queue number  of the special multi-queue network 
 *	                card .  
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

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <iptables.h>
#include "ipt_queuematch.h"

static void help(void)
{
	printf(
			"queuematch %s options:\n"
			"--queueid        ring id of network device\n"
			"\nExamples:\n"
			" iptables -A INPUT -m queuematch --queueid  1 -j NFQUEUE --queue-num 1 \n"
			, QUEUEMATCH_VERSION);
}

static struct option opts[] = {
	{ "queueid", 1, NULL, '1' },
	{0}
};

static void parse_pkts(const char* s,struct ipt_queuematch_info *info)
{
	char* buff;

	buff = strdup(s);

	info->queueid  = strtol(buff,NULL,0);

	free(buff);
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
		const void *entry,
		struct ipt_entry_match **match)
{
	struct ipt_queuematch_info *info = (struct ipt_queuematch_info *)(*match)->data;
	switch(c){
		case '1':
			if (*flags)
				xtables_error(PARAMETER_PROBLEM,
						"queueid `--queueid' may only be "
						"specified once");
			parse_pkts(argv[optind-1], info);
			*flags = 1;
			break;
		default:
			return 0;
	}
	return 1;
}

static void final_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
				"\nqueuematch-parameter problem: for queueid usage type: iptables -m queuematch--help\n");
}


static void __print(struct ipt_queuematch_info * info){
	printf("packet from queue[%d]\n", info->queueid);
}

static void print(const void *ip, const struct ipt_entry_match *match, int numeric)
{
	__print((struct ipt_queuematch_info*)match->data);

}

static struct xtables_match queuematch=
{
	.next           = NULL,
	.name           = "queuematch",
	.version        = XTABLES_VERSION,
	.size           = XT_ALIGN(sizeof(struct ipt_queuematch_info)),
	.userspacesize  = XT_ALIGN(sizeof(struct ipt_queuematch_info)),
	.help           = &help,
	.parse          = &parse,
	.final_check    = &final_check,
	.print          = &print,
	.extra_opts     = opts
};

void _init(void)
{

	xtables_register_match(&queuematch);
}

