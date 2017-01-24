#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/seg6.h>

#define AUTHOR "SR/VNF Connector"
#define DESC "SR/VNF Connector"

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("GPL");

static struct nf_hook_ops sr_ops_pre;
static struct net_device* serv_dev;

static struct ipv6_sr_hdr sr1;
static struct ipv6_sr_hdr sr2;

static struct ipv6hdr outer_iph1;
static struct ipv6hdr outer_iph2;

unsigned char s_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
unsigned char d_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22};

uint8_t service_IP[16];
const char* service_IP_str = "BBBB::2";

bool do_recap_1;
bool do_recap_2;

/* rencap function */
int rencap(struct sk_buff* skb, struct ipv6_sr_hdr* sr_h)
{
    int new_room_size;
    new_room_size = sizeof(struct ipv6hdr) + ((sr_h->hdrlen * 8) + 8);

    if (pskb_expand_head(skb, new_room_size, 0, GFP_ATOMIC)) {
	printk(KERN_INFO "SR/VNF Connector: pskb_expand_head fail!!! NF_DROP!!! \n");
	return NF_DROP;
    }

    skb_put(skb, new_room_size);
    memmove(skb->data + new_room_size, skb->data, skb->len - new_room_size);

    return 0;
}

/* trim function */
struct sk_buff* trim_srh(struct sk_buff* skb, struct ipv6_sr_hdr* sr_h)
{

    int trim_size;
    trim_size = sizeof(struct ipv6hdr) + ((sr_h->hdrlen * 8) + 8);

    printk(KERN_INFO "trim!!!!!\n");

    memmove(skb->data, skb->data + trim_size, skb->len - trim_size);
    __pskb_trim(skb, skb->len - trim_size);

    return skb;
}

/* send_to_VNF function */

int send_to_vnf(struct sk_buff* skb)
{

    dev_hard_header(skb, skb->dev, ETH_P_IPV6, d_mac, s_mac, skb->len);

    skb->dev = serv_dev;

    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS) {
	printk(KERN_INFO "dev_queue_xmit error \n");
	return 1;
    } else {
	printk(KERN_INFO "dev_queue_xmit ok!! \n");
	return 0;
    }
}

/* Pre-Routing function */

unsigned int sr_pre_routing(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{

    struct ipv6hdr* iph = (struct ipv6hdr*)skb_network_header(skb);
    struct ipv6_sr_hdr* srh;
    struct in6_addr* next_hop = NULL;

    if (strncmp("eth1", skb->dev->name, 4) == 0 && iph->nexthdr == 43 && *iph->daddr.s6_addr == *service_IP) {

	printk(KERN_INFO "ifname      = %s \n", skb->dev->name);
	printk(KERN_INFO "payload_len = %u \n", ntohs(iph->payload_len));
	printk(KERN_INFO "hop limit   = %u \n", iph->hop_limit);
	printk(KERN_INFO "saddr       = %pI6c \n", iph->saddr.s6_addr);
	printk(KERN_INFO "daddr       = %pI6c \n", iph->daddr.s6_addr);

	srh = (struct ipv6_sr_hdr*)skb_transport_header(skb);

	printk(KERN_INFO "nexthdr       =  %u \n", srh->nexthdr);
	printk(KERN_INFO "hdrlen        =  %u \n", srh->hdrlen);
	printk(KERN_INFO "type          =  %u \n", srh->type);
	printk(KERN_INFO "segments_left =  %u \n", srh->segments_left);
	printk(KERN_INFO "first_segment =  %u \n", srh->first_segment);

	if (srh->segments_left > 0) {
	    srh->segments_left--;
	    next_hop = srh->segments + srh->segments_left;
	    iph->daddr = *next_hop;
	    do_recap_1 = true;
	} else {
	    do_recap_1 = false;
	}

	memcpy(&outer_iph1, iph, sizeof(outer_iph1));
	memcpy(&sr1, srh, sizeof(sr1));

	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	trim_srh(skb, srh);

	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	if (send_to_vnf(skb) != 0) {
	    printk(KERN_INFO "packet sent to the VNF !!!!! ok  \n");
	} else {
	    printk(KERN_INFO "packet sent to the VNF !!!!! failed  \n");
	}

	return NF_STOLEN;

    } else if (strncmp("veth0-nvf-node", skb->dev->name, 14) == 0 && *iph->saddr.s6_addr == *outer_iph1.saddr.s6_addr) {

	printk(KERN_INFO "This packet is belongs to the flow form client to server \n");

	if (do_recap_1 == true) {

	    printk(KERN_INFO "nexthdr       =  %u \n", sr1.nexthdr);
	    printk(KERN_INFO "hdrlen        =  %u \n", sr1.hdrlen);
	    printk(KERN_INFO "type          =  %u \n", sr1.type);
	    printk(KERN_INFO "segments_left =  %u \n", sr1.segments_left);
	    printk(KERN_INFO "first_segment =  %u \n", sr1.first_segment);

	    rencap(skb, &sr1);
	    memcpy(skb->data, &outer_iph1, sizeof(struct ipv6hdr));
	    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	    memcpy(skb->data + sizeof(struct ipv6hdr), &sr1, (sr1.hdrlen * 8) + 8);
	}

	return NF_ACCEPT;

    } else if (strncmp("eth2", skb->dev->name, 4) == 0 && iph->nexthdr == 43 && *iph->daddr.s6_addr == *service_IP) {

	printk(KERN_INFO "mark        = %d \n", skb->mark);
	printk(KERN_INFO "ifname      = %s \n", skb->dev->name);
	printk(KERN_INFO "payload_len = %u \n", ntohs(iph->payload_len));
	printk(KERN_INFO "hop limit   = %u \n", iph->hop_limit);
	printk(KERN_INFO "saddr       = %pI6c \n", iph->saddr.s6_addr);
	printk(KERN_INFO "daddr       = %pI6c \n", iph->daddr.s6_addr);

	srh = (struct ipv6_sr_hdr*)skb_transport_header(skb);

	printk(KERN_INFO "nexthdr       =  %u \n", srh->nexthdr);
	printk(KERN_INFO "hdrlen        =  %u \n", srh->hdrlen);
	printk(KERN_INFO "type          =  %u \n", srh->type);
	printk(KERN_INFO "segments_left =  %u \n", srh->segments_left);
	printk(KERN_INFO "first_segment =  %u \n", srh->first_segment);

	if (srh->segments_left > 0) {
	    srh->segments_left--;
	    next_hop = srh->segments + srh->segments_left;
	    iph->daddr = *next_hop;
	    do_recap_2 = true;
	} else {
	    do_recap_2 = false;
	}

	memcpy(&outer_iph2, iph, sizeof(outer_iph2));
	memcpy(&sr2, srh, sizeof(sr2));

	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	trim_srh(skb, srh);

	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	if (send_to_vnf(skb) != 0) {
	    printk(KERN_INFO "packet sent to the VNF !!!!! ok  \n");
	} else {
	    printk(KERN_INFO "packet sent to the VNF !!!!! failed  \n");
	}

	return NF_STOLEN;

    } else if (strncmp("veth0-nvf-node", skb->dev->name, 14) == 0 && *iph->saddr.s6_addr == *outer_iph2.saddr.s6_addr) {

	printk(KERN_INFO "This packet is belongs to the flow form server to client  \n");

	if (do_recap_2 == true) {

	    printk(KERN_INFO "nexthdr       =  %u \n", sr2.nexthdr);
	    printk(KERN_INFO "hdrlen        =  %u \n", sr2.hdrlen);
	    printk(KERN_INFO "type          =  %u \n", sr2.type);
	    printk(KERN_INFO "segments_left =  %u \n", sr2.segments_left);
	    printk(KERN_INFO "first_segment =  %u \n", sr2.first_segment);

	    rencap(skb, &sr2);
	    memcpy(skb->data, &outer_iph2, sizeof(struct ipv6hdr));
	    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	    memcpy(skb->data + sizeof(struct ipv6hdr), &sr2, (sr2.hdrlen * 8) + 8);
	}
	return NF_ACCEPT;

    } else {

	return NF_ACCEPT; /* Accept ALL Packets */
    }
}

/* Initialization function */

int sr_vnf_init(void)
{
    int ret = 0;

    printk(KERN_ALERT "Loading module %s...\n", DESC);

    if (in6_pton(service_IP_str, strlen(service_IP_str), service_IP, '\0', NULL) == 1) {
	printk(KERN_INFO " IP Ok \n");
    } else {
	printk(KERN_INFO "IP NO \n");
    }

    serv_dev = dev_get_by_name(&init_net, "veth0-nvf-node");

    // Register the filtering function
    sr_ops_pre.hook = sr_pre_routing;
    sr_ops_pre.pf = PF_INET6;
    sr_ops_pre.hooknum = NF_INET_PRE_ROUTING;
    sr_ops_pre.priority = NF_IP_PRI_LAST;

    ret = nf_register_hook(&sr_ops_pre); /* register NF_IP_PRE_ROUTING hook */
    
	if (ret < 0) {
	printk(KERN_INFO "Sorry, registering SR/VNF connector failed with %d \n", ret);
	return ret;
    }
    printk(KERN_INFO "SR/VNF connector registered (%d)!\n", ret);

    return 0;
}

/* Exit function */

void sr_vnf_exit(void)
{

    printk(KERN_ALERT "Unloading module %s...\n", DESC);
    
	/* Unregister the filtering function*/
    nf_unregister_hook(&sr_ops_pre);
    memset(&sr_ops_pre, 0, sizeof(struct nf_hook_ops));
    printk(KERN_INFO "SR/VNF connector released.\n");
}

module_init(sr_vnf_init);
module_exit(sr_vnf_exit);

