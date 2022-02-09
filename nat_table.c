#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<bits/types.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<pthread.h>
#include	<jansson.h>
#include	"netutil.h"
#include	"base.h"
#include	"ip2mac.h"
#include	"sendBuf.h"
#include	"json_config.h"
#include	"tree.h"
#include	"nat_table.h"



void init_nat_table_element(struct nat_table_element *ele){
    ele->id=0;
    ele->loc_tpl=NULL;
    ele->glo_tpl=NULL;
    ele->protocol=0;
}

void init_five_tuple(struct five_tuple *tpl){
    tpl->src_addr=0;
    tpl->src_port=0;
    tpl->dst_addr=0;
    tpl->dst_port=0;
    tpl->protocol=0;
}

void wan_to_lan(struct iphdr *iphdr,u_char *L3_packet_start,struct five_tuple *ret,struct nat_table *table){

}