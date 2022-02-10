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
#include	<netinet/udp.h>
#include	<netinet/tcp.h>
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

int tuple_check_to_wan(struct iphdr *iphdr,u_char *l3_start,struct nat_table_element *ele){
    if(iphdr->saddr!=ele->loc_tpl->src_addr){
        return 0;
    }
    if(iphdr->daddr!=ele->loc_tpl->dst_addr){
        return 0;
    }
    if(iphdr->protocol!=ele->loc_tpl->protocol){
        return 0;
    }
    if(iphdr->protocol==IPPROTO_TCP){
        struct tcphdr *th=(struct tcphdr *)l3_start;
        if(th->source!=ele->loc_tpl->src_port){
            return 0;
        }
        else if(th->dest!=ele->loc_tpl->dst_port){
            return 0;
        }
    }
    else if(iphdr->protocol==IPPROTO_UDP){
        struct udphdr *uh=(struct udphdr *)l3_start;
        if(uh->uh_sport!=ele->loc_tpl->src_port){
            return 0;
        }
        else if(uh->uh_dport!=ele->loc_tpl->dst_port){
            return 0;
        }
    }
    return 1;
}

int set_header_to_lan(struct iphdr *iphdr,u_char *l3_start,struct nat_table_element *ele){
    if(iphdr->saddr!=ele->glo_tpl->dst_addr){
        return 0;
    }
    //アドレスの逆はAnalyze関数で弾いてる
    if(iphdr->protocol!=ele->glo_tpl->protocol){
        return 0;
    }
    if(iphdr->protocol==IPPROTO_TCP){
        struct tcphdr *th=(struct tcphdr *)l3_start;
        if(th->source!=ele->glo_tpl->dst_port){
            return 0;
        }
        else if(th->dest!=ele->glo_tpl->src_port){//gloのsrcはプログラムで割り振るやつ
            return 0;
        }
        else{
            th->dest=ele->loc_tpl->src_port;
        }
    }
    else if(iphdr->protocol==IPPROTO_UDP){
        struct udphdr *uh=(struct udphdr *)l3_start;
        if(uh->uh_sport!=ele->glo_tpl->dst_port){
            return 0;
        }
        else if(uh->uh_dport!=ele->glo_tpl->src_port){//gloのsrcはプログラムで割り振るやつ
            return 0;
        }
        else{
            uh->uh_dport=ele->loc_tpl->src_port;
        }
    }
    iphdr->daddr=ele->loc_tpl->src_addr;
    return 1;

}

int wan_to_lan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table){
    int i=0;
    for(i=0;i<table->num;i++){
        if(set_header_to_lan(iphdr,l3_start,(table->table_ele+i))==1){
            return 1;
        }
    }
    printf("no table element to match\n");
    return(-1);
}

int lan_to_wan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table){
    int i=0;
    for(i=0;i<table->num;i++){
        if(tuple_check_to_wan(iphdr,l3_start,(table->table_ele+i))==1){
            //iphdrへのセットもここでやる
            return 1;
        }
    }
    //port割り振ってNATテーブルに要素追加する
    return 1;
}