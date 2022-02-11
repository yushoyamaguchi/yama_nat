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

void init_nat_table(struct nat_table *table){
    int i=0;
    for(i=0;i<MAX_TABLE_SIZE;i++){
        table->used_port[i]=0;
    }
    table->last_gave_port=0;
}

void init_nat_table_element(struct nat_table_element *ele){
    ele->prev=NULL;
    ele->next=NULL;
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
    struct nat_table_element *search;
    search=table->start;
    do{
        if(set_header_to_lan(iphdr,l3_start,search)==1){
            return 1;
        }
    }while(search!=table->end);
    printf("no table element to match\n");
    return(-1);
}

void cp_from_iphdr(struct iphdr *iphdr,struct nat_table_element *ele){
    ele->loc_tpl->dst_addr=iphdr->daddr;
    ele->glo_tpl->dst_addr=iphdr->daddr;
    ele->loc_tpl->src_addr=iphdr->saddr;
    ele->loc_tpl->protocol=iphdr->protocol;
    ele->glo_tpl->protocol=iphdr->protocol;
}

void cp_from_l3hdr(struct iphdr *iphdr,u_char *l3_start,struct nat_table_element *ele){
    if(iphdr->protocol==IPPROTO_TCP){
        struct tcphdr *th=(struct tcphdr *)l3_start;
        ele->loc_tpl->src_port=th->source;
        ele->loc_tpl->dst_port=th->dest;
        ele->glo_tpl->dst_port=th->dest;
    }
    else if(iphdr->protocol==IPPROTO_UDP){
        struct udphdr *uh=(struct udphdr *)l3_start;
        ele->loc_tpl->src_port=uh->uh_sport;
        ele->loc_tpl->dst_port=uh->uh_dport;
        ele->glo_tpl->dst_port=uh->uh_dport;
    }
}

int insert_nat_table(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table,DEVICE *dev){
    struct nat_table_element *new_ele;
    if(table->start==NULL){
        table->start=malloc(sizeof(struct nat_table_element));
        if(table->start==NULL){
            printf(MEM_ERR);
            return(-1);
        }
        new_ele=table->start;
        init_nat_table_element(new_ele);
        table->end=new_ele;
    }
    else{
        table->end->next=malloc(sizeof(struct nat_table_element));
        if(table->end->next==NULL){
            printf(MEM_ERR);
            return(-1);
        }
        new_ele=table->end->next;
        init_nat_table_element(new_ele);
        table->end->next=new_ele;
        new_ele->prev=table->end;
        table->end=new_ele;
    }
    new_ele->loc_tpl=malloc(sizeof(struct five_tuple));
    if(new_ele->loc_tpl==NULL){
        printf(MEM_ERR);
        return(-1);
    }
    init_five_tuple(new_ele->loc_tpl);
    new_ele->glo_tpl=malloc(sizeof(struct five_tuple));
    if(new_ele->glo_tpl==NULL){
        printf(MEM_ERR);
        return(-1);
    }
    init_five_tuple(new_ele->glo_tpl);
    cp_from_iphdr(iphdr,new_ele);
    cp_from_l3hdr(iphdr,l3_start,new_ele);
    new_ele->glo_tpl->src_addr=dev->addr.s_addr;
    int glo_sport=table->last_gave_port+1;
    int i=0;
    for(i=0;i<MAX_TABLE_SIZE;i++){
        if(table->used_port[glo_sport%MAX_TABLE_SIZE]){
            break;
        }
        glo_sport++;
    }
    table->used_port[glo_sport%MAX_TABLE_SIZE]=1;
    glo_sport=glo_sport%MAX_TABLE_SIZE+PORT_START;
    new_ele->glo_tpl->src_port=glo_sport;
    return 1;
}

void del_element(struct nat_table_element *ele){
    free(ele->loc_tpl);
    free(ele->glo_tpl);

}

void del_nat_table(struct nat_table *table){
    struct nat_table_element *del=table->start;
    if(del==NULL){
        return;
    }
    int i=0;
    struct nat_table_element *del2=table->start->next;
    while(del!=NULL){
        i++;
        del2=del->next;
        del_element(del);
        free(del);
        del=del2;
    }
}

int lan_to_wan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table,DEVICE *dev){
    int found=0;
    struct nat_table_element *search;
    search=table->start;
    if(search!=NULL){
        do{
            if(tuple_check_to_wan(iphdr,l3_start,search)==1){
                found=1;
                break;
            }
            search=search->next;
        }while(search!=NULL);
    }
    if(!found){
        //port割り振ってNATテーブルに要素追加
        insert_nat_table(iphdr,l3_start,table,dev);
        //searchに新しいテーブルの要素をセット
        search=table->end;
    }
    //srcに自分の情報をセット
    iphdr->saddr=search->glo_tpl->src_addr;
    if(iphdr->protocol==IPPROTO_TCP){
        struct tcphdr *th=(struct tcphdr *)l3_start;
        th->source=search->glo_tpl->src_port;
    }
    else if(iphdr->protocol==IPPROTO_UDP){
        struct udphdr *uh=(struct udphdr *)l3_start;
        uh->uh_sport=search->glo_tpl->src_port;
    }
    return 1;
}