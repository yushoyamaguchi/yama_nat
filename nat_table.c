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
#include    <time.h>
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
    ele->last_time=0;
    ele->is_tcp_estab=0;
}

void init_five_tuple(struct five_tuple *tpl){
    tpl->src_addr=0;
    tpl->src_port=0;
    tpl->dst_addr=0;
    tpl->dst_port=0;
    tpl->protocol=0;
}

void free_element(struct nat_table_element *ele){
    free(ele->loc_tpl);
    free(ele->glo_tpl);
}

void del_nat_table_element(struct nat_table *table,struct nat_table_element *ele){
    struct nat_table_element *next=ele->next;
    struct nat_table_element *prev=ele->prev;
    if(next==NULL&&prev!=NULL){
        table->end=prev;
        prev->next=NULL;
    }
    else if(next!=NULL&&prev==NULL){
        table->start=next;
        next->prev=NULL;
    }
    else if(next!=NULL&&prev!=NULL){
        prev->next=next;
        next->prev=prev;
    }
    else if(next==NULL&&prev==NULL){
        table->start=NULL;
        table->end=NULL;
    }
    free_element(ele);
    free(ele);
}

int tuple_check_to_wan(struct iphdr *iphdr,u_char *l3_start,struct nat_table_element *ele,struct nat_table *table){
    time_t now;
    now=time(NULL);

    if(ele->loc_tpl->protocol==IPPROTO_TCP){
        if(now-ele->last_time>TCP_NAT_TIMEOUT_SEC){
            del_nat_table_element(table,ele);
            table->num--;
            printf("delete tcp\n");
            return 0;
        }
    }
    else if(ele->loc_tpl->protocol==IPPROTO_UDP){
        if(now-ele->last_time>UDP_NAT_TIMEOUT_SEC){
            del_nat_table_element(table,ele);
            table->num--;
            printf("delete udp\n");
            return 0;
        }
    }
    else if(ele->loc_tpl->protocol==IPPROTO_ICMP){
        if(now-ele->last_time>ICMP_NAT_TIMEOUT_SEC){
            del_nat_table_element(table,ele);
            table->num--;
            printf("delete icmp\n");
            return 0;
        }
    }
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
    else if(iphdr->protocol==IPPROTO_ICMP){
        struct icmphdr *ih=(struct icmphdr *)l3_start;
        if(ih->un.echo.id!=ele->loc_tpl->src_port){
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
    else if(iphdr->protocol==IPPROTO_ICMP){
        struct icmphdr *ih=(struct icmphdr *)l3_start;
        if(ih->un.echo.id!=ele->glo_tpl->src_port){
            return 0;
        }
    }
    iphdr->daddr=ele->loc_tpl->src_addr;
    return 1;

}

int wan_to_lan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table){
    struct nat_table_element *search;
    struct nat_table_element *search2;
    search=table->start;
    int rt;
    do{
        search2=search->next;
        rt=set_header_to_lan(iphdr,l3_start,search);
        if(rt==1){
            return 1;
        }
        search=search2;
    }while(search!=NULL);
    printf("no table element to match : to lan\n");
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
    else if(iphdr->protocol==IPPROTO_ICMP){
        struct icmphdr *ih=(struct icmphdr *)l3_start;
        ele->loc_tpl->src_port=ih->un.echo.id;
    }
}




int insert_nat_table(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table,DEVICE *dev){
    struct nat_table_element *new_ele;
    time_t now;
    table->num++;
    now=time(NULL);
    if(table->start==NULL){
        table->start=malloc(sizeof(struct nat_table_element));
        if(table->start==NULL){
            printf(MEM_ERR);
            return(-1);
        }
        new_ele=table->start;
        init_nat_table_element(new_ele);
        new_ele->last_time=now;        
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
        new_ele->last_time=now;
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
    printf("src addr=%x , id=%d , table_num=%d , protocol=%d : ",new_ele->loc_tpl->src_addr,new_ele->loc_tpl->src_port,table->num,new_ele->loc_tpl->protocol);
    new_ele->glo_tpl->src_addr=dev->addr.s_addr;
    int glo_sport=table->last_gave_port+1;
    int i=0;
    for(i=0;i<MAX_TABLE_SIZE;i++){
        if(!table->used_port[glo_sport%MAX_TABLE_SIZE]){
            break;
        }
        glo_sport++;
    }
    table->used_port[glo_sport%MAX_TABLE_SIZE]=1;
    glo_sport=glo_sport%MAX_TABLE_SIZE+PORT_START;
    new_ele->glo_tpl->src_port=glo_sport;
    if(iphdr->protocol==IPPROTO_ICMP){
        new_ele->glo_tpl->src_port=new_ele->loc_tpl->src_port;
    }
    printf("insert\n");
    return 1;
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
        free_element(del);
        free(del);
        del=del2;
    }
}

int lan_to_wan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table,DEVICE *dev){
    int found=0;
    struct nat_table_element *search;
    struct nat_table_element *search2;
    search=table->start;
    if(search!=NULL){
        do{
            search2=search->next;
            if(tuple_check_to_wan(iphdr,l3_start,search,table)==1){
                found=1;
                break;
            }
            search=search2;
        }while(search!=NULL);
    }
    if(!found){
        //port割り振ってNATテーブルに要素追加
        printf("not found in table : to wan\n");
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