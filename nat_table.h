
#define MAX_TABLE_SIZE  10000
#define PORT_START 50000

#define	TCP_NAT_TIMEOUT_SEC	10
#define	UDP_NAT_TIMEOUT_SEC	10
#define	ICMP_NAT_TIMEOUT_SEC	10

struct nat_table{
    struct nat_table_element *start;
    struct nat_table_element *end;
    int     num;
    int     used_port[MAX_TABLE_SIZE];//+50,000して使う
    int     last_gave_port;
};

struct nat_table_element{
    struct  nat_table_element *prev;
    struct  nat_table_element *next;
    struct  five_tuple  *loc_tpl;
    struct  five_tuple  *glo_tpl;
    u_int8_t     protocol;
    time_t      last_time;
    int         is_tcp_estab;
};

struct five_tuple{
    u_int32_t   src_addr;
    u_int16_t   src_port;
    u_int32_t   dst_addr;
    u_int16_t   dst_port;
    u_int8_t    protocol;
};

void init_nat_table_element(struct nat_table_element *ele);

void init_five_tuple(struct five_tuple *tpl);

int wan_to_lan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table);

int lan_to_wan(struct iphdr *iphdr,u_char *l3_start,struct nat_table *table,DEVICE *dev);

void del_nat_table(struct nat_table *table);