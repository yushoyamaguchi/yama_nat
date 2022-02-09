struct nat_table{
    struct nat_table_element *table;
};

struct nat_table_element{
    int     id;
    struct  five_tuple  *loc_tpl;
    struct  five_tuple  *glo_tpl;
    u_int8_t     protocol;
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

void wan_to_lan(struct iphdr *iphdr,u_char *L3_packet_start,struct five_tuple *ret,struct nat_table *table);