struct nat_table{
    struct nat_table_element *table;
};

struct nat_table_element{
    struct  nat_table_element   *prev;
    struct  nat_table_element   *next;
    int     id;
    struct  five_tuple  *src_tpl;
    struct  five_tuple  *dst_tpl;
    int     protocol;
};

struct five_tuple{
    u_int32_t   src_addr;
    int         src_port;
    u_int32_t   dst_addr;
    int         dst_port;
    int         protocol;
};

void init_nat_table_element(struct nat_table_element *ele);

void init_five_tuple(struct five_tuple *tpl);