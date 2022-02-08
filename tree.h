#define INT_BIT_NUM 32
#define IPV4_ADDR_BIT_NUM 32

struct node  {
        struct node      *parent;
        struct node      *child[2];
        u_int32_t       daddr_subnet;
        u_int8_t        subnet_mask;
        u_int32_t       next_hop;
        u_int32_t       daddr_full;
        int             is_empty;
        int             is_root;
};

struct node *longest_match_by_daddr(u_int32_t daddr,struct node *root);

void init_tree_node(struct node *node);

void calc_subnet(struct node *node);


void node_insert(struct node *join_node, struct node *root);

void show_tree(struct node *root);

void tree_destruct(struct node *root);


