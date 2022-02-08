#define MAX_DEV_NUM 20
#define MAX_DEVNAME_LEN 30
#define WAN_DEV_ID	0
#define WAN_DEV_NUM	1

typedef struct	{
	char	*Device1;
	char	*Device2;
	int     DebugOut;
	char	*NextRouter;
}PARAM;

typedef struct	{
	char	*Device[MAX_DEV_NUM];
	int		num_of_dev;
	int     DebugOut;
}PARAM_new;

void init_PARAM_new(PARAM_new *par);
//void json_read(PARAM_new *pa,json_t *json_object,json_error_t *jerror,struct node *root);

