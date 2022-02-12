IP2MAC *Ip2MacSearch(int deviceNo,in_addr_t addr,unsigned char *hwaddr);
IP2MAC *Ip2Mac(int deviceNo,in_addr_t addr,unsigned char *hwaddr);
uint16_t tcp_checksum(u_char *ptr,struct iphdr *iphdr);
int BufferSendOne(int deviceNo,IP2MAC *ip2mac);
int AppendSendReqData(int deviceNo,int ip2macNo);
int GetSendReqData(int *deviceNo,int *ip2macNo);
int BufferSend();
