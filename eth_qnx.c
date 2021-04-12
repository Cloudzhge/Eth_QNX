#include stdio.h  
#include pcap.h  

#include arpainet.h 
#include pthread.h
#include time.h  



#include stdlib.h
#include stdio.h
#include sysstat.h
#include fcntl.h
#include systypes.h
#include sysioctl.h
#include arpainet.h
#include netbpf.h
#include netethertypes.h
#include netif_ether.h
#include unistd.h            close()
#include string.h            strcpy, memset(), and memcpy()
#include netdb.h             struct addrinfo
#include systypes.h         needed for socket(), uint8_t, uint16_t, uint32_t
#include netinetin.h        IPPROTO_ICMP, INET_ADDRSTRLEN
#include netinetip.h        struct ip and IP_MAXPACKET (which is 65535)
#include netinetip_icmp.h   struct icmp, ICMP_ECHO
#include arpainet.h         inet_pton() and inet_ntop()
#include sysioctl.h         macro ioctl is defined
#include netif.h            struct ifreq
#include errno.h             errno, perror()

#include eth_can.h
#define BUFSIZE 1514  
#define NET_NAME emac0
#define EM_LOG printf 
#define LEN     255
#define ETH_2F  0x22ff

uint8_t buf_send[LEN] = {0}; Tx buffer
long total = 0;
int bpf = 0;
const uint8_t myMacAddress[6] = {0x00, 0x0c, 0x29, 0x94, 0x1c, 0x42};
const uint8_t desMacAddress[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

pcap_t  pcap_receive_handle;  接收句柄
回调函数

void callback(unsigned char argument, const struct pcap_pkthdr packet_heaher, const unsigned char packet_content)
{
	unsigned char mac_string;                
	struct ether_header ethernet_protocol;
	unsigned short ethernet_type;           以太网类型  
	printf(----------------------------------------------------n);
	printf(%sn, ctime((time_t )&(packet_heaher-ts.tv_sec))); 转换时间  
	ethernet_protocol = (struct ether_header )packet_content;
 
	mac_string = (unsigned char )ethernet_protocol-ether_shost;获取源mac地址  
	printf(Mac Source Address is %02x%02x%02x%02x%02x%02xn, (mac_string + 0), (mac_string + 1), (mac_string + 2), (mac_string + 3), (mac_string + 4), (mac_string + 5));
	mac_string = (unsigned char )ethernet_protocol-ether_dhost;获取目的mac  
	printf(Mac Destination Address is %02x%02x%02x%02x%02x%02xn, (mac_string + 0), (mac_string + 1), (mac_string + 2), (mac_string + 3), (mac_string + 4), (mac_string + 5));
 
	ethernet_type = ntohs(ethernet_protocol-ether_type);获得以太网的类型  
	printf(Ethernet type is %04xn, ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800printf(The network layer is IP protocoln); break;ip  
	case 0x0806printf(The network layer is ARP protocoln); break;arp  
	case 0x0835printf(The network layer is RARP protocoln); break;rarp  
  case 0x22ffprintf(received success!n);break; 22ff
	defaultbreak;
	}
	printf(packnumber %dn,total++);
}
 
void Eth_init()
{
   char error_content[100];
   char Netcardname[] = vp0;
    rx handler
   pcap_receive_handle = pcap_open_live(Netcardname, BUFSIZE, 1, 1, error_content);socket
   
   char bpfname[16] = {devbpf0};
     opening autocloning BFP device 
    bpf = open(bpfname, O_RDWR);
    int i = 0;
    if (bpf  0){
         no autocloning BPF found fall back to iteration 
        for(i=0; i128; i++){
            snprintf(bpfname, sizeof(bpfname), devbpf%d, i);
            bpf = open(bpfname, O_RDWR);
 
            if(bpf != -1)
                break;
        }
        if(bpf  0){
            printf(Error could not open any devbpf device.n);
        }
    }  
    printf(Opened BPF device %sn, bpfname);
    
     binding with real interface 
    const char ifname = emac0;
    struct ifreq iface;
    strncpy(iface.ifr_name, ifname, sizeof(ifname));
    if( ioctl(bpf, BIOCSETIF, &iface)  0){
        printf(Could not bind %s to BPFn, ifname);
    }
    printf(Associated with %sn, ifname);
 
     set immediate returns on packet arrived instead of when buffer full 
    int setimmediate = 1;
    if( ioctl(bpf, BIOCIMMEDIATE, &setimmediate) == -1){
        printf(Could set IO immediate);
    }
     set promiscuous mode    
    int promiscuous = 1;
    if( ioctl(bpf, BIOCPROMISC, &promiscuous) == -1){
        printf(Could get disable BIOCPROMISC);
    }
}
 
void Rx_Eth(u_char Rx_data,int length)
{
      struct pcap_pkthdr packet;
		  const u_char  pktStr = pcap_next(pcap_receive_handle, &packet);
		  if(pktStr)
		  {
			  if(pktStr[12]==0x22 && pktStr[13]==0xff)
			  {
			  	EM_LOG(captured!n);
				  EM_LOG(%dn,pktStr[16]);	
			  }
		  }	
}

void Tx_Eth(uint8_t Tx_data,int length)
{
  int offset = 0;
  int size = 6;
  int ret;
 	000c29941c42
	dst mac
	memcpy(buf_send,desMacAddress,sizeof(desMacAddress));
	offset += sizeof(desMacAddress);
	src mac
	memcpy(buf_send+offset,myMacAddress,sizeof(myMacAddress));
	offset += sizeof(myMacAddress);
	packet protocl	
	buf_send[offset] = 0x22;
	offset += 1;
	buf_send[offset] = 0xff;
	offset += 1;
	buf_send[offset] = 0x8F;
	offset += 1;
	buf_send[offset] = 0x8F;
	offset += 1;
  memcpy(buf_send+offset,Tx_data,length);
	offset+=length;
 
  ret = write(bpf, buf_send, offset);
 	if (ret = 0)
	{
		perror(send failed);
	}
}

void TX_thread(void args)
{
  uint8_t buf_t[200] = {0};
  while(1)
  {
    Rx_Eth(buf_t,100);
  }
}

int main(int argc, char argv[])
{


  Eth_init();
  pthread_t t1;
  thread_create(&t1,NULL,TX_thread,NULL);
  u_char buf_t[200] = {0};
  uint8_t testsemd[2] = {1,2};
  while(1)
  {
    Tx_Eth(testsemd,2);
  }

	pcap_close(pcap_receive_handle);
	return 0;
}