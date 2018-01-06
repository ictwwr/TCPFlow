#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<time.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<unistd.h>
#include "uthash.h"
#define STRSIZE 1024
#define SIZE_ETHERNET 14

/*Set the default values for parameters */
char * input;
char *output1="output.txt";
char * output2 ="output_summary.txt" ; 

typedef struct {
  char srcip[100];
  char srcport[100];
  char dstip[100];
  char dstport[100];
  char proto[100];
} tcpflow;

typedef struct {
  char srcip[100];
  char dstip[100];
} tf;

/*The structure of the TCP flow*/
typedef struct {
    tcpflow key;
    int totalbyte;
    int packetnum;
    int pktlen;
    UT_hash_handle hh;
} record;

/*Used to calculate the most send IP and receiving IP structure
  */
typedef struct {
    tf key1;
    int totalbyte1;
    int packetnum1;
    UT_hash_handle hh;
} srcdst;

typedef struct {
    char ip[100];  
    int totalbyte;
    int packetnum;
    int otherips;
    UT_hash_handle hh;
} src;

record *records = NULL;
srcdst *srcdsts = NULL;
src *srcs = NULL;
src *dsts = NULL;

/*The hash map structure of the TCP flow*/
typedef struct node_has_space *ptr_has_space;  
struct node_has_space    
{       
    int tbyte;
    int pnum;   
    int pktlen;
    tcpflow value;
    ptr_has_space next;    
}; 

/*The hash map structure of the srcip or dstip*/
typedef struct node_space *ptr_space;  
struct node_space    
{       
    char ip[100];
    int otherips;
    int tbyte;
    int pnum;   
    ptr_space next;    
}; 

void swap(int *a,int *b);
void init_heap(struct node_has_space heap[11],int n);
void init_heap_ip(struct node_space heap[11],int n);
void sift_down_by_byte(struct node_has_space heap[11], int i,int len);
void sift_down_by_pnum(struct node_has_space heap[11], int i,int len);
void sift_down_by_pktlen(struct node_has_space heap[11], int i,int len);
void sift_down_by_ip(struct node_space heap[11], int i,int len);
void solve_hash();
void solve_heap(struct node_has_space heap[11],struct node_has_space heap1[11],struct node_has_space heap2[11],record *s, record *tmp,int n);
void solve_heap_src(struct node_space heap[11],src *s, src *tmp,int n);
void solve_heap_dst(struct node_space heap[11],src *s, src *tmp,int n);
void build_min_heap_by_ip(struct node_space heap[],int len);
void build_min_heap_by_byte(struct node_has_space heap[],int len);
void build_min_heap_by_pnum(struct node_has_space heap[],int len);
void build_min_heap_by_pktlen(struct node_has_space heap[],int len);
static int parse_args(int argc, char **argv);
void summary(char *si,char *sp,char *di,char *dp,int slen,int len);
void sortput_by_byte(struct node_has_space heap[],int index[11],int n);
void sortput_by_ips(struct node_space heap[],int index[11],int n);
void sortput_by_pnum(struct node_has_space heap[],int index[11],int n);
void sortput_by_pktlen(struct node_has_space heap[],int index[11],int n);

int main(int argc,char **argv)
{
	int totalbyte=0,totalpacket=0,totalflow,totalflow1;
	char dp[15],sp[15],si[100],di[100];
	
	struct pcap_file_header *file_header;
	struct pcap_pkthdr *pkt_header;
	struct ether_header *eth_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int size_packet,size_ip,size_tcp,time,type,len;
	FILE *fp,*fp1,*fp2;
	char buf[STRSIZE],capture_time[STRSIZE],starttime[20],starttime1[20],endtime[STRSIZE];
	record *s, *tmp, *p;
	src *s1, *tmp1, *p1;
	u_char *packet=NULL;

	parse_args(argc,argv);
	if((fp=fopen(input,"r"))==NULL)
	{
		printf("Error:can not open input pcap file\n");
		exit(0);
	}
	if((fp1=fopen(output1,"w+"))==NULL)
	{
		printf("Error:can not open output file\n");
		exit(0);
	}
	if((fp2=fopen(output2,"w+"))==NULL)
	{
		printf("Error:can not open output file\n");
		exit(0);
	}
	file_header=(struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
	pkt_header=(struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

	//Save a 24-byte pcap file header data to file_header
	int read_size=fread(file_header,sizeof(char),24,fp);
	if(read_size!=24)
	{
		printf("cannot read pcap file header,invaild format\n");
		goto cleanup;
	}
	
	//Type records the link type of the data flow.1 represents Ethernet,101 represents RAW IP
	type=file_header->linktype;
	if((type!=1)&&(type!=101))
	{
		printf("Sorry,tcpflow_offline does not support this link type of data flow\n"); 
		return 0;
	}
	packet=(u_char *)malloc(file_header->snaplen *sizeof(char));
	
	
	while(!feof(fp))
	{
		
		memset(buf,0,sizeof(buf));
		memset(packet,0,sizeof(packet));
		
		//Read 16-byte packet headers 
		if(fread(buf,16,1,fp)!=1)
		{
			break;
		}
		
		//Caplen represents the length of the package in the pcap file 
		pkt_header->ts.tv_sec=*(bpf_u_int32 *)buf;
		pkt_header->caplen=*(bpf_u_int32*)(buf+8);
		pkt_header->len=*(bpf_u_int32*)(buf+12);
		time=pkt_header->ts.tv_sec;
		size_packet=pkt_header->caplen;
		len=pkt_header->len;

		//Convert the packet capture time to local time
		strftime(capture_time,sizeof(capture_time),"%Y-%m-%d %T",localtime(&(pkt_header->ts.tv_sec)));

		//Save the packet from the file to the packet 
		fread(packet,size_packet,1,fp);

		//The processing method of Ethernet 
		if(type==1)
		{
			eth_header=(struct ether_header *)packet;
			ip_header=(struct iphdr *)(packet+SIZE_ETHERNET);
			//Size_ip represents the length of the IP header
			size_ip=(ip_header->ihl)*4; 
		}
		//The processing method of RAW IP
		else
		{
			ip_header=(struct iphdr *)(packet);
			size_ip=(ip_header->ihl)*4;
		}
		
		//Determine TCP according to the protocol number 
		if(ip_header->version==0x04&&ip_header->protocol==0x06)
		{
			totalpacket++;
			totalbyte+=size_packet;
			fprintf(fp1,"%s, ",capture_time);
			strcpy(endtime,capture_time);

			/*The link state is Ethernet frames*/
			if(type==1)
				 tcp_header=(struct tcphdr *)(packet+SIZE_ETHERNET+size_ip);

			/*The link state is RAW IP*/
			else 
				 tcp_header=(struct tcphdr *)(packet+size_ip);
			size_tcp=(tcp_header->th_off)*4;

			//The source port of the data flow
			int sport=ntohs(tcp_header->th_sport);

			//Destination port for data flow
			int dport=ntohs(tcp_header->th_dport);
			strcpy(si,inet_ntoa(*(struct in_addr*)(&ip_header->saddr)));
			strcpy(di,inet_ntoa(*(struct in_addr*)(&ip_header->daddr)));

			//Output six tuple information 
			fprintf(fp1,"%d, %s, %d, ",time,si,sport);
			fprintf(fp1,"%s, %d, tcp\n",di,dport);
	
			/*Converts sport and dport into a string*/
			sprintf(sp,"%d",sport);
			sprintf(dp,"%d",dport);
			summary(si,sp,di,dp,size_packet,len);

		}
		
	}

	/*Back to the beginning of the output file*/
	rewind(fp1);
	fscanf(fp1,"%s %s,",starttime,starttime1);
	fprintf(fp2,"start_time: %s %s end_time: %s, ",starttime,starttime1,endtime);
	
	/*Total number of TCPflows*/
	totalflow=HASH_COUNT(records);
	fprintf(fp2,"total_flows: %d, total_packets: %d, total_bytes: %d\n\n", totalflow,totalpacket,totalbyte);
	
	/*Get the TCPflows*/
	solve_hash();

	int n=10;
	int j,k,index[11];
	/*Five heaps that need to be maintained*/
	struct node_has_space heap_by_byte[11],heap_by_pnum[11],heap_by_pktlen[11]; 
	struct node_space heap_by_src[11],heap_by_dst[11]; 	

	memset(index, 0, sizeof(index));

	/*Initialize five heaps*/
	init_heap(heap_by_byte,n);
	init_heap(heap_by_pnum,n);
	init_heap(heap_by_pktlen,n);
	init_heap_ip(heap_by_src,n);
	init_heap_ip(heap_by_dst,n);

	/*Adjust it to a small heap*/
        build_min_heap_by_byte(heap_by_byte, n);
  	build_min_heap_by_pnum(heap_by_pnum, n);
	build_min_heap_by_pnum(heap_by_pktlen, n);
	build_min_heap_by_ip(heap_by_src, n);
	build_min_heap_by_ip(heap_by_dst, n);

	/*The hash table can be used to get a hash table of source IP and destination IP*/
	solve_heap(heap_by_byte,heap_by_pnum,heap_by_pktlen,s,tmp,n);
	solve_heap_src(heap_by_src,s1,tmp1,n);
	solve_heap_dst(heap_by_dst,s1,tmp1,n);

	/*Take the top 10 total bytes of the TCPflows from large to small */
	sortput_by_byte(heap_by_byte,index,n);
	fprintf(fp2,"top 10 tcp flows in bytes:\n");
	for ( k = 1; k <= n; k++)   
	{
		j=index[k];
		fprintf(fp2,"%d: %s, %s, %s, %s, %s, #packets: %d, #bytes: %d, #lens: %d\n", k,heap_by_byte[j].value.srcip, heap_by_byte[j].value.srcport, heap_by_byte[j].value.dstip, heap_by_byte[j].value.dstport, heap_by_byte[j].value.proto, heap_by_byte[j].pnum,heap_by_byte[j].tbyte,heap_by_byte[j].pktlen);
	}
	
	/*Take the top 10 total packet length of the TCPflows from large to small */
	sortput_by_pktlen(heap_by_pktlen,index,n);
	fprintf(fp2,"\ntop 10 tcp flows in lengths:\n");
	for ( k = 1; k <= n; k++)   
	{
		j=index[k];
		fprintf(fp2,"%d: %s, %s, %s, %s, %s, #packets: %d, #bytes: %d, #lens: %d\n", k,heap_by_pktlen[j].value.srcip, heap_by_pktlen[j].value.srcport, heap_by_pktlen[j].value.dstip, heap_by_pktlen[j].value.dstport, heap_by_pktlen[j].value.proto, heap_by_pktlen[j].pnum,heap_by_pktlen[j].tbyte,heap_by_pktlen[j].pktlen);
	}

	/*Take the top 10 total packet numbers of the TCPflows from large to small */
	sortput_by_pnum(heap_by_pnum,index,n);
	fprintf(fp2,"\ntop 10 tcp flows in packets:\n");
	for ( k = 1; k <= n; k++)   
	{
		j=index[k];
		fprintf(fp2,"%d: %s, %s, %s, %s, %s, #packets: %d, #bytes: %d, #lens: %d\n", k,heap_by_pnum[j].value.srcip, heap_by_pnum[j].value.srcport, heap_by_pnum[j].value.dstip, heap_by_pnum[j].value.dstport, heap_by_pnum[j].value.proto, heap_by_pnum[j].pnum,heap_by_pnum[j].tbyte,heap_by_pnum[j].pktlen);
	}

	/*Number of source IP addresses*/
	int totalsrcs=HASH_COUNT(srcs);
	fprintf(fp2,"\ntotal_src_ips: %d\n", totalsrcs);

	/*Get the top ten most destination IP address of the source IP address*/
	sortput_by_ips(heap_by_src,index,n);
	fprintf(fp2,"\ntop 10 src ips in dst ips:\n");
	for ( k = 1; k <= n; k++)   
	{
		j=index[k];
		fprintf(fp2,"%d: %s, #dst_ips: %d, #packets: %d, #bytes: %d\n", k,heap_by_src[j].ip, heap_by_src[j].otherips,  heap_by_src[j].pnum,heap_by_src[j].tbyte);
	}
	
	/*Number of destination IP addresses*/
	int totaldsts=HASH_COUNT(dsts);
	fprintf(fp2,"\ntotal_dst_ips: %d\n", totaldsts);

	/*Get the top ten most source IP address of the destination IP address*/
	sortput_by_ips(heap_by_dst,index,n);
	fprintf(fp2,"\ntop 10 dst ips in src ips:\n");
	for ( k = 1; k <= n; k++)   
	{
		j=index[k];
		fprintf(fp2,"%d: %s, #src_ips: %d, #packets: %d, #bytes: %d\n", k,heap_by_dst[j].ip, heap_by_dst[j].otherips,  heap_by_dst[j].pnum,heap_by_dst[j].tbyte);
	}


/*close resources*/
cleanup:
	if(file_header) 
		free(file_header);
	if(pkt_header)
		free(pkt_header);
	if(packet)
		free(packet);

	fclose(fp);
	fclose(fp1);
	fclose(fp2);
	return 0;
	
}





void swap(int *a,int *b)  
{  
    int temp;  
    temp=*a;  
    *a=*b;  
    *b=temp;  
}  

/*Initialize the heap of 10 nodes to maintain the maximum TCP flows*/
void init_heap(struct node_has_space heap[11],int n)
{
	int j;
	 for (j = 1; j <= n; j++)    
    	{    
    		heap[j].tbyte = 0;    
    		heap[j].pnum = 0; 
		heap[j].pktlen=0;
		strcpy(heap[j].value.srcip, "");   
		strcpy(heap[j].value.srcport, "");  
		strcpy(heap[j].value.dstip, "");  
		strcpy(heap[j].value.dstport, "");  
		strcpy(heap[j].value.proto, "");     
    	}
}  

/*Initialize the heap of 10 nodes to maintain the maximum srcips or dstips */
void init_heap_ip(struct node_space heap[11],int n)
{
	int j;
	 for (j = 1; j <= n; j++)    
    	{    
    		heap[j].tbyte = 0;    
    		heap[j].pnum = 0; 
		heap[j].otherips=0;
		strcpy(heap[j].ip, "");   
    	}
}  

/*Maintains the small root heap structure of the TCPflow according to byte*/    
void sift_down_by_byte(struct node_has_space heap[11], int i,int len)    
{    
    int min_index = -1;    
    int left = 2 * i;    
    int right = 2 * i + 1;    
        
    if (left <= len && heap[left].tbyte < heap[i].tbyte)    
        min_index = left;    
    else    
        min_index = i;    
        
    if (right <= len && heap[right].tbyte < heap[min_index].tbyte)    
        min_index = right;    
        
    if (min_index != i)    
    {    
        /*Switching node element*/   
        swap(&heap[i].tbyte, &heap[min_index].tbyte);    
        swap(&heap[i].pnum, &heap[min_index].pnum);     
	swap(&heap[i].pktlen, &heap[min_index].pktlen);     
        tcpflow t;   
        t=heap[i].value;
        heap[i].value=heap[min_index].value;
        heap[min_index].value=t;   
        sift_down_by_byte(heap, min_index,len);    
    }    
}    
    
/*Maintains the small root heap structure of the TCPflow according to packetnum*/     
void sift_down_by_pnum(struct node_has_space heap[11], int i,int len)    
{    
    int min_index = -1;    
    int left = 2 * i;    
    int right = 2 * i + 1;    
        
    if (left <= len && heap[left].pnum < heap[i].pnum)    
        min_index = left;    
    else    
        min_index = i;    
        
    if (right <= len && heap[right].pnum < heap[min_index].pnum)    
        min_index = right;    
        
    if (min_index != i)    
    {    
        /*Switching node element*/    
        swap(&heap[i].tbyte, &heap[min_index].tbyte);    
        swap(&heap[i].pnum, &heap[min_index].pnum);  
	swap(&heap[i].pktlen, &heap[min_index].pktlen);      
        tcpflow t;   
        t=heap[i].value;
        heap[i].value=heap[min_index].value;
        heap[min_index].value=t;   
        sift_down_by_pnum(heap, min_index,len);    
    }    
} 

/*Maintains the small root heap structure of the TCPflow according to the packet's len*/      
void sift_down_by_pktlen(struct node_has_space heap[11], int i,int len)    
{    
    int min_index = -1;    
    int left = 2 * i;    
    int right = 2 * i + 1;    
        
    if (left <= len && heap[left].pktlen < heap[i].pktlen)    
        min_index = left;    
    else    
        min_index = i;    
        
    if (right <= len && heap[right].pktlen < heap[min_index].pktlen)    
        min_index = right;    
        
    if (min_index != i)    
    {    
        /*Switching node element*/      
        swap(&heap[i].tbyte, &heap[min_index].tbyte);    
        swap(&heap[i].pnum, &heap[min_index].pnum);  
	swap(&heap[i].pktlen, &heap[min_index].pktlen);      
        tcpflow t;   
        t=heap[i].value;
        heap[i].value=heap[min_index].value;
        heap[min_index].value=t;   
        sift_down_by_pktlen(heap, min_index,len);    
    }    
} 

/*Maintains the small root heap structure of the TCPflow according to srcips or dstips*/      
void sift_down_by_ip(struct node_space heap[11], int i,int len)    
{    
    int min_index = -1;    
    int left = 2 * i;    
    int right = 2 * i + 1;    
        
    if (left <= len && heap[left].otherips < heap[i].otherips)    
        min_index = left;    
    else    
        min_index = i;    
        
    if (right <= len && heap[right].otherips< heap[min_index].otherips)    
        min_index = right;    
        
    if (min_index != i)    
    {    
        /*Switching node element*/      
        swap(&heap[i].tbyte, &heap[min_index].tbyte);    
        swap(&heap[i].pnum, &heap[min_index].pnum);  
	swap(&heap[i].otherips, &heap[min_index].otherips);   
        char t[100]; 
	strcpy(t,heap[i].ip);  
        strcpy(heap[i].ip,heap[min_index].ip);
	strcpy(heap[min_index].ip,t);
        sift_down_by_ip(heap, min_index,len);    
    }    
} 

/*Process srcdst hash to get src and dst*/
void solve_hash()
{
	src l, *p, *r;
	srcdst *tmp,*s;
	memset(&l, 0, sizeof(src));
	/*Traverse srcdst hashmap,each record is stored in s*/
	HASH_ITER(hh, srcdsts, s, tmp) 
	{
		
		
    		strcpy(l.ip, s->key1.srcip);
		/*Check whether the source IP address already exists*/
  		HASH_FIND(hh, srcs, &l.ip, 100*sizeof(char), p);

		/*If the source IP address already exists, accumulate the corresponding number of packages, total number of bytes and the number of receiving destination IP 			address*/
   	 	if (p) 
    		{
			p->totalbyte+=s->totalbyte1;
			p->packetnum+=s->packetnum1;
			p->otherips++;
    		}
		/*If this source IP address does not exist, a new record is added in the hash table and initialized*/
    		else
    		{
			r = (src*)malloc( sizeof(src) );
    			memset(r, 0, sizeof(src));
   			strcpy(r->ip,s->key1.srcip );
    			r->totalbyte=s->totalbyte1;
    			r->packetnum=s->packetnum1;
			r->otherips=1;
    			HASH_ADD(hh, srcs, ip, 100*sizeof(char), r);
   	 	}

		memset(&l, 0, sizeof(src));
		/*Check whether the Destination IP address already exists*/
		strcpy(l.ip, s->key1.dstip);
  		HASH_FIND(hh, dsts, &l.ip, 100*sizeof(char), p);

   	 	if (p) 
    		{
			p->totalbyte+=s->totalbyte1;
			p->packetnum+=s->packetnum1;
			p->otherips++;
    		}
    		else
    		{
			r = (src*)malloc( sizeof(src) );
    			memset(r, 0, sizeof(src));
   			strcpy(r->ip,s->key1.dstip );
    			r->totalbyte=s->totalbyte1;
    			r->packetnum=s->packetnum1;
			r->otherips=1;
    			HASH_ADD(hh, dsts, ip, 100*sizeof(char), r);
   	 	}
		
	}

}

/*Function is the function of traversing the records(hash table) at the same time dealing with three small heaps*/
void solve_heap(struct node_has_space heap[11],struct node_has_space heap1[11],struct node_has_space heap2[11],record *s, record *tmp,int n)
{
	HASH_ITER(hh, records, s, tmp) 
	{
		
		/*You need to adjust the heap only if the type value of the current record is greater than the minimum type value in the heap*/			
   		if (s->totalbyte > heap[1].tbyte)    
        	{    
            		heap[1].tbyte= s->totalbyte;  
			heap[1].pnum=s->packetnum;
			heap[1].pktlen=s->pktlen;
			strcpy(heap[1].value.srcip,s->key.srcip);   
			strcpy(heap[1].value.srcport,s->key.srcport);  
			strcpy(heap[1].value.dstip,s->key.dstip);  
			strcpy(heap[1].value.dstport,s->key.dstport);  
			strcpy(heap[1].value.proto,"tcp");    
            		sift_down_by_byte(heap, 1, n);    
       		 }    
		if (s->packetnum > heap1[1].pnum)    
        	{    
            		heap1[1].tbyte= s->totalbyte;  
			heap1[1].pnum=s->packetnum;
			heap1[1].pktlen=s->pktlen;
			strcpy(heap1[1].value.srcip,s->key.srcip);   
			strcpy(heap1[1].value.srcport,s->key.srcport);  
			strcpy(heap1[1].value.dstip,s->key.dstip);  
			strcpy(heap1[1].value.dstport,s->key.dstport);  
			strcpy(heap1[1].value.proto,"tcp");    
            		sift_down_by_pnum(heap1, 1, n);    
       		 }    
		 if (s->pktlen > heap1[1].pktlen)    
        	{    
            		heap2[1].tbyte= s->totalbyte;  
			heap2[1].pnum=s->packetnum;
			heap2[1].pktlen=s->pktlen;
			strcpy(heap2[1].value.srcip,s->key.srcip);   
			strcpy(heap2[1].value.srcport,s->key.srcport);  
			strcpy(heap2[1].value.dstip,s->key.dstip);  
			strcpy(heap2[1].value.dstport,s->key.dstport);  
			strcpy(heap2[1].value.proto,"tcp");    
            		sift_down_by_pktlen(heap2, 1, n);    
       		 }      
		   
	}
}

/*Traverse the src hash table in order to adjust the SRC heap*/
void solve_heap_src(struct node_space heap[11],src *s, src *tmp,int n)
{
	HASH_ITER(hh, srcs, s, tmp) 
	{
		/*The heap can only be adjusted if the number of IP addresses that are currently logged is greater than the minimum number of data in the heap*/	
   		if (s->otherips> heap[1].otherips)    
        	{    
            		heap[1].tbyte= s->totalbyte;  
			heap[1].pnum=s->packetnum;
			heap[1].otherips=s->otherips;
			strcpy(heap[1].ip,s->ip);   
            		sift_down_by_ip(heap, 1, n);    
       		 }    	   
	}
}

/*Traverse the dst hash table in order to adjust the dst heap*/
void solve_heap_dst(struct node_space heap[11],src *s, src *tmp,int n)
{
	HASH_ITER(hh, dsts, s, tmp) 
	{

		/*The heap can only be adjusted if the number of IP addresses that are currently logged is greater than the minimum number of data in the heap*/	
   		if (s->otherips> heap[1].otherips)    
        	{    
            		heap[1].tbyte= s->totalbyte;  
			heap[1].pnum=s->packetnum;
			heap[1].otherips=s->otherips;
			strcpy(heap[1].ip,s->ip);   
            		sift_down_by_ip(heap, 1, n);    
       		 }    	   
	}
}


/*According to the IP address to build min heap*/    
void build_min_heap_by_ip(struct node_space heap[],int len)    
{    
	int i;
    if (heap == NULL)    
        return;    
        
    int index = len / 2;    
    for (i = index; i >= 1; i--)    
        sift_down_by_ip(heap, i,len);    
}      


/*According to the byte to build min heap*/    
void build_min_heap_by_byte(struct node_has_space heap[],int len)    
{    
	int i;
    if (heap == NULL)    
        return;    
        
    int index = len / 2;    
    for (i = index; i >= 1; i--)    
        sift_down_by_byte(heap, i,len);    
}    
    
/*According to the packet nums to build min heap*/    
void build_min_heap_by_pnum(struct node_has_space heap[],int len)    
{    
	int i;
    if (heap == NULL)    
        return;    
        
    int index = len / 2;    
    for (i = index; i >= 1; i--)    
        sift_down_by_pnum(heap, i,len);    
}  

/*According to the packet len to build min heap*/     
void build_min_heap_by_pktlen(struct node_has_space heap[],int len)    
{    
	int i;
    if (heap == NULL)    
        return;    
        
    int index = len / 2;    
    for (i = index; i >= 1; i--)    
        sift_down_by_pktlen(heap, i,len);    
} 


/*Aanalysis parameters*/
static int parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	int opterr=0;
	argvopt = argv;

	while ((opt = getopt(argc, argvopt, "r:w:s:")) != -1) {

		switch (opt) {

		/* Offline pcap file name*/
		case 'r':
			input=optarg;
			break;

		/*The filename of the five-tuple information output*/
		case 'w':
			output1=optarg;
			break;

		/*The file name of the statistics output*/
		case 's':
			output2=optarg;
			break;


		default:
			printf("please check the arguments!\n");
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;

	/* reset getopt lib */
	optind = 0; 
	return ret;
}

void summary(char *si,char *sp,char *di,char *dp,int slen,int len)
{
    record l, *p, *r, *tmp;
    srcdst l1,*p1,*r1,*tmp1;

    memset(&l, 0, sizeof(record));
    strcpy(l.key.srcip, si);
    strcpy(l.key.srcport, sp);
    strcpy(l.key.dstip, di);
    strcpy(l.key.dstport, dp);
    strcpy(l.key.proto , "tcp");
    
    /*Check whether the TCP flow exists in the hash */
    HASH_FIND(hh, records, &l.key, sizeof(tcpflow), p);

    /*If it is TCP flow already exists, then update the field value*/
    if (p) 
    {
	p->totalbyte+=slen;
	p->pktlen+=len;
	p->packetnum++;
    }
    
    /*If it doesn't exist, add a record in the hash and initialize the value*/
    else
    {
	r = (record*)malloc( sizeof(record) );
    	memset(r, 0, sizeof(record));
   	strcpy(r->key.srcip, si);
   	strcpy(r->key.srcport, sp);
    	strcpy(r->key.dstip, di);
    	strcpy(r->key.dstport, dp);
    	strcpy(r->key.proto, "tcp");
    	r->totalbyte=slen;
	r->pktlen=len;
    	r->packetnum=1;
    	HASH_ADD(hh, records, key, sizeof(tcpflow), r);
    }

    memset(&l1, 0, sizeof(srcdst));
    strcpy(l1.key1.srcip, si);
    strcpy(l1.key1.dstip, di);
    HASH_FIND(hh, srcdsts, &l1.key1, sizeof(tf), p1);

    if (p1) 
    {
	p1->totalbyte1+=slen;
	p1->packetnum1++;
    }
    else
    {
	r1 = (srcdst*)malloc( sizeof(srcdst) );
    	memset(r1, 0, sizeof(srcdst));
   	strcpy(r1->key1.srcip, si);
    	strcpy(r1->key1.dstip, di);
    	r1->totalbyte1=slen;
    	r1->packetnum1=1;
    	HASH_ADD(hh, srcdsts, key1, sizeof(tf), r1);
    }


    
   /* HASH_ITER(hh, records, p, tmp) {
      HASH_DEL(records, p);
      free(p);
    }*/
}

/*Sort the type heap and store the result in the index array*/
void sortput_by_byte(struct node_has_space heap[],int index[11],int n)
{
	int num[11];
	int i,j,temp,k,x=1;
	memset(num, 0, sizeof(num));
	memset(index, 0, sizeof(index));
	for(k=1;k<=n;k++)
	{
		num[k]=heap[k].tbyte;
	}
	for(i=1;i<11;i++)
	{
		k=i;
		for(j=1;j<11;j++)
		{
			if(num[j]>num[k]) k=j;
		}
		num[k]=-1;
		index[x++]=k;
	}
}

/*Sort the ip heap and store the result in the index array*/
void sortput_by_ips(struct node_space heap[],int index[11],int n)
{
	int num[11];
	int i,j,temp,k,x=1;
	memset(num, 0, sizeof(num));
	memset(index, 0, sizeof(index));
	for(k=1;k<=n;k++)
	{
		num[k]=heap[k].otherips;
	}
	for(i=1;i<11;i++)
	{
		k=i;
		for(j=1;j<11;j++)
		{
			if(num[j]>num[k]) k=j;
		}
		num[k]=-1;
		index[x++]=k;
	}
}

/*Sort the packet num heap and store the result in the index array*/
void sortput_by_pnum(struct node_has_space heap[],int index[11],int n)
{
	int num[11];
	int i,j,temp,k,x=1;
	memset(num, 0, sizeof(num));
	memset(index, 0, sizeof(index));
	for(k=1;k<=n;k++)
	{
		num[k]=heap[k].pnum;
	}
	for(i=1;i<11;i++)
	{
		k=i;
		for(j=1;j<11;j++)
		{
			if(num[j]>num[k]) k=j;
		}
		num[k]=-1;
		index[x++]=k;
	}
}

/*Sort the packet len heap and store the result in the index array*/
void sortput_by_pktlen(struct node_has_space heap[],int index[11],int n)
{
	int num[11];
	int i,j,temp,k,x=1;
	memset(num, 0, sizeof(num));
	memset(index, 0, sizeof(index));
	for(k=1;k<=n;k++)
	{
		num[k]=heap[k].pktlen;
	}
	for(i=1;i<11;i++)
	{
		k=i;
		for(j=1;j<11;j++)
		{
			if(num[j]>num[k]) k=j;
		}
		num[k]=-1;
		index[x++]=k;
	}
}


