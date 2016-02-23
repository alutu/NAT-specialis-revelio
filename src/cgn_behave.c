#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include "stun.h"

char *stunserver = STUN_SERVER;
int stunport = STUN_PORT;
#define MAXBUFLEN 62




double get_time (void) {
	struct timeval tv;
	double d;

	gettimeofday (&tv, NULL);

	d = ((double) tv.tv_usec) / 1000000. + (unsigned long) tv.tv_sec;

	return d;
}


char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
  switch(sa->sa_family) {
  case AF_INET:
    inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
	      s, maxlen);
    break;

  case AF_INET6:
    inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
	      s, maxlen);
    break;

  default:
    strncpy(s, "Unknown AF", maxlen);
    return NULL;
  }

  return s;
}

/*------------------------------------------------------------------------------------------
 * ---------------------------MAIN----------------------------------------------------------
 -----------------------------------------------------------------------------------------*/


int main(int argc, char *argv[])
{
	//printf("timestamp;localInterfaces:IP;IGD;STUN_mapped;hairpin-TTL;tr_port1;tr_port2;tr_port3;tr_port4; tr_port5; tr_port6;tr_port7;tr_port8;tr_port9;tr_port10;traceroute_fixedTarget\n");
    double t = get_time();
    printf("%d;", (int )t);

	//add timestamp here!
	/*--------------------------------------------------------------------------------------------------
	  * ---------------------------------------Local IP address-------------------------------------------------
	  --------------------------------------------------------------------------------------------------*/

      char          buff[1024] = {0};
      struct ifconf ifc = {0};
      struct ifreq *ifr = NULL;
      int           sck = 0;
      int           nInterfaces = 0;
      int           i = 0;

      sck = socket(AF_INET, SOCK_DGRAM, 0);
      if(sck < 0) {
        perror("socket");
        return 1;
      }

      /* Query available interfaces. */
      ifc.ifc_len = sizeof(buff);
      ifc.ifc_buf = buff;
      if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl(SIOCGIFCONF)");
        return 1;
      }

      /* Iterate through the list of interfaces. */
      ifr = ifc.ifc_req;
      nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
      for(i = 0; i < nInterfaces; i++)
        {//&amp;
          struct ifreq *item = &ifr[i];

          /* Show the device name and IP address */
          struct sockaddr *addr = &(item->ifr_addr);
          char ip[INET6_ADDRSTRLEN];
          printf("%s:%s,",
    	     item->ifr_name,
    	     get_ip_str(addr, ip, INET6_ADDRSTRLEN));
        }
		printf(";");


	 /*--------------------------------------------------------------------------------------------------
	  * ---------------------------------------STUN mapped address-------------------------------------------------
	  --------------------------------------------------------------------------------------------------*/
//ministun -- classic stun
	int sock, res, sock_alt;
	struct sockaddr_in server,client,mapped,changed, mapped_t2, mapped_t3, client_alt;
	struct hostent *hostinfo;
	//int numbytes;
	//struct sockaddr_in their_addr;
	//unsigned char *buf = (unsigned char *)malloc(MAXBUFLEN);
	//socklen_t addr_len;
	//addr_len = sizeof their_addr;

	hostinfo = gethostbyname(stunserver);
	if (!hostinfo) {
		fprintf(stderr, "Error resolving host %s\n", stunserver);
		return -1;
	}
	bzero(&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
	server.sin_port = htons(stunport); //3478

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if( sock < 0 ) {
		fprintf(stderr, "Error creating socket\n");
		return -1;
	}

	bzero(&client, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_ANY);
	client.sin_port = 0;

	if (bind(sock, (struct sockaddr*)&client, sizeof(client)) < 0) {
		fprintf(stderr, "Error bind to socket\n");
		close(sock);
		return -1;
	}
/*
 * verify connectivity to the STUN server and the fact that the server has a change address configured
 */
	res = stun_request(sock, &server, &changed, 1, -1, -1);
	if (!res){
		printf("\nCHANGED %s:%i;",inet_ntoa(changed.sin_addr), ntohs(changed.sin_port));

	}

	res = stun_request(sock, &server, &mapped, -1, -1, -1);
	if (!res){
		printf("\nMAPPED Test1 %s:%i;",inet_ntoa(mapped.sin_addr), ntohs(mapped.sin_port));
	}
//send STUN Binding Request to the change address, primary port
	server.sin_addr = changed.sin_addr;
	server.sin_port = htons(stunport); //3478

	res = stun_request(sock, &server, &mapped_t2, -1, -1, -1);
	if (!res){
		printf("\nMAPPED Test2 %s:%i;",inet_ntoa(mapped_t2.sin_addr), ntohs(mapped_t2.sin_port));
	}

	if ((mapped.sin_port == mapped_t2.sin_port) & (inet_ntoa(mapped.sin_addr) == inet_ntoa(mapped_t2.sin_addr))){
		printf("Endpoint Independent Mapping\n");
	}else{
		res = stun_request(sock, &changed, &mapped_t3, -1, -1, -1);
		if (!res){
			printf("MAPPED Test3 %s:%i;",inet_ntoa(mapped_t3.sin_addr), ntohs(mapped_t3.sin_port));
		}
		if((mapped_t3.sin_port == mapped_t2.sin_port) & (inet_ntoa(mapped_t3.sin_addr) == inet_ntoa(mapped_t2.sin_addr))){
			printf("Address Dependent Mapping\n");
		}else{
			printf("Address and Port Dependent Mapping\n");
		}
	}

	/*
	 * Verify type of FILTERING
	 */

	server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
	server.sin_port = htons(stunport); //3478
	res = stun_request(sock, &server, &mapped, -1, 1, 1);
	if (!res){
		printf("Endpoint Independent Filtering\n");
	}else{
		res = stun_request(sock, &server, &mapped, -1, 1, -1);
		if (!res){
				printf("Address-Dependent Filtering\n");
			}else{
				printf("Address and Port-Dependent Filtering\n");
			}
	}

	/*
	 * Verify Mapping Lifetime (UDP, TCP, ICMP)
	 * send STUN BR to the stunserver using port x
	 * wait t time
	 * send STUN BR to the stunserver using port y but with RESPONSE_ADDRESS set to the mapped address retrieved above
	 */

	res = stun_request(sock, &server, &mapped, -1, -1, -1);
	if (!res){
		printf("\nResponse address to use %s:%i;",inet_ntoa(mapped.sin_addr), ntohs(mapped.sin_port));
	}


	sock_alt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if( sock_alt < 0 ) {
		fprintf(stderr, "Error creating socket\n");
		return -1;
	}

	bzero(&client_alt, sizeof(client_alt));
	client_alt.sin_family = AF_INET;
	client_alt.sin_addr.s_addr = htonl(INADDR_ANY);
	client_alt.sin_port = 0;

	if (bind(sock_alt, (struct sockaddr*)&client_alt, sizeof(client_alt)) < 0) {
		fprintf(stderr, "Error bind to socket\n");
		close(sock_alt);
		return -1;
	}


	/* discover the timeout on a trial and error basis
	 * start with a minimum of 2 minutes  and increment from there
	 */
	sleep(1);
	//request a STUN answer from mapped_t2
	res = stun_request_response_address(sock_alt, sock, &server, &mapped_t2, &mapped);
	// add the socket on which we have to receive the reply
	if (!res){
		printf("Mapping Lifetime %s:%i;",inet_ntoa(mapped_t2.sin_addr), ntohs(mapped_t2.sin_port));
	}
	return 0;
}
