#pragma once

// Includes
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

// Define
#define ERROR_DNS "ping: %s: Temporary failure in name resolution\n"
#define ERROR_SOCKFD "Sockfd couldn't be created correctly\n"
#define ERROR_NO_ARG "ping: usage error: Destination address required\n"

// Struct
typedef struct s_ping
{
	char	*ip_addr;
	int		sockfd;
	char	*packet;
	char	*buffer;
	struct	icmphdr *icmp_addr;
	struct	sockaddr_in *addr;
	struct	sockaddr_in *recv_addr;
	socklen_t			addr_length;
}	t_ping;

// Functions
unsigned short checksum(void *str, size_t len);
void	resolve_dns(t_ping *ping, char *host_name);
void	sockfd_create(t_ping *ping);
void	init_packet(t_ping *ping);
void	send_packet(t_ping *ping);
void	recv_packet(t_ping *ping);
void	exploit_packet(t_ping *ping);
