#include "utils.h"
#include <bits/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned short checksum(void *str, size_t len)
{
	unsigned int sum = 0;
	unsigned short *byte = str;
	unsigned short result = 0; // on utilise des short parce que le protocol ICMP travail en 16bits

	for (; len > 1; len -= 2)
		sum += *byte++;
	if (len == 1)
		sum += *(unsigned char *)byte;
	sum = (sum >> 16) + (sum & 0xFFFF); // on additionne les 16 bits haut de notre sum, avec les 16 bas
	sum += sum >> 16; // on s'assure qu'il n'y est plus de bits qui depacent les 16
	result -= ~sum; // complement a 1, utile parce que dans des cas tres precis, sans ca on peut se retrouver avec des erreurs masques 
	// et c'est juste une norme en plus
	return result;
}

void	fatal(t_ping *ping)
{
	if (ping->buffer)
		free(ping->buffer);
	if (ping->sockfd != -1)
		close(ping->sockfd);
	if (ping->addr)
		free(ping->addr);
	if (ping->recv_addr)
		free(ping->recv_addr);
	exit(1);
}

void	resolve_dns(t_ping *ping, char *host_name)
{
	struct in_addr addr;
	struct hostent *host = gethostbyname(host_name);

	if (!host)
	{
		dprintf(2, ERROR_DNS, host_name);
		exit(1);
	}
	else
	{
		bcopy(*host->h_addr_list++, (char *)&addr, sizeof(addr));
		ping->ip_addr = inet_ntoa(addr);
	}
}

void	sockfd_create(t_ping *ping)
{
	// je commence a faire la config de mon reseau
	struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
	ping->addr = addr;
	ping->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // je set le socket
	if (ping->sockfd == -1)
	{
		dprintf(2, ERROR_SOCKFD);
		exit(1);
	}
	bzero(addr, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	inet_pton(AF_INET, ping->ip_addr, &addr->sin_addr); // AF_INET = IPv4, inet_ntoa, mon addresse au format de string, sin_addr, je lui dis vers quel

	struct timeval timeout;
	timeout.tv_sec = TIMEOUT_SEC;
	timeout.tv_usec = 0;
	if (setsockopt(ping->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
	{
		perror("Timout");
		fatal(ping);
	}
}

void	init_packet(t_ping *ping)
{
	ping->seq = 1;
	struct sockaddr_in *recv_addr = malloc(sizeof(struct sockaddr_in));
	socklen_t l = sizeof(struct sockaddr_in);
	ping->recv_addr = recv_addr;
	ping->addr_length = l;
	char *buffer = calloc(1024, 1);
	if (!buffer)
		fatal(ping);
	ping->buffer = buffer;
}

void	prep_packet(t_ping *ping)
{
	if (ping->icmp_addr)
		free(ping->icmp_addr);
	struct icmp *icmp_addr = calloc(sizeof(struct icmp), 1);
	ping->icmp_addr = icmp_addr;

	icmp_addr->icmp_type = ICMP_ECHO; // On veut faire des request de type echo comme la vrai command ping
	icmp_addr->icmp_code = 0; // Ferra partie du header de ma request ne sert a rien parce que j'ai deja init a 0 avec le bzero mais pg
	icmp_addr->icmp_id = getpid() & 0xFFFF; // utile pour pouvoir utilise plusieurs ping en meme temps sans qu'ils s'emmele les pinceaux
	// on tronc parce que c'est sur 16bits
	icmp_addr->icmp_seq = htons(ping->seq++);// je fais passe un nombre qui n'est pas dans le bon format en big-endian car c'est la norme des reseaux
	icmp_addr->icmp_cksum = checksum(ping->icmp_addr, sizeof(struct icmphdr));
}

void	send_packet(t_ping *ping)
{
	if (sendto(ping->sockfd, ping->icmp_addr, sizeof(struct icmphdr), 0, (struct sockaddr *)ping->addr, sizeof(struct sockaddr_in)) == -1)
	{
		perror("sendto");
		close(ping->sockfd);
		exit(1);
	}
}

void	recv_packet(t_ping *ping)
{
	if (recvfrom(ping->sockfd, ping->buffer, 1024, 0, (struct sockaddr *)ping->recv_addr, &ping->addr_length) == -1)
		fatal(ping);
}


void	exploit_packet(t_ping *ping, double time)
{	
	struct	ip *ip_header = (struct ip *)ping->buffer;
	struct icmp *icmp_header = (struct icmp *)(ping->buffer + (ip_header->ip_hl << 2));
	// ihl, internet header length, ca calcul le nombre de packet de 4 octets pour le header, c'est pour ca le *4

	if (icmp_header->icmp_type == ICMP_ECHOREPLY && icmp_header->icmp_id == (getpid() & 0xFFFF))
	{
		//64 bytes from stackoverflow.com (198.252.206.1): icmp_seq=1 ttl=58 time=14.3 ms
		printf("64 bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms\n", ping->dns, ping->ip_addr, ntohs(ping->icmp_addr->icmp_seq), ip_header->ip_ttl, time);
	}
	else {
		printf("error\n");
		fatal(ping);
	}
}
