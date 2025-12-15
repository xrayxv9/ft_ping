#include "utils.h"
#include <stdio.h>

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
		printf("addresse : %s\n", inet_ntoa(addr));
		ping->ip_addr = inet_ntoa(addr);
	}
}

void	sockfd_create(t_ping *ping)
{
	// je commence a faire la config de mon reseau
	struct sockaddr_in addr;
	ping->addr = &addr;
	ping->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // je set le socket
	if (ping->sockfd == -1)
	{
		dprintf(2, ERROR_SOCKFD);
		exit(1);
	}
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, ping->ip_addr, &addr.sin_addr); // AF_INET = IPv4, inet_ntoa, mon addresse au format de string, sin_addr, je lui dis vers quel
	// type d'IP il va communique
}

void	init_packet(t_ping *ping)
{
	char packet[sizeof(struct icmphdr)]; // je fais ca pour avoir un tableau brut de la taille que je demande
	struct icmphdr *icmp_addr = (struct icmphdr *)packet; // packet de type ICMP
	bzero(&packet, sizeof(packet));
	icmp_addr->type = ICMP_ECHO; // On veut faire des request de type echo comme la vrai command ping
	icmp_addr->code = 0; // Ferra partie du header de ma request ne sert a rien parce que j'ai deja init a 0 avec le bzero mais pg
	icmp_addr->un.echo.id = getpid() & 0xFFFF; // utile pour pouvoir utilise plusieurs ping en meme temps sans qu'ils s'emmele les pinceaux
	// on tronc parce que c'est sur 16bits
	icmp_addr->un.echo.sequence = htons(1); // je fais passe un nombre qui n'est pas dans le bon format en big-endian car c'est la norme des reseaux
	icmp_addr->checksum = checksum(packet, sizeof(packet));
	ping->icmp_addr = icmp_addr;
	ping->packet = packet;
	
	struct sockaddr_in recv_addr;
	socklen_t l = sizeof(recv_addr);
	ping->recv_addr = &recv_addr;
	ping->addr_length = l;
	char *buffer = calloc(1024, 1);
	if (!buffer)
		fatal(ping);
	ping->buffer = buffer;

}

void	send_packet(t_ping *ping)
{
	if (sendto(ping->sockfd, ping->packet, sizeof(ping->packet), 0, (struct sockaddr *)ping->addr, sizeof(*ping->addr)) == -1)
	{
		perror("sendto: ");
		close(ping->sockfd);
		exit(1);
	}
}

void	recv_packet(t_ping *ping)
{	
	if (recvfrom(ping->sockfd, ping->buffer, 1024, 0, (struct sockaddr *)ping->recv_addr, &ping->addr_length) == -1)
		fatal(ping);
}


void	exploit_packet(t_ping *ping)
{	
	struct	iphdr *ip_header = (struct iphdr *)ping->buffer;
	struct icmphdr *icmp_header = (struct icmphdr *)(ping->buffer + (ip_header->ihl * 4));
	// ihl, internet header length, ca calcul le nombre de packet de 4 octets pour le header, c'est pour ca le *4

	if (icmp_header->type == ICMP_ECHOREPLY && icmp_header->un.echo.id == (getpid() & 0xFFFF))
	{
		printf("Recu correctement\n");
	}
	else {
		printf("error\n");
	}

}
