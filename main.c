#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <unistd.h>
int main()
{
	struct in_addr str;
	struct hostent *host = gethostbyname("stackoverflow.com");
	if (!host)
	{
		printf("cheh\n");
	}
	else
	{
		while (*host->h_aliases)
			printf("alias: %s\n", *host->h_aliases++);
		while (*host->h_addr_list)
		{
			bcopy(*host->h_addr_list++, (char *)&str, sizeof(str));
			printf("addresse : %s\n", inet_ntoa(str));
		}
		printf("name : %s\n", host->h_name);
	}

	int sockfd = socket(AF_INET, SOCK_RAW, )
}
