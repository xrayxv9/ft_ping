#include "utils.h"

int main(int ac, char *av[])
{
	t_ping	ping;

	if (ac == 1)
	{
		dprintf(2, ERROR_NO_ARG);
		return 1;
	}
	bzero(&ping, sizeof(ping));
	ping.sockfd = -1;
	resolve_dns(&ping, av[ac - 1]);
	sockfd_create(&ping);
	init_packet(&ping);
	send_packet(&ping);
	recv_packet(&ping);
	exploit_packet(&ping);

	close(ping.sockfd);
	free(ping.buffer);
}
