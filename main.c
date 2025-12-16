#include "utils.h"
#include <sys/time.h>

int main(int ac, char *av[])
{
	t_ping	ping;
	struct timeval t_start, t_end;

	if (ac == 1)
	{
		dprintf(2, ERROR_NO_ARG);
		return 1;
	}
	bzero(&ping, sizeof(ping));
	ping.dns = strdup(av[ac - 1]);
	ping.sockfd = -1;
	resolve_dns(&ping, av[ac - 1]);
	sockfd_create(&ping);
	init_packet(&ping);
	while (1)
	{
		prep_packet(&ping);
		gettimeofday(&t_start, NULL);
		send_packet(&ping);
		recv_packet(&ping);
		gettimeofday(&t_end, NULL);
		double rtt = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
                      (t_end.tv_usec - t_start.tv_usec) / 1000.0;
		exploit_packet(&ping, rtt);
		sleep(1);
	}

	
	free(ping.dns);
	free(ping.addr);
	close(ping.sockfd);
	free(ping.buffer);
	free(ping.recv_addr);
}
