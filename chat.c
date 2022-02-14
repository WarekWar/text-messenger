/*
* Authors:
* Michal Ptak
* Michal Kaszuba
* Wojciech Nodzynski
*/


#include        <sys/types.h>   /* basic system data types */
#include        <sys/socket.h>  /* basic socket definitions */
#include        <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include        <arpa/inet.h>   /* inet(3) functions */
#include        <errno.h>
#include        <signal.h>
#include        <stdio.h>
#include        <stdlib.h>
#include        <string.h>
#include 		<sys/ioctl.h>
#include 		<unistd.h>
#include 		<net/if.h>
#include		<netdb.h>
#include		<sys/utsname.h>
#include		<linux/un.h>
#include        <fcntl.h>
#include		<sys/wait.h>
#include		<netinet/sctp.h>
#include		<ctype.h>

#define MAXLINE 1024
#define SA      struct sockaddr
#define IPV6 1
#define	SENDRATE	1		/* send one datagram every one second */

char* nickname;

void
sig_chld(int signo)			// zabijamy procesy zombie :)
{
	pid_t	pid;
	int		stat;

	while ((pid = waitpid(-1, &stat, WNOHANG)) > 0); //cios w glowe
		//printf("child %d terminated\n", pid);
	return; 
}


int snd_udp_socket(const char* serv, int port, SA** saptr, socklen_t* lenp)				//Tworzenie gniazda wysylajacego UDP multicast
{
	int sockfd, n;
	struct sockaddr_in* pservaddrv4;
	*saptr = malloc(sizeof(struct sockaddr_in));
	pservaddrv4 = (struct sockaddr_in*)*saptr;
	bzero(pservaddrv4, sizeof(struct sockaddr_in));

	if (inet_pton(AF_INET, serv, &pservaddrv4->sin_addr) <= 0) {
		fprintf(stderr, "AF_INET inet_pton error for %s : %s \n", serv, strerror(errno));
		return -1;
	}
	else {
		pservaddrv4->sin_family = AF_INET;
		pservaddrv4->sin_port = htons(port);
		*lenp = sizeof(struct sockaddr_in);
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			fprintf(stderr, "AF_INET socket error : %s\n", strerror(errno));
			return -1;
		}
	}

	return(sockfd);
}
/* end send_udp_socket */

int rcv_udp_socket(const char* serv, int sendfd, SA* sasnd, SA** sarcv, socklen_t* lenp) {		//Tworzenie gniazda odbierajacego UDP multicast

	int sockfd;
	const int on = 1;
	struct sockaddr_in* rcvaddrv4;
	const char* ief2;
	ief2 = "enp0s8";

	if ((sockfd = socket(sasnd->sa_family, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket error : %s\n", strerror(errno));
		return 1;
	}

	*sarcv = malloc(sizeof(struct sockaddr_in));
	rcvaddrv4 = (struct sockaddr_in*)*sarcv;
	bzero(rcvaddrv4, sizeof(struct sockaddr_in));

	rcvaddrv4 = (struct sockaddr_in*)sarcv;
	rcvaddrv4->sin_addr.s_addr = htonl(INADDR_ANY);

	struct in_addr        localInterface;
	localInterface.s_addr = if_nametoindex(serv);
	if (setsockopt(sendfd, IPPROTO_IP, IP_MULTICAST_IF,
		(char*)&localInterface, sizeof(localInterface)) < 0) {
		perror("setting local interface");
		exit(1);
	}
	
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		fprintf(stderr, "setsockopt error : %s\n", strerror(errno));
		return 1;
	}

	return(sockfd);
}
/* end recv_udp_socket */

int snd_sctp_socket(char* serv, int port, SA** saptr, socklen_t* lenp) {		//Tworzenie gniazda wysylajacego SCTP
	int sockfd, n;
	struct sockaddr_in* pservaddrv4;

		*saptr = malloc(sizeof(struct sockaddr_in));
		pservaddrv4 = (struct sockaddr_in*)*saptr;
		bzero(pservaddrv4, sizeof(struct sockaddr_in));

		if (inet_pton(AF_INET, serv, &pservaddrv4->sin_addr) <= 0) {
			fprintf(stderr, "AF_INET inet_pton error for %s : %s \n", serv, strerror(errno));
			return -1;
		}
		else {
			pservaddrv4->sin_family = AF_INET;
			pservaddrv4->sin_port = htons(port);
			*lenp = sizeof(struct sockaddr_in);
			if ((sockfd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0) {
				fprintf(stderr, "AF_INET socket error : %s\n", strerror(errno));
				return -1;
			}
		}
	return(sockfd);
}
/* end send_udp_socket */

int rcv_sctp_socket(SA* sasnd, SA** sarcv, socklen_t* lenp) {			//Tworzenie gniazda odbierajacego SCTP

	int sockfd;
	const int on = 1;


	if ((sockfd = socket(sasnd->sa_family, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0) {
		fprintf(stderr, "socket error : %s\n", strerror(errno));
		return 1;
	}


	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		fprintf(stderr, "setsockopt error : %s\n", strerror(errno));
		return 1;
	}

	return(sockfd);
}
/* end recv_udp_socket */

int family_to_level(int family)
{
	switch (family) {
	case AF_INET:
		return IPPROTO_IP;
#ifdef	IPV6
	case AF_INET6:
		return IPPROTO_IPV6;
#endif
	default:
		return -1;
	}
}

int mcast_join(int sockfd, const SA* grp, socklen_t grplen,				// Dolaczenie do grupy multicastowej
	const char* ifname, u_int ifindex)
{
	struct group_req req;
	if (ifindex > 0) {
		req.gr_interface = ifindex;
	}
	else if (ifname != NULL) {
		if ((req.gr_interface = if_nametoindex(ifname)) == 0) {
			errno = ENXIO;	/* if name not found */
			return(-1);
		}
	}
	else
		req.gr_interface = 0;
	if (grplen > sizeof(req.gr_group)) {
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.gr_group, grp, grplen);
	return (setsockopt(sockfd, family_to_level(grp->sa_family),
		MCAST_JOIN_GROUP, &req, sizeof(req)));
}
/* end mcast_join */

int sockfd_to_family(int sockfd)
{
	struct sockaddr_storage ss;
	socklen_t	len;

	len = sizeof(ss);
	if (getsockname(sockfd, (SA*)&ss, &len) < 0)
		return(-1);
	return(ss.ss_family);
}

int mcast_set_loop(int sockfd, int onoff)				// Ustawienie MULTICAST_LOOP
{
	switch (sockfd_to_family(sockfd)) {
	case AF_INET: {
		u_char		flag;

		flag = onoff;
		return(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
			&flag, sizeof(flag)));
	}

#ifdef	IPV6
	case AF_INET6: {
		u_int		flag;

		flag = onoff;
		return(setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			&flag, sizeof(flag)));
	}
#endif

	default:
		errno = EAFNOSUPPORT;
		return(-1);
	}
}
/* end mcast_set_loop */

int send_all(int sendfd,int recvfd, SA* sadest, socklen_t salen)		//Wysylanie na adres multicastowy
{
	char		line[MAXLINE];		/* hostname and process ID */
	char 	pom[MAXLINE];
	char	exit[MAXLINE];

	snprintf(line, sizeof(line), "%s has joined the chat.\n", nickname);
	if (sendto(sendfd, line, strlen(line), 0, sadest, salen) < 0)
		fprintf(stderr, "sendto() error : %s\n", strerror(errno));

	for (;;) {

	ponow:

		fgets(pom, MAXLINE, stdin);
		if (strlen(pom) < 2) {
			goto ponow;
		}

		snprintf(line, sizeof(line), "%s: %s", nickname, pom);
		snprintf(exit, sizeof(exit), "%s: exit%c", nickname, 10);

		if (strcmp(line, exit) == 0) {				// Jesli wpiszemy exit, opuszczamy rozmowe

			printf("\033[1;31m");
			printf("\nLeaving conversation...\n");
			printf("\033[0m");

			snprintf(line, sizeof(line), "%s has left the chat.\n", nickname);
			if (sendto(sendfd, line, strlen(line), 0, sadest, salen) < 0)
				fprintf(stderr, "sendto() error : %s\n", strerror(errno));

			return -1;

		}

		if (sendto(sendfd, line, strlen(line), 0, sadest, salen) < 0)
			fprintf(stderr, "sendto() error : %s\n", strerror(errno));
		sleep(SENDRATE);
	}
}

void recv_all(int recvfd, socklen_t salen)			// Odbieranie wiadomosci z adresu multicast
{
	int					n;
	char				line[MAXLINE + 1];
	socklen_t			len;
	struct sockaddr* safrom;
	char str[128];
	struct sockaddr_in6* cliaddr;
	struct sockaddr_in* cliaddrv4;
	char			addr_str[INET6_ADDRSTRLEN + 1];

	safrom = malloc(salen);

	for (;;) {
		len = salen;
		if ((n = recvfrom(recvfd, line, MAXLINE, 0, safrom, &len)) < 0)
			perror("recvfrom() error");

		line[n] = 0;	/* null terminate */

		if (safrom->sa_family == AF_INET6) {
			cliaddr = (struct sockaddr_in6*)safrom;
			inet_ntop(AF_INET6, (struct sockaddr*)&cliaddr->sin6_addr, addr_str, sizeof(addr_str));
		}
		else {
			cliaddrv4 = (struct sockaddr_in*)safrom;
			inet_ntop(AF_INET, (struct sockaddr*)&cliaddrv4->sin_addr, addr_str, sizeof(addr_str));
		}

		printf("%s", line);

		fflush(stdout);

	}

}

int send_priv(int sendfd, int recvfd, SA* sadest, socklen_t salen) {		// Wysylanie SCTP - prywatny chat
	char		line[MAXLINE];		/* hostname and process ID */
	char 	pom[MAXLINE];
	char	exit[MAXLINE];


	snprintf(line, sizeof(line), "%s has joined the chat.\n", nickname);
	if (sctp_sendmsg(sendfd, line, strlen(line), sadest, salen, 0, 0, 1, 0, 0) < 0) {
		fprintf(stderr, "sctp_sendmsg error : %s\n", strerror(errno));
		return -1;
	}

	for (;;) {

	ponow:

		fgets(pom, MAXLINE, stdin);
		if (strlen(pom) < 2) {
			goto ponow;
		}

		snprintf(line, sizeof(line), "%s: %s", nickname, pom);
		snprintf(exit, sizeof(exit), "%s: exit%c", nickname, 10);

		if (strcmp(line, exit) == 0) {			// Jesli wpiszemy exit, opuszczamy rozmowe

			printf("\033[1;31m");
			printf("\nLeaving conversation...\n");
			printf("\033[0m");

			snprintf(line, sizeof(line), "%s has left the chat.\n", nickname);
			if (sctp_sendmsg(sendfd, line, strlen(line), sadest, salen, 0, 0, 1, 0, 0) < 0) {
				fprintf(stderr, "sctp_sendmsg error : %s\n", strerror(errno));
				return -1;
			}
			return -1;
		}

		if (sctp_sendmsg(sendfd, line, strlen(line), sadest, salen, 0, 0, 1, 0, 0) < 0) {
			fprintf(stderr, "sctp_sendmsg error : %s\n", strerror(errno));
			return -1;
		}
		sleep(SENDRATE);
	}


}

void recv_priv(int recvfd, socklen_t salen) {			// Odbieranie SCTP - prywatny chat

	int					n;
	char				line[MAXLINE + 1];
	socklen_t			len;
	struct sockaddr* safrom;
	struct sockaddr_in6* cliaddr;
	struct sockaddr_in* cliaddrv4;
	char			addr_str[INET6_ADDRSTRLEN + 1];
	struct sctp_sndrcvinfo sri;

	safrom = malloc(salen);

	for (;;) {
		len = salen;
		if ((n = sctp_recvmsg(recvfd, line, MAXLINE, safrom, &len, &sri, 0)) < 0)
			perror("recvfrom() error");

		line[n] = 0;	/* null terminate */

		if (safrom->sa_family == AF_INET6) {
			cliaddr = (struct sockaddr_in6*)safrom;
			inet_ntop(AF_INET6, (struct sockaddr*)&cliaddr->sin6_addr, addr_str, sizeof(addr_str));
		}
		else {
			cliaddrv4 = (struct sockaddr_in*)safrom;
			inet_ntop(AF_INET, (struct sockaddr*)&cliaddrv4->sin_addr, addr_str, sizeof(addr_str));
		}

		printf("%s", line);

		fflush(stdout);

	}

}


int main(int argc, char** argv)
{
	int sendfd, recvfd;
	socklen_t salen;
	struct sockaddr* sasend, * sarecv;
	pid_t c_pid;
	const char* ip_multicast;
	ip_multicast = "224.1.1.1";
	char ip_useraddr[MAXLINE];
	const char* ief;
	ief = "enp0s8";

	signal(SIGCHLD, sig_chld);		//obs³uga sigchld

	if (argc != 2) {
		fprintf(stderr, "usage: %s <nickname> \n", argv[0]);
		return 1;
	}

	nickname = argv[1];
	int wybor;
	printf("\033[1;36m"); 
	printf("\nWelcome %s!", nickname);
	printf("\033[0m");

powrot:
	printf("\n\n1 - Connect to private chat\n2 - Join to group chat\n3 - Exit\n\n");
	scanf("%d", &wybor);

	switch (wybor) {
	case 1:					// Prywatny chat

		printf("\nEnter user IP address: ");
		scanf("%s", ip_useraddr);
		char* ip_user = ip_useraddr;

		// sprawdzanie adresu IPV4

		unsigned char test[sizeof(struct in_addr)];
		while (inet_pton(AF_INET, ip_user, test) <= 0) {

			printf("\nWrong adress family. Enter user IP address: ");
			scanf("%s", ip_useraddr);

			ip_user = ip_useraddr;

		}
		printf("\n%s\n", ip_user);

		sendfd = snd_sctp_socket(ip_user, 1243, &sasend, &salen);		// tworzenie gniazd
		recvfd = rcv_sctp_socket(sasend, &sarecv, &salen);

		setsockopt(sendfd, SOL_SOCKET, SO_BINDTODEVICE, ief, strlen(ief));	//przypisanie interfejsu do gniazda
		setsockopt(recvfd, SOL_SOCKET, SO_BINDTODEVICE, ief, strlen(ief));

		struct sockaddr_in servaddr;
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		servaddr.sin_port = htons(1243);


		if (bind(recvfd, (SA*)&servaddr, sizeof(servaddr)) < 0) {
			fprintf(stderr, "bind error : %s\n", strerror(errno));
			return 1;
		}
		if (listen(recvfd, 2) == -1) {
			fprintf(stderr, "listen error : %s\n", strerror(errno));
			return 1;
		}
		printf("\033[1;32m");
		printf("\nConnected to private chat. Remember the rules of netiquette :)\nType 'exit' to leave\n\n");
		printf("\033[0m");
		break;

	case 2:			// Grupowy chat

		sendfd = snd_udp_socket(ip_multicast, 1234, &sasend, &salen);
		recvfd = rcv_udp_socket(ip_multicast, sendfd, sasend, &sarecv, &salen);

		sarecv = malloc(salen);
		memcpy(sarecv, sasend, salen);

		setsockopt(sendfd, SOL_SOCKET, SO_BINDTODEVICE, ief, strlen(ief));

		if (bind(recvfd, sarecv, salen) < 0) {
			fprintf(stderr, "bind error : %s\n", strerror(errno));
			return 1;
		}

		if (mcast_join(recvfd, sasend, salen, ief, 0) < 0) {
			fprintf(stderr, "mcast_join() error : %s\n", strerror(errno));
			return 1;

		}

		mcast_set_loop(sendfd, 0);
		printf("\033[1;32m");
		printf("\nConnected to group chat. Remember the rules of netiquette :)\nType 'exit' to leave\n\n");
		printf("\033[0m");

		break;

	case 3:
		printf("\033[1;36m");
		printf("\nSee you soon %s!\n\n", nickname);
		printf("\033[0m");
		return 0;
	default:
		goto powrot;
	}


	c_pid = fork();

	if (c_pid == 0)			/* child -> receives */
		if (wybor == 2) {
			recv_all(recvfd, salen);	
		}
		else
			recv_priv(recvfd, salen);
			
	
	while (1) {			/* parent -> sends */
		if (wybor == 2) {
			if ((send_all(sendfd, recvfd, sasend, salen)) < 0) {		
		
				kill(c_pid, SIGTERM);

				close(sendfd);
				close(recvfd);

				goto powrot;
			}
		}
		else {

			if ((send_priv(sendfd, recvfd, sasend, salen)) < 0) {

				kill(c_pid, SIGTERM);

				close(sendfd);
				close(recvfd);

				goto powrot;
			}
		}


	}
}
