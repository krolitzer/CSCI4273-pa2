#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RSA_SERVER_CERT "server.cert"
#define RSA_SERVER_PRIV "server_priv.key"
#define	QLEN		  32	/* maximum connection queue length	*/
#define	BUFSIZE		4096
#define PORTS 50


extern int	errno;
int		errexit(const char *format, ...);
int		passivesock(const char *portnum, int qlen);
int		echo(SSL* fd);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char	*portnum = "5004";	/* Standard server port number	*/
	struct sockaddr_in fsin;	/* the from address of a client	*/
	int	msock;			/* master server socket		*/
	fd_set	rfds;			/* read file descriptor set	*/
	fd_set	afds;			/* active file descriptor set	*/
	unsigned int	alen;		/* from-address length		*/
	int	fd, nfds;
	SSL_CTX *ctx;
	SSL *ssl;
	SSL *sslSessions[PORTS];

	switch (argc) {
	case	1:
		break;
	case	2:
		portnum = argv[1];
		break;
	default:
		errexit("usage: TCPmechod [port]\n");
	}
	SSL_library_init();
	SSL_load_error_strings();
	const SSL_METHOD *meth = SSLv3_method();
	ctx = SSL_CTX_new(meth);
	
	if(SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT,SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Loading Certificate Failed\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if(SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_PRIV, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Loading private key failed\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if(!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key doesn't match\n");
		exit(1);
	}

	msock = passivesock(portnum, QLEN);

	nfds = getdtablesize();
	FD_ZERO(&afds);
	FD_SET(msock, &afds);

	while (1) {
		memcpy(&rfds, &afds, sizeof(rfds));
		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0,
				(struct timeval *)0) < 0)
			errexit("select: %s\n", strerror(errno));
		if (FD_ISSET(msock, &rfds)) {
			int	ssock;

			alen = sizeof(fsin);
			ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
			sslSessions[ssock] = SSL_new(ctx);
			SSL_set_fd(sslSessions[ssock], ssock);

			if (ssock < 0)
				errexit("accept: %s\n", strerror(errno));

			FD_SET(ssock, &afds);
			
			int er = SSL_accept(sslSessions[ssock]);
			if ((er)==-1) { ERR_print_errors_fp(stderr); exit(1); }

		}
		for (fd=0; fd<nfds; ++fd) {
			if (fd != msock && FD_ISSET(fd, &rfds)) {
				if (echo(sslSessions[fd]) == 0) {
					(void) close(fd);
					FD_CLR(fd, &afds);
				}
			}
		}
	}
	return 0;
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int
echo(SSL* fd)
{
	char	buf[BUFSIZ];
	int	cc;
	cc = SSL_read(fd, buf, sizeof buf);
	if (cc < 0)
		errexit("echo read: %s\n", strerror(errno));
	if (cc && SSL_write(fd, buf, cc) < 0)
		errexit("echo write: %s\n", strerror(errno));
	return cc;
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int
errexit(const char *format, ...)
{
        va_list args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}

/*------------------------------------------------------------------------
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int
passivesock(const char *portnum, int qlen)
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
{
        struct sockaddr_in sin; /* an Internet endpoint address  */
        int     s;              /* socket descriptor             */

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;

    /* Map port number (char string) to port number (int) */
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
            errexit("can't create socket: %s\n", strerror(errno));

    /* Bind the socket */
        if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
                portnum, strerror(errno));
            sin.sin_port=htons(0); /* request a port number to be allocated
                                   by bind */
            if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't bind: %s\n", strerror(errno));
            else {
                socklen_t socklen = sizeof(sin);

                if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
                        errexit("getsockname: %s\n", strerror(errno));
                printf("New server port number is %d\n", ntohs(sin.sin_port));
            }
        }

        if (listen(s, qlen) < 0)
            errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
        return s;
}

