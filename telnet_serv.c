#include        <sys/types.h>   /* basic system data types */
#include        <sys/socket.h>  /* basic socket definitions */
#include        <sys/time.h>    /* timeval{} for select() */
#include        <time.h>                /* timespec{} for pselect() */
#include        <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include        <arpa/inet.h>   /* inet(3) functions */
#include        <errno.h>
#include        <fcntl.h>               /* for nonblocking */
#include        <netdb.h>
#include        <signal.h>
#include        <stdio.h>
#include        <stdlib.h>
#include        <string.h>
#include	<limits.h>		/* for OPEN_MAX */
#include 	<poll.h>
#include 	<unistd.h>
 
#define MAXLINE 1024
#define SA struct sockaddr
#define LISTENQ 2
#define INFTIM -1
#define BUFSIZE 128

typedef enum {COMMAND, AUTH, RESPONSE} msgtype;

char* extractmsg(msgtype type, char buff[MAXLINE], size_t nbytes){
    char* startpattern; 
    char* endpattern;
    int startlen = 0;
    int endlen = 0;
    
    switch(type){
        case COMMAND:
            startpattern = malloc(strlen("|COMMAND-START|"));
            startpattern = "|COMMAND-START|";
            endpattern = malloc(strlen("|COMMAND-END|"));
            endpattern = "|COMMAND-END|";
            break;
    }
    
    char* target = NULL;
    char* start;
    char* end;
    
    if(start = strstr(buff, startpattern)){
        start += strlen(startpattern);
        if(end = strstr(buff, endpattern)){
            target = (char*)malloc(end-start+1);
            memcpy(target, start, end-start);
            target[end-start] = '\0';
        }
    }
    if(target){
        return target;
    }
    return NULL;
}

char* preparemsg(msgtype type, char buff[MAXLINE], size_t nbytes){
    char* target = NULL;
    char* start = NULL;
    char* end = NULL;
    size_t startlen, endlen;
    
    switch(type){
        case RESPONSE:
            startlen = strlen("|RESPONSE-START|");
            endlen = strlen("|RESPONSE-END|");
            target = malloc(startlen + nbytes + endlen + 1);
            memcpy(target, "|RESPONSE-START|", startlen);
            memcpy(target + startlen, buff, nbytes);
            memcpy(target + startlen + nbytes, "|RESPONSE-END|", endlen);
            break;
    }
    return target;
}

ssize_t						/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
        /*
        ssize_t write(int fd, const void *buf, size_t count);
        
        write() writes up to count bytes from the buffer starting at buf to the file referred to by the file descriptor fd.
        On success, the number of bytes written is returned.  
        On error, -1 is returned, and errno is set to indicate the error. */
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
            /* A return value of EINTR means that the function was interrupted by a signal before the function could finish its normal job. */
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}
/* end writen */

void
Writen(int fd, void *ptr, size_t nbytes)
{
	if (writen(fd, ptr, nbytes) != nbytes)
		perror("writen error");
}

int authenticate(msgtype type, int fd, char buff[MAXLINE], size_t nbytes){
    char* target = NULL;
    char* start = NULL;
    char* end = NULL;
    size_t startlen, endlen;
    ssize_t nwritten;
    
    switch(type){
        case AUTH:
            startlen = strlen("|AUTH-START|");
            endlen = strlen("|AUTH-END|");
            target = malloc(startlen + nbytes + endlen + 1);
            memcpy(target, "|AUTH-START|", startlen);
            memcpy(target + startlen, buff, nbytes);
            memcpy(target + startlen + nbytes, "|AUTH-END|", endlen);
            break;
    }
    printf("\nResponse: %s\n", target);
    if ( (nwritten = write(fd, target, strlen(target))) <= 0) {
        if (nwritten < 0 && errno == EINTR)
            nwritten = 0;
        else
            return(-1);
    }
    return 0;
}

int parse_output(int fd, char buff[MAXLINE], size_t nbytes) {
    printf("\nBuff: %s\n", buff);
    char* msg = extractmsg(COMMAND, buff, nbytes);
    msg[strlen(msg)-1] = '\0';
    /*char data[1024];
    FILE * stream;
    const int max_buffer = 1024;
    char buffer[max_buffer];
    cmd.append(" 2>&1");

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
        pclose(stream);
    }*/
    
    
    
    char* cmd = malloc(strlen(msg)+strlen(msg)+strlen(" 2>&1"));
    memcpy(cmd, msg, strlen(msg));
    memcpy(cmd+strlen(msg), " 2>&1", strlen(" 2>&1"));
    printf("\nCommand: %s\n", cmd);
    
    char buf[BUFSIZE];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    char* res = malloc(MAXLINE);
    char* response = malloc(MAXLINE);
    while (fgets(buf, BUFSIZE, fp) != NULL) {
        printf("Command output: %s", buf);
        strcat(res, buf);
    }
    response = preparemsg(RESPONSE, res, strlen(res));
    Writen(fd, response, strlen(response));
    
    if (pclose(fp)) {
        //printf("Command not found or exited with error status\n");
        return -1;
    }
    
    //char* x = system("ls");
    //printf("\n------\nOutput: %s\n------\n",x);
    
    return 0;
}

int login(int fd, char buff[MAXLINE], size_t nbytes) {
	char* msg = buff;
    
    char* startpattern;
    char* passpattern; 
    char* endpattern;
    int startlen = 0, passlen = 0, endlen = 0;
    
    startpattern = malloc(strlen("|LOGIN-START|"));
    passpattern = malloc(strlen("|PASSWORD-START|"));
    endpattern = malloc(strlen("|LOGIN-END|"));
    
    startpattern = "|LOGIN-START|";
    passpattern = "|PASSWORD-START|";
    endpattern = "|LOGIN-END|";
    
    char* login = NULL;
    char* start, *end;
    
    if(start = strstr(buff, startpattern)){
        start += strlen(startpattern);
        if(end = strstr(buff, passpattern)){
            login = (char*)malloc(end-start+1);
            memcpy(login, start, end-start);
            login[end-start] = '\0';
        }
    }
    
    char* password = NULL;
    
    if(start = strstr(buff, passpattern)){
        start += strlen(passpattern);
        if(end = strstr(buff, endpattern)){
            password = (char*)malloc(end-start+1);
            memcpy(password, start, end-start);
            password[end-start-1] = '\0';
        }
    }
    
    printf("\nReceived login: %s\n", login);
    printf("\nReceived password: %s\n", password);
    
    /*size_t command_len1 = strlen("echo \'");
    size_t command_len2 = strlen("\' 2>&1");
    size_t command_len3 = strlen(" | su ");
    size_t loginlen = strlen(login);
    size_t passwordlen = strlen(password);
    
    char* command = malloc(command_len1 + command_len2 + command_len3 + loginlen + passwordlen);
    memcpy(command, "echo \'", command_len1);
    memcpy(command + command_len1, password, passwordlen);
    memcpy(command + command_len1 + passwordlen, "\' 2>&1", command_len2);
    memcpy(command + command_len1 + passwordlen + command_len2, " | su ", command_len3);
    memcpy(command + command_len1 + passwordlen + command_len2 + command_len3, login, loginlen);*/
    
    /*int i = 0; while(i < strlen(password)){ printf("(%d)", password[i]); i=i+1;}
    printf("\nPAAWORD: %d\n", strcmp(password,"a"));*/

    if(strcmp(login,"olcia") == 0 && strcmp(password ,"haslo") == 0){
        int res = authenticate(AUTH, fd, "OK", strlen("OK"));
        return 1;
    }
    else{
        int res = authenticate(AUTH, fd, "INCORRECT", strlen("INCORRECT"));
        return 0;
    }
    
    //command(strlen(command)-1) = "\0";
    //printf("\ncommand: [%s]\n", command);
    
    /*printf("%c -> %d\n", command[strlen(command)-5]);
    printf("%c -> %d\n", command[strlen(command)-4]);
    printf("%c -> %d\n", command[strlen(command)-3]);
    printf("%c -> %d\n", command[strlen(command)-2]);
    printf("%c -> %d\n", command[strlen(command)-1]);
    printf("%c -> %d\n", command[strlen(command)]);
     
	char cbuf[BUFSIZE];
    FILE *fp;

    if ((fp = popen(command, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    while (fgets(cbuf, BUFSIZE, fp) != NULL) {
        Writen(fd, cbuf, strlen(cbuf));
        printf("%s", cbuf);
    }

    if (pclose(fp)) {
        printf("Incorrect login\n");
        return -1;
    }*/
}

int
main(int argc, char **argv)
{
	int		listenfd, connfd, sockfd;
	pid_t		childpid;
	socklen_t	clilen;
	struct sockaddr_in6	cliaddr, servaddr;
	void		sig_chld(int);
	int		i, maxi, maxfd, n; 
	int		nready;
	char 		buf[MAXLINE], addr_buf[INET6_ADDRSTRLEN+1];
	struct pollfd	client[FOPEN_MAX];
	int auth[FOPEN_MAX] = {0};

    /*
    int socket(int domain, int type, int protocol);
    socket() creates an endpoint for communication and returns a file descriptor that refers to that endpoint.
    
     SOCK_STREAM - Provides sequenced, reliable, two-way, connection-based byte streams.  An out-of-band data transmission mechanism may be supported.
     
     Normally only a single protocol exists to support a particular socket type within a given protocol family, in which case protocol can be specified as 0.
     
     On success, a file descriptor for the new socket is returned. 
     On error, -1 is returned, and errno is set to indicate the error.
     */
	if ( (listenfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0){
	       fprintf(stderr,"socket error : %s\n", strerror(errno));
	       return 1;
	}


	bzero(&servaddr, sizeof(servaddr));
    /*
     The bzero() function erases the data in the n bytes of the memory starting at the location pointed to by s, by writing zeros (bytes containing '\0') to that area.
 
    */
	servaddr.sin6_family = AF_INET6;
    /*
    The AF_INET6 address family is the address family for IPv6
    */
	servaddr.sin6_addr   = in6addr_any;
    /*
    If you set this field to the constant in6addr_any, the socket is bound to all network interfaces on the host.
    */
	servaddr.sin6_port   = htons(2323);	
    /* The htons() function converts the unsigned short integer from host byte order to network byte order.  */

    /*
    When a socket is created with socket(), it exists in a name space (address family) but has no address assigned to it.  
    
    bind() assigns the address specified by addr to the socket referred to by the file descriptor sockfd.  addrlen specifies the size, in bytes, of the address structure pointed to by addr. 
    */
	if ( bind( listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
	        fprintf(stderr,"bind error : %s\n", strerror(errno));
	        return 1;
	}
	
	/*
    int listen(int sockfd, int backlog);
    listen() marks the socket referred to by sockfd as a passive socket, that is, as a socket that will be used to accept incoming connection requests using accept(2).
    The sockfd argument is a file descriptor that refers to a socket of type SOCK_STREAM or SOCK_SEQPACKET. The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.
    */
	if ( listen(listenfd, LISTENQ) < 0){
	        fprintf(stderr,"listen error : %s\n", strerror(errno));
	        return 1;
	}

	client[0].fd = listenfd;
	client[0].events = POLLIN; /* POLLIN There is data to read */
	for (i = 1; i < FOPEN_MAX; i++)
		client[i].fd = -1;		/* -1 indicates available entry */
	maxi = 0;					/* max index into client[] array */

	for ( ; ; ) {
        /*
         int poll(struct pollfd *fds, nfds_t nfds, int timeout);
         
         poll - wait for some event on a file descriptor.  poll() performs a similar task to select(2): it waits for one of
         a set of file descriptors to become ready to perform I/O

        The set of file descriptors to be monitored is specified in the
        fds argument. 
        The caller should specify the number of items in the fds array in nfds.
        The timeout argument specifies the number of milliseconds that
        poll() should block waiting for a file descriptor to become
        ready.
        
        */
		if ( (nready = poll(client, maxi+1, INFTIM)) < 0){
				perror("poll error");
				exit(1); 					//change to something more intelligent
		}
		if (client[0].revents & POLLIN) {	/* new client connection */
			clilen = sizeof(cliaddr);
        /*
        int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen); 
        The accept() system call is used with connection-based socket        types (SOCK_STREAM, SOCK_SEQPACKET).  It extracts the first
        connection request on the queue of pending connections for the
        listening socket, sockfd, creates a new connected socket, and
        returns a new file descriptor referring to that socket.  The
        newly created socket is not in the listening state. 
        On success, these system calls return a file descriptor for the
        accepted socket (a nonnegative integer).  On error, -1 is
        returned, errno is set to indicate the error, and addrlen is  left unchanged.
        */
		if ( (connfd = accept(listenfd, (SA *) &cliaddr, &clilen)) < 0) {
				perror("accept error");
				exit(1);
		}


		bzero(addr_buf, sizeof(addr_buf));
	   	inet_ntop(AF_INET6, (struct sockaddr  *) &cliaddr.sin6_addr,  addr_buf, sizeof(addr_buf));
			printf("new client: %s, port %d\n",	addr_buf, ntohs(cliaddr.sin6_port));

			for (i = 1; i < FOPEN_MAX; i++)
				if (client[i].fd < 0) {
					client[i].fd = connfd;	/* save descriptor */
					break;
				}
			if (i == FOPEN_MAX){
				perror("too many clients");
				continue;
			}

			client[i].events = POLLIN;
			if (i > maxi)
				maxi = i;				/* max index in client[] array */

			if (--nready <= 0)
				continue;				/* no more readable descriptors */
		}

		for (i = 1; i <= maxi; i++) {	/* check all clients for data */
			if ( (sockfd = client[i].fd) < 0)
				continue;
			if (client[i].revents & (POLLIN | POLLERR)) {
                /*
                 POLLIN There is data to read.
                 POLLERR Error condition
                 
                 & Binary AND Operator copies a bit to the result if it exists in both operands. 
                 */
				if ( (n = read(sockfd, buf, MAXLINE)) < 0) {
					if (errno == ECONNRESET) {
							/*connection reset by client */
						printf("client[%d] aborted connection\n", i);
						close(sockfd);
						client[i].fd = -1;
						auth[i] = 0;
					} else{
						perror("read error");
						exit(1);
					}
				} else if (n == 0) {
						/*connection closed by client */
					printf("client[%d] closed connection\n", i);
					close(sockfd);
					client[i].fd = -1;
					auth[i] = 0;
				} else{
					printf("%d", auth[i]);
					if(auth[i] == 0){
						int success = login(sockfd, buf, n);
                        if(success == 1){
                            auth[i] = 1;
                        }
                        else{
                            perror("\nincorrect login/password\n");
                            
                            break;
                        }
					}
					else{
						parse_output(sockfd, buf, n);
					}
					// printf("%s", buf);
				}

				if (--nready <= 0)
					break;				/* no more readable descriptors */
			}
		}
	}
}
