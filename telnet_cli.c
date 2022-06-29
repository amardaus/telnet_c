//#include	"unp.h"
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
#include 		<unistd.h>

#define MAXLINE 1024
#define SA      struct sockaddr

typedef enum {COMMAND, RESPONSE} msgtype;

char* extractmsg(msgtype type, char buff[MAXLINE], size_t nbytes){
    char* startpattern; 
    char* endpattern;
    int startlen = 0;
    int endlen = 0;
    
    switch(type){
        case RESPONSE:
            startpattern = malloc(strlen("|RESPONSE-START|"));
            startpattern = "|RESPONSE-START|";
            endpattern = malloc(strlen("|RESPONSE-END|"));
            endpattern = "|RESPONSE-END|";
            break;
    }
    
    char* target = NULL;
    char* start;
    char* end;
    
    int i = 0;
    
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

char *
Fgets(char *ptr, int n, FILE *stream)
{
	char	*rptr;

    /*
    fgets(char *str, int n, FILE *stream) reads a line from the specified stream and stores it into the string pointed to by str. 
    It stops when either (n-1) characters are read, the newline character is read, or the end-of-file is reached, whichever comes first.
    */
	if ( (rptr = fgets(ptr, n, stream)) == NULL && ferror(stream))
		perror("fgets error");

	return (rptr);
}

void
Fputs(const char *ptr, FILE *stream)
{
	if (fputs(ptr, stream) == EOF)
		perror("fputs error");
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
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
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
    //printf("[WRITING: %s]", ptr);
	if (writen(fd, ptr, nbytes) != nbytes)
		perror("writen error");
}

char* preparemsg(msgtype type, char buff[MAXLINE], size_t nbytes){
    char* target = NULL;
    char* start = NULL;
    char* end = NULL;
    size_t startlen, endlen;
    
    switch(type){
        case COMMAND:
            startlen = strlen("|COMMAND-START|");
            endlen = strlen("|COMMAND-END|");
            target = malloc(startlen + nbytes + endlen + 1);
            memcpy(target, "|COMMAND-START|", startlen);
            memcpy(target + startlen, buff, nbytes);
            memcpy(target + startlen + nbytes, "|COMMAND-END|", endlen);
            break;
    }
    return target;
}

char* preparelogin(char lbuff[MAXLINE], char pbuff[MAXLINE], size_t lbytes, size_t pbytes){
    char* target = NULL;
    char* start = NULL;
    char* end = NULL;
    size_t startlen, passlen, endlen;
    
    startlen = strlen("|LOGIN-START|");
    passlen = strlen("|PASSWORD-START|");
    endlen = strlen("|LOGIN-END|");
    target = malloc(startlen + passlen + endlen + lbytes + pbytes + 1);
    memcpy(target, "|LOGIN-START|", startlen);
    memcpy(target + startlen, lbuff, lbytes);
    memcpy(target + startlen + lbytes, "|PASSWORD-START|", passlen);
    memcpy(target + startlen + lbytes + passlen, pbuff, pbytes);
    memcpy(target + startlen + lbytes + passlen + pbytes, "|LOGIN-END|", endlen);
    
    return target;
}

void
str_cli(FILE *fp, int sockfd, char ipaddr[MAXLINE])
{
	char sendline[MAXLINE], recvline[MAXLINE];
	int n;
	char loginline[MAXLINE], passwordline[MAXLINE];
    printf("\nLogin: ");
	Fgets(loginline, MAXLINE, fp);
    loginline[strlen(loginline)-1] = '\0';
    
	printf("Password: ");
	Fgets(passwordline, MAXLINE, fp);
	char* message = preparelogin(loginline, passwordline, strlen(loginline), strlen(passwordline));
	
	Writen(sockfd, message, strlen(message));
	
	if ((n=read(sockfd, recvline, MAXLINE)) == 0){
		perror("str_cli: server terminated prematurely");
		exit(0);
	}
	
	if(strstr(recvline, "|AUTH-START|OK|AUTH-END|") != NULL){
		printf("Authenctication successful\n");
        printf("\x1B[32m%s@%s$ \x1B[0m", loginline, ipaddr);
		while (Fgets(sendline, MAXLINE, fp) != NULL) {
            if(sendline[0] == '\n'){
                printf("\x1B[32m%s@%s$ \x1B[0m", loginline, ipaddr);
            }
            else{
                char* msg = preparemsg(COMMAND, sendline, strlen(sendline));
                //printf("\n--------\n%s\n--------\n", msg);
                Writen(sockfd, msg, strlen(msg));
                if ((n=read(sockfd, recvline, MAXLINE)) == 0){
                    perror("str_cli: server terminated prematurely");
                    exit(0);
                }
                //printf("\nReceived line: %s\n", recvline);
                char* response = extractmsg(RESPONSE,recvline,n);
                //printf("\nParsed line: %s\n", response);
                //Fputs(response, stdout);
                //recvline[n]=0;
                Fputs(response, stdout);
                printf("\x1B[32m%s@%s$ \x1B[0m", loginline, ipaddr);
            }
		}
	}
	else{
        printf("\033[31mIncorrect login or password\033[0m\n");
    }
	return;
}


int
main(int argc, char **argv)
{
	int					sockfd, n;
	struct sockaddr_in6	servaddr;
	char				recvline[MAXLINE + 1];

	if (argc != 2){
		fprintf(stderr, "usage: %s <IPaddress> \n", argv[0]);
		return 1;
	}
	if ( (sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0){
		fprintf(stderr,"socket error : %s\n", strerror(errno));
		return 1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_port   = htons(2323);	/* echo server */
	if (inet_pton(AF_INET6, argv[1], &servaddr.sin6_addr) <= 0){
		fprintf(stderr,"Address error: inet_pton error for %s : %s \n", argv[1], strerror(errno));
		return 1;
	}
	if (connect(sockfd, (SA *) &servaddr, sizeof(servaddr)) < 0){
		fprintf(stderr,"connect error : %s \n", strerror(errno));
		return 1;
	}

	str_cli(stdin, sockfd, argv[1]);
	fflush(stderr);

	exit(0);
}
