//
// Created by sean on 4/15/19.
//

//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <jmorecfg.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <zconf.h>
#include <time.h>

#define STARTMSG "START GAME\n"
#define POSITIONMSG "POSITIONING SHIPS\n"
#define INPOSITIONMSG "SHIPS IN POSITION\n"
#define HITMSG "HIT\n"
#define MISSMSG "MISS\n"
#define EXITMSG "EXIT\n"
#define PORT 8080
#define MAX 80

#define FAIL    -1


int length = 0;
int board[9][9];
int numShots = 0;
int shipPlaced;
char buff[MAX];

/// check for a win !!!

int scanBoard() {
    int result = 1;
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++)
            if (board[i][j] != 0) {
                result = 0;
            }
    }
    return result;
}


/// check a shot for a hit or a miss and update the board
int shoot() {
    {
        int row = buff[0] - 64 - 1; // convert uppercase letter to row
        int col = buff[1] - '0' - 1;
        if (board[col][row] > 0) {
            board[col][row] = 0;
            printf("\nHIT");
            return 1;
        } else {
            printf("\nMISS");
            return 2;
        }
    }


}


/***
 * 0 is waiting for client to press start
 * 1 is waiting for positioning ships
 * 2 is waiting for ships in position
 * 3 is waiting for shots
 *    shot received,  hit , miss
 * 4 is game is over
 *
 */

void printBoard() {
    printf("\nBOARD");
    printf("\n");
    {
        printf("\n* A B C D E F G H I");
    }
    for (int i = 0; i < 9; i++) {
        printf("\n%d", i + 1);
        for (int j = 0; j < 9; j++) {
            printf(" %d", board[i][j]);
        }

    }
}


/// check an incoming message for it's type
int getMessageType(char array[]) {


    length = strlen(array);

    char c = array[0];
    char d = array[1];

    if (array[0] == '\0') { return 9; }

    else if (strcmp(array, STARTMSG) == 0) {
        printf("\nserver found It's a start message");
        return 1;
    } else if (strcmp(array, EXITMSG) == 0) {
        printf("\nserver found It's an exit message");
        return 8;
    } else if ((d >= '1' & d <= '9') & (c >= 'A' & c <= 'J') & (length < 4)) {
        printf("\nserver found It's a shot message");
        return 6;

    } else if (strcmp(array, "") == 0) {
        return 9;
    } else { return -1; }
}


/// set board to empty
void initializeBoard() {

    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            board[i][j] = 0;

        }
    }

}


/// stick a ship on the board
/// returns a one when finished
int placeShip(int size) {
    int result = 0;
    int direction = rand() & 1; // 0 is vertical 1 is horizontal
    /// horizontal is a row
    /// [row][columns]
    /// a horizontal row is represented by [x][0] [x][1] [x][2] [x][3] ..
    /// a vertical column is represented by [0][y] [1][y] [2][y]
    int rowColNumber = rand() % 9; // generate random row or column number
    int pos = rand() % 9; // generate random position

    /// if it's horizontal check the row for space
    if (direction == 1) {
        /// if row doesn't have space for ship beyond position reset
        if ((8 - pos) < size) {
            pos = 8 - size;
        }
        /// check for free space
        int freeSpace = 0;
        for (int j = 0; j < size; j++) {
            freeSpace = freeSpace + board[rowColNumber][pos + j];
        }  /// if there is enough space then place ship
        if (freeSpace == 0) {
            for (int j = 0; j < size; j++) {
                board[rowColNumber][pos + j] = size;
            }
            result = 1; /// ship has been placed

        }
    }

    /// if it's vertical check the column for space
    if (direction == 0) {
        /// if column doesn't have space for ship beyond position reset
        if ((8 - pos) < size) {
            pos = 8 - size;
        }
        int freeSpace = 0;
        for (int j = 0; j < size; j++) {
            freeSpace = freeSpace + board[pos + j][rowColNumber];
        }  /// if there is enough space then place ship
        if (freeSpace == 0) {
            for (int j = 0; j < size; j++) {
                board[pos + j][rowColNumber] = size;
            }
            result = 1; /// ship has been placed

        }
    }

    return result;
}



/*** OPEN SSL FUNCTIONS ***/




int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}


SSL_CTX* InitServerCTX(void)
{   const SSL_METHOD *method;  // added "const" to remove build error
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    // method = TLSv1_2_server_method();  /* create new server-method instance */ -- depreciated
    method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}


void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char reply[80];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);        /* get any certificates */

        ///*** processing loop ///

        ///while(1) {
        ///    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        ///    if (bytes > 0) {
        ///        buf[bytes] = 0;
        ///        printf("Client msg: \"%s\"\n", buf);
        ///        sprintf(reply, HTMLecho, buf);   /* construct reply */
        ///        SSL_write(ssl, reply, strlen(reply)); /* send reply */
        ///    } else
        ///        ERR_print_errors_fp(stderr);

        while (1) {
            bzero(buff, MAX);

            // read the message from client and copy it in buffer
            ///read(sockfd, buff, sizeof(buff));
            bytes = SSL_read(ssl, buff, sizeof(buff)); /* get request */
            // print buffer which contains the client contents
            int type = getMessageType(buff);
            printf("From client: %s\t To client : ", buff);


            if (type == 8 || type < 0) {
                printf("Server Exit...\n");

                char die[] = EXITMSG;
                //write(sockfd, die, sizeof(die));
                SSL_write(ssl, die, strlen(die)); /* send reply */

                break;
            }

                /// if we recieve a start message set the board up
            else if (type == 1) {

                srand(time(0));
                printf("\ninitializing board");
                printBoard();
                char response[] = POSITIONMSG;
                // write(sockfd, response, sizeof(response));
                SSL_write(ssl, reply, strlen(reply)); /* send reply */

                bzero(buff, MAX);
                for (int i = 2; i < 6; i++) {
                    shipPlaced = 0;
                    // place a ship of size 2
                    while (shipPlaced == 0) {
                        shipPlaced = placeShip(i);
                    }
                }


                printf("\nboard finished\n");
                sleep(1); /// maybe this helps the program not hanging when the client doesnt loop back fast enough
                char response2[] = INPOSITIONMSG;
                //write(sockfd, response2, sizeof(response2));
                SSL_write(ssl, response2, strlen(response2)); /* send reply */
                bzero(buff, MAX);

            }


                /// if we recieve a shot message deal with it
            else if (type == 6) {

                printf("\nchecking shot\n");
                int shot = shoot();

                if (shot == 1) {
                    numShots++;
                    int win = scanBoard();
                    if (win == 1) {
                        numShots++;
                        char response6[MAX];
                        sprintf(response6, "%d", numShots);

                        printf("You WIN ...\n");

                        // write(sockfd, response6, sizeof(response6));
                        SSL_write(ssl, response6, strlen(response6)); /* send reply */
                        printf("Server Exit...\n");


                    }
                    char response3[] = HITMSG;
                    //write(sockfd, response3, sizeof(response3));
                    SSL_write(ssl, response3, strlen(response3)); /* send reply */
                    printBoard();
                } else if (shot == 2) {
                    numShots++;
                    char response2[] = MISSMSG;
                    //write(sockfd, response2, sizeof(response2));
                    SSL_write(ssl, response2, strlen(response2)); /* send reply */
                    printBoard();
                } else {
                    printf("Server Exit...\n");
                    char die[] = EXITMSG;
                    ///write(sockfd, die, sizeof(die));
                    SSL_write(ssl, die, strlen(die)); /* send reply */

                }

            }

            bzero(buff, sizeof(buff));

        }

    }


sd = SSL_get_fd(ssl);       /* get socket connection */
SSL_free(ssl);         /* release SSL state */
close(sd);          /* close connection */
}

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *portnum;
    initializeBoard();


    /***
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
     **/
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();

    portnum = strings[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    //SSL *ssl;

    int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
    printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    ssl = SSL_new(ctx);              /* get new SSL state with context */
    SSL_set_fd(ssl, client);/* set connection socket to SSL state */


    /*** processing */

    Servlet(ssl); //service connection */

    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}


