
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
#include <openssl/sha.h>

#define STARTMSG "START GAME\n"
#define POSITIONMSG "POSITIONING SHIPS\n"
#define INPOSITIONMSG "SHIPS IN POSITION\n"
#define HITMSG "HIT\n"
#define MISSMSG "MISS\n"
#define EXITMSG "EXIT\n"
#define OVERMSG "OVER\n"
#define WAITMSG "WAIT\n"

#define MAX 65

#define FAIL    -1


int length = 0;
int board[9][9]; // array to hold the board
int numShots = 0; // count of number of shots placed
int shipPlaced;
char buff[65]; // buffer for communication
int boardPositionsArray[12]; // array to hold board positions created
char boardPos[12]; // string representation of boardPositionsArray
char hashString[65]; // The board pos string converted into hash
int rowNumber;
int colNumber;
unsigned char hash[SHA256_DIGEST_LENGTH]; // hash of board position string
int killMe = 0;

/// function to convert board positions ( 12 integer representation of board ) into hash
// the hash uses sha256

void hasher() {

    size_t length = strlen(boardPos);
    SHA256(boardPos, length, hash);
    int i;
    printf("\nHash");
    printf("\n");

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    /// convert hash to string


    // convert hex version of hash to string
    static const char alphabet[] = "0123456789ABCDEF";

    for (int i = 0; i != 32; ++i) {
        hashString[2 * i] = alphabet[hash[i] / 16];
        hashString[2 * i + 1] = alphabet[hash[i] % 16];
    }
    hashString[64] = '\0';

    printf("\nHashString %s", hashString);
    int l = strlen(hashString);
    printf("\nHashString Length, %d", l);

    /// print the board positions values

    printf("\nBoard Position string");
    printf("\n%s", boardPos);

}

/// convert the integer array representation of board into a string
void setBoardPositions() {

    for (int i = 0; i < 12; i++) { boardPos[i] = boardPositionsArray[i] + '0'; }
    printf("\nBoard Position string in function");
    printf("\n%s", boardPos);

    ///

}

/// check what ships have been hit on the board
/// an empty board is all zeros and will return zero
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

    else if (strcmp(array, OVERMSG) == 0) {
        printf("\nserver found It's a game over message");
        return 7;
    } else if (strcmp(array, STARTMSG) == 0) {
        printf("\nserver found It's a start message");
        return 1;
    } else if (strcmp(array, EXITMSG) == 0) {
        printf("\nserver found It's an exit message");
        return 8;
    } else if ((d >= '1' & d <= '9') & (c >= 'A' & c <= 'J') & (length < 4)) {
        printf("\nserver found It's a shot message");
        return 6;

    }
    else if (strcmp(array, WAITMSG) == 0) {
        return 12; }
    else if (strcmp(array, "") == 0) {  // if message isn't correct type close connection
        return 9;
    } else { return -1; } // if message isn't correct type close connection
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
        rowNumber = rowColNumber;
        colNumber = pos;
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
            /// store ship position as a long
            /// use ship size to position in array
            /// 012 345 678 9 10 11
            ///  2   3   4    5
            /// in this section rowColNumber , pos , Direction
            /// 2 is zero,  3 is 3 , 4 is 6 , 5 is 9
            /// subtract size 2 and multiply by 3
            int shipName = (size - 2) * 3;
            /// set the 3 values
            boardPositionsArray[shipName] = rowNumber;
            boardPositionsArray[shipName + 1] = colNumber;
            boardPositionsArray[shipName + 2] = direction;


            result = 1; /// ship has been placed

        }
    }

    /// if it's vertical check the column for space
    if (direction == 0) {
        rowNumber = pos;
        colNumber = colNumber;
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
            /// store ship position as a long

            /// store ship position as a long
            /// use ship size to position in array
            /// 012 345 678 9 10 11
            ///  2   3   4    5
            /// in this section rowColNumber , pos , Direction
            /// 2 is zero,  3 is 3 , 4 is 6 , 5 is 9
            /// subtract size 2 and multiply by 3
            int shipName = (size - 2) * 3;
            /// set the 3 values
            boardPositionsArray[shipName] = rowNumber;
            boardPositionsArray[shipName + 1] = colNumber;
            boardPositionsArray[shipName + 2] = direction;
            result = 1; /// ship has been placed

        }
    }


    return result;
}


/*** OPEN SSL FUNCTIONS ***/

/// code from here http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html ///


int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        abort();
    }
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/// more ssl "library" implementation
SSL_CTX *InitServerCTX(void) {
    const SSL_METHOD *method;  // added "const" to remove build error
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    // method = TLSv1_2_server_method();  /* create new server-method instance */ -- depreciated
    method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


/// more ssl "library" implementation

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/// more ssl "library" implementation

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("No certificates.\n");
}





void Servlet(SSL *ssl) /* Serve the connection -- threadable */
{

    int sd;
    if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);        /* get any certificates */

        ///*** processing loop ///

        ///*** processing loop //}

        while (1) {

            bzero(buff, MAX);

            // read the message from client and copy it in buffer
            SSL_read(ssl, buff, sizeof(buff)); /* get request */
            int type = getMessageType(buff);
            if (type == 8 || type < 0) {
                killMe = 1;
                break;
            } else if (type == 1) {
                /// set up the board then reply with ships in position
                srand(time(0));
                printf("\ninitializing board");
                printBoard();
                for (int i = 2; i < 6; i++) {
                    shipPlaced = 0;
                    // place a ship of size 2
                    while (shipPlaced == 0) {
                        shipPlaced = placeShip(i);
                    }
                }
                printf("\nboard finished\n");
                setBoardPositions();
                hasher();
                SSL_write(ssl, hashString, strlen(hashString));
                break;
            }

        }

        while (1) { /// respond to shots until win

            SSL_read(ssl, buff, sizeof(buff)); /* get request */
            int type = getMessageType(buff);
            if (killMe == 1) { break; }
            if (type == 6) {
                printf("\nchecking shot\n");
                int shot = shoot();
                if (shot == 1) {
                    numShots++;
                    int win = scanBoard();
                    if (win == 1) { /// if the board has been cleared by the shot its a win
                        bzero(buff, MAX);
                        printf("You WIN ...\n");
                        /// send the board pos array down to client
                        /// client can then check the hash of it
                        SSL_write(ssl, boardPos, strlen(boardPos)); /* send reply */
                        bzero(buff, MAX);
                        break;
                    }
                    char response3[] = HITMSG;
                    SSL_write(ssl, response3, strlen(response3)); /* send reply */
                    printBoard();
                } else if (shot == 2) {
                    numShots++;
                    char response2[] = MISSMSG;
                    SSL_write(ssl, response2, strlen(response2)); /* send reply */
                    printBoard();
                } else {}
            }
            bzero(buff, sizeof(buff));
        }

        /// send the score until exit recieved

        numShots++;

        while (1) {

            if (killMe == 1) { break; }
            char response6[MAX];
            sprintf(response6, "%d", numShots);
            printf("You WIN ...\n");
            SSL_write(ssl, response6, strlen(response6)); /* send reply */
            SSL_read(ssl, buff, sizeof(buff)); /* get reply & decrypt */
            printf("From Server : %s", buff);
            /// if win message
            int type = getMessageType(buff);
            if (type == 8 || type < 0) {
                killMe = 1;
                break;
            }
        }



        sd = SSL_get_fd(ssl);       /* get socket connection */
        SSL_free(ssl);         /* release SSL state */
        close(sd);          /* close connection */


    }
}


int main(int count, char *strings[]) {

    /// SET UP CONNECTION AND CERTS
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *portnum;
    initializeBoard();


    if (count != 2) {
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


    int client = accept(server, (struct sockaddr *) &addr, &len);  /* accept connection as usual */
    printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    ssl = SSL_new(ctx);              /* get new SSL state with context */
    SSL_set_fd(ssl, client);/* set connection socket to SSL state */


    /*** processing */

    Servlet(ssl); //service connection */


    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
    return 0;


}