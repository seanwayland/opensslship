
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <jmorecfg.h>
#include <memory.h>
#include <errno.h>
#include <zconf.h>
#include <time.h>
#include <arpa/inet.h>


#define STARTMSG "START GAME\n"
#define POSITIONMSG "POSITIONING SHIPS\n"
#define INPOSITIONMSG "SHIPS IN POSITION\n"
#define HITMSG "HIT\n"
#define MISSMSG "MISS\n"
#define EXITMSG "EXIT\n"
#define OVERMSG "OVER\n";
#define WAITMSG "WAIT\n"
#define MAXBUF 65


#define FAIL    -1


/// global variables for came play
int length = 0;
int shotBoard[9][9]; // 2D array to store what shots have been taken
int numShots = 0;
int shipPlaced;
char buf[MAXBUF];
char lastShot[MAXBUF];
char initialHash[65]; // array to store the hash sent over at the outset
char boardPos[12];
char hashString[65];
int killMe = 0;
int sd;

unsigned char hash[SHA256_DIGEST_LENGTH];

int gameState; // variable to track game position



/*** SSL VARIABLES */
/// 0 is not started
/// 1 is start message sent
/// 2 is positioning ships
/// 3 is ships in position
/// 4 is playing game
/// set board to empty



void hasher() {

    size_t length = strlen(boardPos);
    SHA256(boardPos, length, hash);
    int i;
    printf("\n");
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    /// convert hash to string
    static const char alphabet[] = "0123456789ABCDEF";
    for (int i = 0; i != 32; ++i) {
        hashString[2 * i] = alphabet[hash[i] / 16];
        hashString[2 * i + 1] = alphabet[hash[i] % 16];
    }
    hashString[64] = '\0';

    printf("\nFinal Hash String Generated \n%s", hashString);
    printf("\nThis should be same as initial Hash\n");


    /// print the board positions values


}

/// set the shot board to zeros
void initializeBoard() {

    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            shotBoard[i][j] = 0;
        }
    }

}

/// print out the shots we have tried with hits and misses
void printShotBoard() {
    printf("\nBOARD IS NOW");

    {
        printf("\n1 is a miss, 2 is a hit, 0 is unused shot");
        printf("\n* A B C D E F G H I");
    }
    for (int i = 0; i < 9; i++) {
        printf("\n%d", i + 1);
        for (int j = 0; j < 9; j++) {
            printf(" %d", shotBoard[i][j]);
        }

    }
    printf("\n");
}

/// this function parses an incoming message and checks what type it is

int getMessageType(char array[]) {


    length = strlen(array);


    char c = array[0];
    char d = array[1];

    if (array[0] == '\0') { return 9; }

    else if (strcmp(array, HITMSG) == 0) {

        return 4;
    } else if (length == 64) {
        printf("\nHash received");

        return 7;
    } else if (length == 12) {
        printf("\nBoard Positions received");
        return 11;
    } else if (strcmp(array, MISSMSG) == 0) {

        return 5;
    } else if ((d >= '1' & d <= '9') & (c >= 'A' & c <= 'J') & (length < 4)) {
        return 9;
    } else if ((d >= '1' & d <= '9') & (c >= '1' & c <= '9') & (length < 4)) {
        return 6;
    } else if (strcmp(array, POSITIONMSG) == 0) {
        printf("\n");
        return 2;
    } else if (strcmp(array, INPOSITIONMSG) == 0) {
        printf("\n");
        return 3;
    }
    else if (strcmp(array, WAITMSG) == 0) {
        return 12; }
    else if (strcmp(array, EXITMSG) == 0) {
        return 8;
    }
    else { return -1; } /// if message is not correct type reject it
}



/*** SSL FUNCTIONS ***///

int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *) (host->h_addr);
    if (connect(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX *InitCTX(void) {
    const SSL_METHOD *method; // added "const" to remove build error
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLS_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}



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

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else
        printf("Info: No client certificates configured.\n");
}


void clientFunction(SSL *ssl) {


    bzero(buf, sizeof(buf));
    printf("BATTLESHIP GAME\n");
    printf("GAME STARTING\n");
    char start[] = STARTMSG;
    SSL_write(ssl, start, sizeof(start)); /* send reply */

    /// wait for hash message

    while(1)
    {

        bzero(buf, sizeof(buf));
        SSL_read(ssl, buf, sizeof(buf)); /* get request */
        int type = getMessageType(buf);
        if (type == 8 || type < 0) {
            killMe = 1;
            break;
        }
        else if ( type == 7){
            printf("\n");
            sprintf(initialHash, "%s", buf);
            printf("Hash saved :\n %s", initialHash);
            printf("\n");
            bzero(buf, sizeof(buf));
            break;
        }
        else { }
    }
    /// loop until win
    while(1){
        if (killMe == 1){break;}
        bzero(buf, sizeof(buf));
        printf("\n");
        /// GET SHOT FROM USER AND CHECK FOR CORRECT INPUT
        while (1) {

            printf("Enter your shot!! \n(Capital letter ( A to I )  then number ( 1 to 9 ) \nEXIT to quit:  ");
            fgets(buf, MAXBUF, stdin);
            if (getMessageType(buf) == 9) { break; }
            else if (getMessageType(buf) == 8) {
                printf("Client Exit...\n");
                char response[] = EXITMSG;
                SSL_write(ssl, response, sizeof(response)); /* send reply */
                killMe = 1;
                break;
            } else { printf("\nIncorrect input!!\nPlease enter your shot again: "); }
        }

        /// SEND THE SHOT
        SSL_write(ssl, buf, sizeof(buf)); /* send reply */
        strncpy(lastShot, buf, MAXBUF);
        bzero(buf, sizeof(buf));
        SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        printf("From Server : %s", buf);
        /// if win message
        int type = getMessageType(buf);
        if (type == 11) {
            printf("\nyou win ... \n");
            printf("\nboard pos array received... %s ", buf);
            printf("Client Exit...\n");

            for (int i = 0; i < 12; i++) {
                boardPos[i] = buf[i];
            }
            printf("\nInitial hash \n%s", initialHash);
            hasher();
            bzero(buf, sizeof(buf));
            break;
        }
        if (type == 4) {
            /// hit
            /// store on shotBoard
            int row = lastShot[0] - 64 - 1; // convert uppercase letter to row
            int col = lastShot[1] - '0' - 1;
            shotBoard[col][row] = 2;
            printShotBoard();
        }

        if (type == 5) {
            /// miss
            /// store on shotBoard
            int row = lastShot[0] - 64 - 1; // convert uppercase letter to row
            int col = lastShot[1] - '0' - 1;
            shotBoard[col][row] = 1;
            printShotBoard();
            printf("\n");


        }
        if (type == 8 || type < 0) { // if message isn't correct type close connection
            printf("Client Exit...\n");
            break;
        } else {}


    }


    /// wait for the score then respond with exit
    while(1){
        if (killMe == 1){ break;}
        bzero(buf, sizeof(buf));
        SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        printf("From Server : %s", buf);
        /// if win message
        int type = getMessageType(buf);
        if (type == 8 || type < 0){
        break ;}

        else if (type == 6) {
            printf("\nyou win ... \n");
            printf("\nscore is  ... %s ", buf);
            printf("Client Exit...\n");

            // check the hash
            bzero(buf, MAXBUF);
            char response[] = EXITMSG;
            SSL_write(ssl, response, sizeof(response)); /* send reply */
            break;
        }

    }

}


int main(int count, char *strings[]) {
    gameState = 0; // starting !!
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *hostname, *portnum;
    initializeBoard();
    if (count != 3) {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname = strings[1];
    portnum = strings[2];

    ctx = InitCTX();
    //SSL_CTX_set_verify_depth(ctx, 2);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    //SSL_verify_client_post_handshake(ssl);
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if (SSL_connect(ssl) == FAIL)   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else {
        {

            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);        /* get any certs */
            clientFunction(ssl);


        }
    }
    SSL_free(ssl);        /* release connection state */
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}