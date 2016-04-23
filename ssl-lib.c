/*
 * SSL Enumerator (ssl-enum) is Copyright (C) 2009-2014 David Kierznowski
 * (https://github.com/davidkierznowski/ssl-enum).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 *
 */

#include "ssl-enum.h"

/*
 Build sslv2 client hello message

 struct - pointer to struct
 int opt - single cipher option or not 1/0
 char *c - cipher to use for single cipher option
*/
unsigned char *
build_ssl2_hello_msg ( struct ssl2_client_hello *clientHello, int opt, char *c1, char *c2 )
{
    unsigned char *p;
    unsigned char *off;
    unsigned long num;
    int i;

    /* size up ptr */
    p=malloc ( sizeof ( struct ssl2_client_hello ) );
    clientHello=malloc ( sizeof ( struct ssl2_client_hello ) );
    memset ( p, 0, sizeof ( struct ssl2_client_hello ) );
    memset ( clientHello, 0, sizeof ( struct ssl2_client_hello ) );


    /* Test a single cipher or check all */
    //if ( opt ) {
    num=hstr_i ( c1 );
    //	clientHello->CipherSuite = htons(num);
    //}
    //else
    //	clientHello->CipherSuite = htons(0x0005);

    clientHello->rl_content_type = SSL2_HANDSHAKE;
    //clientHello->rl_len = htons(sizeof(struct ssl2_client_hello)-2);
    clientHello->rl_len = sizeof ( struct ssl2_client_hello )-2;
    clientHello->client_handshake = CLIENT_HELLO;
    clientHello->client_version = htons ( SSL2_VERSION );
    /*
     SSLv2 uses 3 bytes per cipher, we'll try use a uint32_t
     and strip it later or let trim random bytes if needed
     which follows.
    */
    clientHello->cipher_len = htons ( SSL2_CIPHERLEN );
    clientHello->sessionID = htons ( SESSIONID );
    clientHello->challenge_len = htons ( SSL2_CHALLENGE_LEN );
    /*
     Do a left bitwise shift to get our
     uint24_r, leave the extra byte to fall
     into random.
    */
    num = num << 8;
    clientHello->CipherSuite = htonl ( num ); /* Cipher to send */
    /*
     todo: cleaner way to generate random()
    */
    for ( i=0; i<sizeof ( clientHello->random ); i++ )
    {
        clientHello->random[i] = random();
    }
    i=0;
    /*
     We copy our items off struct one by one to ensure
     correct alignment at compile time.
    */
    off=p;

    memcpy ( off, &clientHello->rl_content_type, sizeof ( clientHello->rl_content_type ) );
    off += sizeof ( clientHello->rl_content_type );
    memcpy ( off, &clientHello->rl_len, sizeof ( clientHello->rl_len ) );
    off += sizeof ( clientHello->rl_len );
    memcpy ( off, &clientHello->client_handshake, sizeof ( clientHello->client_handshake ) );
    off += sizeof ( clientHello->client_handshake );
    memcpy ( off, &clientHello->client_version, sizeof ( clientHello->client_version ) );
    off += sizeof ( clientHello->client_version );
    memcpy ( off, &clientHello->cipher_len, sizeof ( clientHello->cipher_len ) );
    off += sizeof ( clientHello->cipher_len );
    memcpy ( off, &clientHello->sessionID, sizeof ( clientHello->sessionID ) );
    off += sizeof ( clientHello->sessionID );
    memcpy ( off, &clientHello->challenge_len, sizeof ( clientHello->challenge_len ) );
    off += sizeof ( clientHello->challenge_len );
    memcpy ( off, &clientHello->CipherSuite, sizeof ( clientHello->CipherSuite ) );
    off += sizeof ( clientHello->CipherSuite );
    memcpy ( off, &clientHello->random, sizeof ( clientHello->random ) );

    free ( clientHello );
    return p;
}

/*
 Build SSLv3/TLSv1 client hello message

 struct - pointer to struct
 int opt - single cipher option or not 1/0
 char *c - cipher to use for single cipher option
*/
unsigned char *
build_hello_msg ( struct tls1_ssl3_client_hello *clientHello, int opt, char *c1, char *c2 )
{
    unsigned char *p;
    unsigned char *off;
    unsigned long num;
    int i;

    /* size up ptr */
    p=malloc ( sizeof ( struct tls1_ssl3_client_hello ) );
    clientHello=malloc ( sizeof ( struct tls1_ssl3_client_hello ) );
    memset ( p, 0, sizeof ( struct tls1_ssl3_client_hello ) );
    memset ( clientHello, 0, sizeof ( struct tls1_ssl3_client_hello ) );


    /* Test a single cipher or check all */
    //if ( opt ) {
    num=hstr_i ( c1 );
    clientHello->CipherSuite = htons ( num );
    //}
    //else
    //	clientHello->CipherSuite = htons(0x0005);

    clientHello->rl_content_type = SSLHANDSHAKE;
    /*
    	Decimal value for 1 in TLS1 is 49 (man ascii)

    	We use this for comparison as it saves us having
    	to use string compare functions.
    */
    if ( ( int ) c2[3] == 49 )
        clientHello->rl_client_version = htons ( TLS1_VERSION );
    else
        clientHello->rl_client_version = htons ( SSL3_VERSION );

    /*
     todo: add -2 to lens because of extra 2 byte padding.
    */
    clientHello->rl_len = htons ( sizeof ( struct tls1_ssl3_client_hello )-7 );		/* Length for rest of struct */
    clientHello->client_handshake = CLIENT_HELLO;
    clientHello->client_len_pad = 0x00; /* pad */
    clientHello->client_len = htons ( sizeof ( struct tls1_ssl3_client_hello )-11 );	/* Length for rest of struct */
    if ( ( int ) c2[3] == 49 )
        clientHello->client_version = htons ( TLS1_VERSION );
    else
        clientHello->client_version = htons ( SSL3_VERSION );
    //clientHello->client_version = htons ( SSL3_VERSION );	/* SSL/TLS version (0x0301) */
    //clientHello->random_bytes[] = '';  /* We can leave this blank as we aren't renewing a session */
    clientHello->sessionID = SESSIONID;      /* opaque SessionID<0..32>, safe to leave as 0 */
    clientHello->cipher_len = htons ( CIPHER_LEN ); /* cipher len, 2 bytes per cipher */
    //clientHello->CipherSuite = htons(0x0002);    /* Cipher to send */
    clientHello->compression_len = COMPRESSION_LEN;        /* compression length */
    clientHello->compression_method = COMPRESSION_TYPE;     /* 0-255 safe to leave null or 00 */
    /*
     todo: cleaner way to generate random()
    */
    for ( i=0; i<sizeof ( clientHello->random_bytes ); i++ )
    {
        clientHello->random_bytes[i] = random();
    }
    i=0;

    /*
     We copy our items off struct one by one to ensure
     correct alignment at run time.
    */
    off=p;

    memcpy ( off, &clientHello->rl_content_type, sizeof ( clientHello->rl_content_type ) );
    off += sizeof ( clientHello->rl_content_type );
    memcpy ( off, &clientHello->rl_client_version, sizeof ( clientHello->rl_client_version ) );
    off += sizeof ( clientHello->rl_client_version );
    memcpy ( off, &clientHello->rl_len, sizeof ( clientHello->rl_len ) );
    off += sizeof ( clientHello->rl_len );
    memcpy ( off, &clientHello->client_handshake, sizeof ( clientHello->client_handshake ) );
    off += sizeof ( clientHello->client_handshake );
    memcpy ( off, &clientHello->client_len_pad, sizeof ( clientHello->client_len_pad ) );
    off += sizeof ( clientHello->client_len_pad );
    memcpy ( off, &clientHello->client_len, sizeof ( clientHello->client_len ) );
    off += sizeof ( clientHello->client_len );
    memcpy ( off, &clientHello->client_version, sizeof ( clientHello->client_version ) );
    off += sizeof ( clientHello->client_version );
    memcpy ( off, &clientHello->random_bytes, sizeof ( clientHello->random_bytes ) );
    off += sizeof ( clientHello->random_bytes );
    memcpy ( off, &clientHello->sessionID, sizeof ( clientHello->sessionID ) );
    off += sizeof ( clientHello->sessionID );
    memcpy ( off, &clientHello->cipher_len, sizeof ( clientHello->cipher_len ) );
    off += sizeof ( clientHello->cipher_len );
    memcpy ( off, &clientHello->CipherSuite, sizeof ( clientHello->CipherSuite ) );
    off += sizeof ( clientHello->CipherSuite );
    memcpy ( off, &clientHello->compression_len, sizeof ( clientHello->compression_len ) );
    off += sizeof ( clientHello->compression_len );
    memcpy ( off, &clientHello->compression_method, sizeof ( clientHello->compression_method ) );

    free ( clientHello );
    return p;
}

/*
 new_socket

 struct sockaddr_in
 servIP
 sslPort

*/
int
new_socket ( struct sockaddr_in *s, struct hostent **h, unsigned short sslPort )
{
    int sock;

    if ( ( sock = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
        DieWithError ( "socket() failed" );

    /* Construct the server address structure */
    bzero ( ( char * ) &s, sizeof ( s ) ); /* Zero out structure */
    s->sin_family=AF_INET;             /* Internet address family */
    //bcopy((char *)&h->h_addr,(char *)&s->sin_addr.s_addr,h->h_length);
    //s->sin_addr.s_addr = inet_addr(servIP);   /* Server IP address */
    s->sin_port=htons ( sslPort ); /* Server port */

    return sock;
}

/*
 Make TCP Connection
*/
void
new_connect ( struct sockaddr_in *s, int sock )
{
    struct sigaction act, oact;
    unsigned tcp_connect_timeout = DEFAULT_TCP_CONNECT_TIMEOUT;
    /*
     Set signal handler for alarm.
     just use sigaction() rather than signal()
     to prevent SA_RESTART
     	*/
    act.sa_handler=sig_alarm;
    sigemptyset ( &act.sa_mask );
    act.sa_flags=0;
    sigaction ( SIGALRM,&act,&oact );
    /*
    Set alarm
    */
    alarm ( tcp_connect_timeout );
    /*
     Start connect
    */
    if ( connect ( sock, ( struct sockaddr * ) &s, sizeof ( struct sockaddr_in ) ) != 0 )
    {
        if ( errno == EINTR )
            errno = ETIMEDOUT;
        DieWithError ( "connect() failed" );
    }

    /*
    Cancel alarm
    */
    alarm ( 0 );

}

/*
 Send SSL Data over socket
*/
void
new_write ( int sock, unsigned char *pkt_out, int struct_len )
{

    /*
    	Send pkt_out
    */
    if ( send ( sock, pkt_out, struct_len, 0 ) < 0 )
        DieWithError ( "send() error" );

}
/*	Make connection

	struct sockaddr_in
	sock
*/
void
new_read ( int sock, struct getBytes *byte, int struct_len )
{
    char buf[RCVBUFSIZE];
    int totalBytesRcvd = 0;
    int bytesRcvd = 0;
    unsigned recv_timeout = DEFAULT_RECV_TIMEOUT;

    struct sigaction act2, oact2;

    act2.sa_handler=sig_alarm;
    sigemptyset ( &act2.sa_mask );
    act2.sa_flags=0;
    sigaction ( SIGALRM,&act2,&oact2 );

    alarm ( recv_timeout );

    while ( totalBytesRcvd < RCVBUFSIZE )
    {
        /* Receive up to the buffer size (minus 1 to leave space for
           a null terminator) bytes from the sender */
        if ( ( bytesRcvd = recv ( sock, buf, RCVBUFSIZE - 1, 0 ) ) < 1 )
        {
            if ( errno == EINTR )
                errno = ETIMEDOUT;
            break;
        }

        if ( bytesRcvd != 0 )
            totalBytesRcvd += bytesRcvd;   /* Keep tally of total bytes */

        if ( totalBytesRcvd >= struct_len )
            break;

        /* We know we are done when we get a Server Hello Done */
        /* x0e x00 x00 x00 */

    }

    alarm ( 0 );

    byte->totalBytesRcvd=totalBytesRcvd;
    byte->recv_data = buf;

}
/*  process_ssl_hello(char *serverhello)

	If we recieve a valid SSL SERVER response
	then we know our requested cipher is valid.

	This function can be a lot better.
*/
void
process_ssl_hello ( char *serverhello, char *c1, char *c2, char *c3, int verbose )
{
    // This only supports SSLv3 for now.
    if ( verbose>3&&serverhello[0] == SSLHANDSHAKE )
    {
        unsigned char *h;
        struct tls1_ssl3_server_hello *hi;
        hi=malloc ( sizeof ( struct tls1_ssl3_server_hello ) );
        memset ( hi, 0, sizeof ( struct tls1_ssl3_server_hello ) );

        memcpy ( &hi->content_type, serverhello, sizeof ( hi->content_type ) );
        serverhello += sizeof ( hi->content_type );
        memcpy ( &hi->ssl_version, serverhello, sizeof ( hi->ssl_version ) );
        serverhello += sizeof ( hi->ssl_version );
        memcpy ( &hi->hello_len, serverhello, sizeof ( hi->hello_len ) );
        serverhello += sizeof ( hi->hello_len );
        memcpy ( &hi->server_hello, serverhello, sizeof ( hi->server_hello ) );
        serverhello += sizeof ( hi->server_hello );
        memcpy ( &hi->server_hello_len, serverhello, sizeof ( hi->server_hello_len ) );
        /*
            Bitwise left shift to move ensure 24 bit not 32 bit
        */
        hi->server_hello_len = hi->server_hello_len << 8;
        serverhello += sizeof ( hi->server_hello_len )-1;
        memcpy ( &hi->ssl_version_hello, serverhello, sizeof ( hi->ssl_version_hello ) );
        serverhello += sizeof ( hi->ssl_version_hello );
        memcpy ( &hi->gmt_unix_time, serverhello, sizeof ( hi->gmt_unix_time ) );
        serverhello += sizeof ( hi->gmt_unix_time );
        memcpy ( &hi->random_bytes, serverhello, sizeof ( hi->random_bytes ) );
        serverhello += sizeof ( hi->random_bytes );
        memcpy ( &hi->SessionID_len, serverhello, sizeof ( hi->SessionID_len ) );
        serverhello += sizeof ( hi->SessionID_len );

        if ( hi->SessionID_len > 0 )
        {
            hi->SessionID = malloc ( hi->SessionID_len );
            memset ( hi->SessionID, 0, sizeof ( hi->SessionID_len ) );
            memcpy ( hi->SessionID, serverhello, hi->SessionID_len );
            serverhello += hi->SessionID_len;
        }

        memcpy ( &hi->CipherSuite, serverhello, sizeof ( hi->CipherSuite ) );
        serverhello += sizeof ( hi->CipherSuite );
        memcpy ( &hi->compression_method, serverhello, sizeof ( hi->compression_method ) );
        serverhello += sizeof ( hi->compression_method );

        /*
            SSL Output for debugging and information
            gathering.
        */
        printf ( "\nPACKET DECODE:\n" );
        printf ( "HANDSHAKE TYPE: %d\n", hi->content_type );
        printf ( "SSL VERSION: %d\n", hi->ssl_version );
        printf ( "LENGTH: %d\n", htons ( hi->hello_len ) );
        printf ( "SERVER HELLO: %d \n", hi->server_hello );
        printf ( "LENGTH: %d\n", htonl ( hi->server_hello_len ) );
        printf ( "SSL VERSION: %d\n", hi->ssl_version_hello );

        time_t epch = htonl ( hi->gmt_unix_time );
        printf ( "GMT UNIX TIME: %s", asctime ( gmtime ( &epch ) ) );

        h = hexstring ( ( unsigned char* ) &hi->random_bytes, sizeof ( hi->random_bytes ) );
        printf ( "RANDOM BYTES: %s\n", h );
        free ( h );

        printf ( "SESSION LEN: %d\n", hi->SessionID_len );

        if ( hi->SessionID_len > 0 )
        {
            h = hexstring ( hi->SessionID, hi->SessionID_len );
            printf ( "SESSIONID: %s\n", h );
            free ( h );
        }
        else
        {
            printf ( "SESSIONID: NULL\n" );
        }

        h = hexstring ( ( unsigned char* ) &hi->CipherSuite, sizeof ( hi->CipherSuite ) );
        printf ( "CIPHER: %s\n", h );
        free ( h );

        printf ( "COMPRESSION: %d\n", hi->compression_method );

        // uint8_t compression_method;     /* 0-255 safe to leave null or 00 */

        free ( hi );

    }

    printf ( "0x%s\t%s\t%s", c1,c2,c3 );

}


/*  make_ssl_debug(unsigned char *buf, char *msg, int len)

	Generic debug function using hexstring()
*/
void
make_ssl_debug ( unsigned char *buf, char *msg, int len )
{
    char *h;

    h=hexstring ( ( unsigned char * ) buf, len );
    printf ( "%s: %s (length %d)\n", msg, h, len );
    free ( h );
}

/*  process_ssl_alert(char *sslalert)

	If we detect an SSL error then we try find out
	what went wrong.
*/
void
process_ssl_alert ( char *sslalert, char *c1, char *c2, char *c3, int verbose )
{
    /* More errors in openssl */
    /* ../../openssl-0.9.8k/crypto/err/openssl.ec */

    if ( verbose > 0 )
    {

        switch ( sslalert[SSLALERTBYTE] )
        {
        case 0:
            printf ( "CloseNotify\n" );
            break;
        case 10:
            printf ( "UnexpectedMessage\n" );
            break;
        case 20:
            printf ( "BadRecordMAC\n" );
            break;
        case 21:
            printf ( "DecryptionFailed\n" );
            break;
        case 22:
            printf ( "RecordOverflow\n" );
            break;
        case 30:
            printf ( "DecompressionFailure\n" );
            break;
        case 40:
            printf ( "HandshakeFailure\n" );
            //printf("0x%s\t%s\tCIPHER NOT SUPPORTED\t%s", c1,c2,c3);
            break;
        case 41:
            printf ( "NoCertificate\n" );
            break;
        case 42:
            printf ( "BadCertificate\n" );
            break;
        case 43:
            printf ( "UnsupportedCertificate\n" );
            break;
        case 44:
            printf ( "CertificateRevoked\n" );
            break;
        case 45:
            printf ( "CertificateExpired\n" );
            break;
        case 46:
            printf ( "CertificateUnknown\n" );
            break;
        case 47:
            printf ( "IllegalParameter\n" );
            break;
        case 48:
            printf ( "UnknownCA\n" );
            break;
        case 49:
            printf ( "AccessDenied\n" );
            break;
        case 50:
            printf ( "DecodeError\n" );
            break;
        case 51:
            printf ( "DecryptError\n" );
            break;
        case 60:
            printf ( "ExportRestriction\n" );
            break;
        case 70:
            printf ( "ProtocolVersion\n" );
            break;
        case 71:
            printf ( "InsufficientSecurity\n" );
            break;
        default:
            printf ( "UNKNOWN SSL ERROR\n" );
            break;
        }
    }

}

void
DieWithError ( char *errorMessage )
{
    printf ( "%s\n", errorMessage );
    exit ( 1 );
}

/*
 *      hexstring -- Convert data to printable hex string form
 *
 *      Code taken from ike-scan
 *      (http://www.nta-monitor.com)
 */
char *
hexstring ( const unsigned char *data, size_t size )
{
    char *result;
    char *r;
    const unsigned char *cp;
    unsigned i;
    /*
     *      If the input data is NULL, return an empty string.
     */
    if ( data == NULL )
    {
        result = malloc ( 1 );
        result[0] = '\0';
        return result;
    }
    /*
     *      Create and return hex string.
     */
    result = malloc ( 2*size + 1 );
    cp = data;
    r = result;
    for ( i=0; i<size; i++ )
    {
        sprintf ( r, "%.2x", *cp++ );
        r += 2;
    }
    *r = '\0';

    return result;
}

/*
 *		Convert char to uint
 *
 *      Code taken from ike-scan
 *      (http://www.nta-monitor.com)
 *
 *		int s was added to allow multibyte
 *		conversion.
 */

unsigned int
hstr_i ( const char *cptr )
{
    unsigned int i;
    unsigned int j = 0;
    int k;
    int s = strlen ( cptr );

    for ( k=0; k<s; k++ )
    {
        i = *cptr++ - '0';
        if ( 9 < i )
            i -= 7;
        j <<= 4;
        j |= ( i & 0x0f );
    }
    return j;
}


/*      sig_alarm -- Signal handler for SIGALRM
 *
 *      Code taken from ike-scan
 *      (http://www.nta-monitor.com)
 */
void sig_alarm ( int signo )
{
    return;      /* just interrupt the current system call */
}

