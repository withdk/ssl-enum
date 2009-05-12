/*
 * SSL Enumerator (ssl-enum) is Copyright (C) 2009-2014 David Kierznowski
 * (withdk.com).
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

int 
main(int argc, char *argv[])
{	
	int sock;
	char *servIP;
	char hostname[128];
    unsigned short sslPort;     	
    struct sockaddr_in sa;      
    char *pkt_in;     
    int totalBytesRcvd;
	int struct_len;
                           
	char *cipher;
	char *cipherfile;
	int default_file=0;
	unsigned char *finished_hello; 
	
	int opt;
	int verbose=0;
	int cipher_arg=0;

	FILE *fp;
    char fbuf[MAXLINE];
    unsigned short sock_cipher;
    char *cipherlist[3];
	
	while((opt=getopt(argc,argv, "s:p:c:v:f:23")) != -1)
	{
		switch(opt)
		{
			case 's':
				servIP = optarg;
				break;
			case 'p':
				sslPort = atoi(optarg);
				break;
			case 'f':
				cipherfile = optarg;
				default_file = 1;
				break;
			case 'c':
				cipher = optarg;
				cipher_arg = 1;
				break;
			case 'v':
                 verbose = atoi(optarg);
			case '2':
				printf("using ssl 2\n");
				break;
			case '3':
				printf("using ssl 3\n");
				break;
			default:
				break;
		}
	}
	 

	if (!sslPort)
		sslPort = 443;
	/*
		Access cipher list or die
	*/
	if (!default_file)
		cipherfile = "cipher-list.txt";
	if ( (fp=fopen(cipherfile, "r")) == NULL)
		DieWithError("fopen() failed");
	/*
		Loop around ciphers and test each one
		todo: this is a bit rudimentary
	*/
    while ( fgets(fbuf, MAXLINE, fp) != 0)
	{
		/*
			Skip blank lines and comments
		*/
		if (fbuf[0] == '#' || fbuf[0] == '\n' || fbuf[0] == '\r')
         continue;      
		/*
			Tokenise cipherlist file
		*/
        if ((cipherlist[0]=strtok(fbuf, "\t")) == NULL) /* Hex value */
			DieWithError("strtok() failed: invalid cipherlist format in file");
        if ((cipherlist[1]=strtok(NULL, "\t")) == NULL) /* Description */
			DieWithError("strtok() failed: invalid cipherlist format in file");
        if ((cipherlist[2]=strtok(NULL, "\t")) == NULL)	/* Export */
			DieWithError("strtok() failed: invalid cipherlist format in file");
	/*
		We initialise our client_hello struct
		and build the byte stream ready to send.
	*/
	/*
		Decimal value for 1 in TLS1 is 49 (man ascii)
		
		We use this for comparison as it saves us having 
		to use string compare functions.
	*/
	if ((int)cipherlist[1][3] == 50) {
    	struct ssl2_client_hello ppkt_out;
		struct_len = sizeof(struct ssl2_client_hello);
		finished_hello=build_ssl2_hello_msg(&ppkt_out, cipher_arg, cipherlist[0], cipherlist[1]);
	}
	else {
		struct tls1_ssl3_client_hello ppkt_out;
		struct_len = sizeof(struct tls1_ssl3_client_hello);
		finished_hello=build_hello_msg(&ppkt_out, cipher_arg, cipherlist[0], cipherlist[1]);
	}
	/* 
		Display our client hello request if 
		verbose is on 
	*/
	if (verbose==2)
		make_ssl_debug(finished_hello, "Sent Data", struct_len);
    /*
		call socket
	*/
	sock=new_socket(&sa, servIP, sslPort);
	/*
		call connect
	*/
	new_connect(&sa, sock);
	/*
		call send
	*/
	new_write(sock, finished_hello, struct_len);
		
    /* 
		call recv
	*/
	struct getBytes gb;
	new_read(sock, &gb, struct_len);
	/*
		retreive recv data
	*/
	totalBytesRcvd=gb.totalBytesRcvd;
	pkt_in=malloc(totalBytesRcvd);
	memset(pkt_in, 0, totalBytesRcvd);
	pkt_in=gb.recv_data;
	/* 
		Display received data in hex 
		for debugging 
	*/
	if (verbose==2)
		make_ssl_debug((unsigned char*)pkt_in, "Received Data", totalBytesRcvd);
	/* 
		Check for SSL Error 
	*/
	if (pkt_in[0] == SSLALERT && totalBytesRcvd == 7 && verbose > 0) 
		process_ssl_alert(pkt_in, cipherlist[0], cipherlist[1], cipherlist[2]);
	/* 
		Check for server hello 
		
		todo: might want to make this a bit smarter
	*/
	if (pkt_in[0] == SSLHANDSHAKE) 
		process_ssl_hello(pkt_in, cipherlist[0], cipherlist[1], cipherlist[2]);
	/*
		Pain in the behind but if SSLv2 cipher is
		not supported, it doesn't actually tell us,
		it simply sets the len to 0000.
	*/
	if (pkt_in[10] == SSL2_SERVERHELLOBYTE)
		process_ssl_hello(pkt_in, cipherlist[0], cipherlist[1], cipherlist[2]);
	/*
		Close sock
	*/
    close(sock);
	/*
		Clean up - more work here.
	*/
    free(finished_hello);
	/* todo: having trouble free'ing, so we null it instead */
	memset(gb.recv_data, 0, totalBytesRcvd);
	/*
		Close file pointer
	*/
	}
	fclose(fp);
	
	return 0;
}
