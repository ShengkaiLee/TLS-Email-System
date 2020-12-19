#include <stdio.h>
#include <iostream>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <experimental/filesystem>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"

#include <vector>
#include <fstream>
using namespace std;

//Testing Certificate and Private Key
static char const *CertFile = "../ca/intermediate/certs/www.server.com.cert.pem";
static char const *KeyFile = "../ca/intermediate/private/www.server.com.key.pem";
static char const *CACert = "../ca/intermediate/certs/ca-chain.cert.pem";
//static char const *client_ca_path = "../ca/intermediate/certs";
static int padding = RSA_PKCS1_OAEP_PADDING;
static int flen    = 40;
static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void send_certificate(SSL *ssl, const char* path)
{
	FILE *fp = NULL;
	fp = fopen(path, "rb");
	if (fp == 0)
	{
		cout<<"fopen failed to open "<<path<<endl;
	}
	fseek(fp, 0, SEEK_END);
	size_t size = ftell (fp);
	rewind(fp);
	char *buf = (char*) malloc (sizeof(char) * size);
	if (buf == NULL)
	{
		die("malloc in send_certificate failed");
	}
	//cout<<"sizeof buf: "<<size<<endl;
	if (fread(buf, 1, size, fp) != size)
	{
		cout<<"fread failed"<<endl;
	}
	SSL_write(ssl, buf, size);
	//BIO_flush(ssl);
	fclose(fp);
	free(buf);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        die("Usage: %s <port number>");
    }
    //Lisen on socket
    int err = 0;
    int portNum = atoi(argv[1]);
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int clientSock;
    unsigned int clntLen;
    int servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (servSock < 0)
    {
        die("socket() failed");
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(portNum);
    err = bind(servSock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err < 0)
    {
        die("bind() failed");
    }
    err = listen(servSock, 10);
    if (err < 0)
    {
        die("listen() failed");
    }
    //SSL init
    SSL_CTX *ctx;
    SSL *ssl;
    const SSL_METHOD *method;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        die("SSL_CTX_nex() failed");
    }
    //Setting Up Certificates for the SSL Server
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        die("SSL_CTX_use_certificate_file() falied");
    }
    //Load CA Private Key
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        die("SSL_CTX_use_PrivateKey_file() falied");
    }
    //Load Trusted CA for authentification
    if (!SSL_CTX_load_verify_locations(ctx, CACert, NULL))
    {
        die("SSL_CTX_load_verify_locations() falied");
    }
    ssl = SSL_new(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
    //Start accept()
    clntLen = sizeof(client_addr);
    if ((clientSock = accept(servSock, (struct sockaddr *)&client_addr, &clntLen)) < 0)
    {
        die("accept() failed");
    }
    fprintf(stderr, "\nconnection started from: %s\n", inet_ntoa(client_addr.sin_addr));
    SSL_set_fd(ssl, clientSock);
    err = SSL_accept(ssl);
    //cout << "err: " << err << endl;

    if (SSL_get_peer_certificate(ssl) == NULL)
    {
        //printf("peer_certificate = NULL\n");
    }
    int ver_err = SSL_get_verify_result(ssl);
    {
        const char *message = X509_verify_cert_error_string(ver_err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, ver_err);
    }


    char buf[2000];
    int count = 0;
    int total = 0;
    count = SSL_read(ssl, buf, sizeof(buf));
    {
        total += count;
    }
    if (total > 0)
    {
        //printf("Client msg: \"%s\"\n", buf);
    }
    BIO *bio;
    X509 *certificate;
    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, buf);
    certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (certificate == NULL)
    {
        die("Cert is NULL");
    }
    //char *line;
    //line = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0);
    //printf("Subject: %s\n", line);
    //cout << "success" << endl;

    
    // verify clinet's cert
    // 
    //X509 *selfCert = SSL_get_certificate(ssl);
    //X509* selfCert = NULL;
    //FILE *cfp = NULL;
    //cfp = fopen("../ca/intermediate/certs/www.addleness.com.cert.pem","rb");
    //if(cfp == NULL)
    //{
        //selfCert = NULL;
        //cout<<"cfp = NULL"<<endl;
    //}
    //else
    //{
        //selfCert = PEM_read_X509(cfp, NULL, NULL, NULL);
        //cout << "selfCert" << endl;
    //}
    //fclose(cfp);
    //cout << "selfCert" << endl;
    EVP_PKEY *pubkey = X509_get_pubkey(certificate);
    //cout << "publicKey" << endl;
    //int result = X509_verify(certificate, pubkey);
    //cout << "result: " << result << endl;
    //int result = X509_cmp(certificate, selfCert);
    //cout << "result of X509_cmp: "<<result<<endl;
    /*
    if(result != 0)
    {
	    die("certificate does not match");
    }
    */

    char read1_buf[10];
    // read1 = function name
    int read1 = SSL_read(ssl, read1_buf, sizeof(read1_buf));
    if (read1 <= 0)
    {
	    die("SSL_read function name failed");
    }
    if (strncmp(read1_buf, "sendmsg()", 9) == 0)
    {
	    cout<<"sendmsg() request start"<<endl;
	    
	    // username + rcpt name
	    char read2_buf[1000];
	    int read2 = SSL_read(ssl, read2_buf, sizeof(read2_buf));
	    char read2_temp[read2];
	    strncpy(read2_temp, read2_buf, read2);
	    read2_temp[read2]  = '\0';
	    char *token = strtok(read2_temp, " ");
	    char *sendername = token;
	    //cout<<"username: "<<sendername<<endl;
	    // check certificate of the sender
	    //
	    string username = string(sendername);
	    string CertFile_temp = "../ca/intermediate/certs/www."+username+ ".com.cert.pem";
	    cout<<"certfile path"<<CertFile_temp<<endl;
	    const char *CertFile = CertFile_temp.c_str();
	    // verify clinet's cert
    		// 
    		//X509 *selfCert = SSL_get_certificate(ssl);
    		X509* selfCert = NULL;
    		FILE *cfp = NULL;
    		//cfp = fopen("../ca/intermediate/certs/www.addleness.com.cert.pem","rb");
    		cfp = fopen(CertFile, "rb");
		if(cfp == NULL)
   		{
       			selfCert = NULL;
        		//cout<<"cfp = NULL"<<endl;
    		}
    		else
   		 {
 		        selfCert = PEM_read_X509(cfp, NULL, NULL, NULL);
        		//cout << "selfCert" << endl;
    		}
    		fclose(cfp);
    		//EVP_PKEY *pubkey = X509_get_pubkey(certificate);
    		int result = X509_cmp(certificate, selfCert);
    		//cout << "result of X509_cmp: "<<result<<endl;
		if (result != 0)
		{
			die("certificate does not match");
		}
		X509_free(selfCert);

	    int rcpt_number = 0;
	    vector<char*> rcpt_name;
	    while (token != NULL)
	    {
		    token = strtok(NULL, " ");
		    if (token == NULL)
			   break; 
		    rcpt_name.push_back(token);
		    //cout<<"token["<<rcpt_number<<"]: "<<token<<endl;
		    //cout<<"rcpt_name: " << rcpt_name[rcpt_number] << endl;
		    rcpt_number++;
	    }
		
	    // send encrypted message
	    //
	    //generate encrypt_msg
   	    const char *test_msg = "hahaha";
    	char encrypt_msg[2560];
    	auto rsa = EVP_PKEY_get1_RSA(pubkey);
    	int enc = RSA_public_encrypt(flen, (const unsigned char *)test_msg, (unsigned char *)encrypt_msg, rsa, padding);
    	//printf("%s\n", encrypt_msg);
	if (enc == -1)
	{
		die("RSA_public_encrypt failed");
	}
    	SSL_write(ssl, encrypt_msg, sizeof(encrypt_msg));

	    // verify decrypted message
	    char read3_buf[20];
	    int read3 = SSL_read(ssl, read3_buf, sizeof(read3_buf));
	    if (read3 <= 0)
	    {
		    die("read dedcrypted message from client failed");
	    }
	    if (strncmp(test_msg, read3_buf, sizeof(*test_msg)) != 0)
	    {
		    //cout<<"wrong decrypted message, invalid user"<<endl;
		    die("wrong decrypted message, invalid user");
	    }
	    
	    // send cert
	    for (int i = 0; i < rcpt_number; i++)
	    {
            	    //FILE *rcptfp = NULL;
		    char path[1000]; 
		    sprintf(path, "../ca/intermediate/certs/www.%s.com.cert.pem", rcpt_name[i]);
		    //printf("path: %s\n", path);
		    send_certificate(ssl, path);
	    }
	    
	    // save message to mailbox
	    //FILE *rcptfp = NULL;
	    for (int i = 0; i < rcpt_number; i++)
	    {
		    FILE *rcptfp = NULL;
		    char mail_path[1000];
		    sprintf(mail_path, "../mailbox/%s/%s", rcpt_name[i], sendername);
		    //printf("mail_path: %s\n", mail_path);
		    rcptfp = fopen(mail_path, "wb"); 
		    char read4_buf[25600];
		    int read4 = SSL_read(ssl, read4_buf, sizeof(read4_buf));
		    if(fwrite(read4_buf, 1, read4, rcptfp) != (size_t)read4)
		    {
			    cout<<"fwrite for "<<rcpt_name[i]<<" failed"<<endl;
		    }
		    fclose(rcptfp);
	    }
	    //fclose(rcptfp);
	    RSA_free(rsa);
    }
    else
    {
        cout<<"sendmsg() request start"<<endl;
        //get recv username
        char read2_buf[1000];
	    int read2 = SSL_read(ssl, read2_buf, sizeof(read2_buf));
	    char recv_user[read2];
	    strncpy(recv_user, read2_buf, read2);
	    recv_user[read2]  = '\0';
        printf("resv: %s\n", recv_user);
        //send encrpted message
        const char *test_msg = "hahaha";
    	char encrypt_msg[2560];
    	auto rsa = EVP_PKEY_get1_RSA(pubkey);
    	int enc = RSA_public_encrypt(flen, (const unsigned char *)test_msg, (unsigned char *)encrypt_msg, rsa, padding);
    	//printf("%s\n", encrypt_msg);
	if (enc == -1)
	{
		die("RSA_public_encrypt failed");
	}
    	SSL_write(ssl, encrypt_msg, sizeof(encrypt_msg));
        // verify decrypted message
	    char read3_buf[20];
	    int read3 = SSL_read(ssl, read3_buf, sizeof(read3_buf));
	    if (read3 <= 0)
	    {
		    die("failed to  read decrypted message from the client");
	    }
	    if (strncmp(test_msg, read3_buf, sizeof(*test_msg)) != 0)
	    {
		    cout<<"wrong decrypted message, invalid user"<<endl;
		    die("user does not have the correct private key");
	    }
        else
        {
            cout<<"decrpt success\n";
        }
        
        //Not real implementation, just for testing
        char recv_path[1000];
        //sprintf(recv_path, "../mailbox/%s", recv_user);
        DIR *d;
        struct dirent *dir;
        d = opendir(recv_path);
        int msg_num = 0;
        if (d) 
        {
            while ((dir = readdir(d)) != NULL)
            {   
                if(string(dir->d_name) == "." || string(dir->d_name) == "..")
                {
                    continue;
                }
                printf("sender name: %s\n", dir->d_name);
                msg_num = msg_num + 1;
            }
            closedir(d);
        }
        char num_msg[100];
        sprintf(num_msg, "%d", msg_num);
        printf("msg_num_int: %d\n", msg_num);
        printf("msg_num: %s\n", num_msg);
        SSL_write(ssl, num_msg, strlen(num_msg));
        
        DIR *d2;
        struct dirent *dir2;
        d2 = opendir(recv_path);
        if (d2) 
        {
            while ((dir2 = readdir(d2)) != NULL)
            {   
                if(string(dir2->d_name) == "." || string(dir2->d_name) == "..")
                {
                    continue;
                }
                printf("sender name: %s\n", dir2->d_name);
                string sender_cert_path_temp = "../ca/intermediate/certs/www." +string(dir2->d_name)+ ".com.cert.pem";
                const char *sender_cert_path = sender_cert_path_temp.c_str();
                string msg_path_temp = "../mailbox/"+string(recv_user)+"/"+string(dir2->d_name);
                const char *msg_path = msg_path_temp.c_str();
                send_certificate(ssl, sender_cert_path);
                FILE *fp_ver = NULL;
                fp_ver = fopen(msg_path, "rb");
                if (fp_ver == 0)
                {
                    cout<<"fopen failed to open "<<msg_path<<endl;
                }
                fseek(fp_ver, 0, SEEK_END);
                size_t size = ftell (fp_ver);
                rewind(fp_ver);
                char *buf = (char*) malloc (sizeof(char) * size);
                if (buf == NULL)
                {
                    die("malloc in send_certificate failed");
                }
                //cout<<"sizeof buf: "<<size<<endl;
                if (fread(buf, 1, size, fp_ver) != size)
                {
                    cout<<"fread failed"<<endl;
                }
                SSL_write(ssl, buf, size);
                fclose(fp_ver);
                free(buf);
            }
            closedir(d2);
        }
        RSA_free(rsa);
    }
    /*
    //generate encrypt_msg
    char *test_msg = "Pass Pass Pass Pass Pass";
    char encrypt_msg[2560];
    auto rsa = EVP_PKEY_get1_RSA(pubkey);
    int enc = RSA_public_encrypt(flen, (const unsigned char *)test_msg, (unsigned char *)encrypt_msg, rsa, padding);
    printf("%s\n", encrypt_msg);
    SSL_write(ssl, encrypt_msg, sizeof(encrypt_msg));
    */
    BIO_free(bio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    X509_free(certificate);
    //X509_free(selfCert);
    EVP_PKEY_free(pubkey);
    //EVP_PKEY_free(rsa);

    close(clientSock);
    return 0;
}
