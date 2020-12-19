#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/cms.h>

using namespace std;
/*
 * Compile with -lssl -lcrypto
 *
 */
static char const *CACert = "../ca/intermediate/certs/ca-chain.cert.pem";
static int padding = RSA_PKCS1_OAEP_PADDING;
static void die(const char *msg)
{
    perror(msg);
	exit(1);
}

static void verify_certificate(SSL *ssl)
{
	int err = SSL_get_verify_result(ssl);
	if (err != X509_V_OK)
	{
		const char *message = X509_verify_cert_error_string(err);
		fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
	}
	X509 *cert = SSL_get_peer_certificate(ssl);
	if (cert == nullptr)
	{
		fprintf(stderr, "No certificate was presented by the server\n");
    }
	X509_free(cert);
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
		//die("malloc in send_certificate failed");
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

int main(int argc, char **argv)
{   
	/* ./recvmsg localhost 8888 username */
    if (argc != 3)
    {
    	//die("./recvmsg localhost 8888 username");
	}	
    char *hostName = argv[1];
    int portNum  = atoi(argv[2]);
	string userName = argv[3];
	string funcName_temp = "recvmsg()";
	const char *funcName = funcName_temp.c_str();
	string CertFile_temp = "../ca/intermediate/certs/www."+userName+ ".com.cert.pem";
	string KeyFile_temp  = "../ca/intermediate/private/www."+userName+".com.key.pem";
	const char *CertFile = CertFile_temp.c_str();
	const char *KeyFile  = KeyFile_temp.c_str();
	//prepare "username recpt1 recpt2 recpt3"
	const char *user_rcpt = userName.c_str();

	//ALL Pointers to be free
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	const SSL_METHOD *meth = NULL;
	RSA *rsa = NULL;
	BIO *bio_enc = NULL;
	X509 *certificate = NULL;
	EVP_PKEY *pubkey = NULL;
	RSA *rsa_pubkey = NULL;
	BIO *in_sign = NULL;
	EVP_PKEY *skey = NULL;
	X509 *scert = NULL;
	BIO *out_sign = NULL;

	int err; string s;
	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */
	OpenSSL_add_all_ciphers();

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    	// Load Client Certificate
	ssl = SSL_new(ctx);
    int use_certificate_file = SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM);
    int use_PrivateKey_file = SSL_CTX_use_PrivateKey_file(ctx,KeyFile, SSL_FILETYPE_PEM);
	int load_verify_locations = SSL_CTX_load_verify_locations(ctx,CACert,NULL);
	int check_private_key = SSL_CTX_check_private_key(ctx);
	if (use_certificate_file == 0 || use_PrivateKey_file == 0 || load_verify_locations == 0 || check_private_key == 0)
	{	
		die("lode Certificate or Keyfile failed");
	}
	if ( !SSL_CTX_check_private_key(ctx) )
	{	
		die("Private key does not match the public certificate");
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(portNum);

	he = gethostbyname(hostName);
	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
		perror("connect");
		return 2;
	}

	SSL_set_fd(ssl, sock);

	err = SSL_connect(ssl);
	if (SSL_connect(ssl) != 1) {
		switch (SSL_get_error(ssl, err)) {
			case SSL_ERROR_NONE: s="SSL_ERROR_NONE"; break;
			case SSL_ERROR_ZERO_RETURN: s="SSL_ERROR_ZERO_RETURN"; break;
			case SSL_ERROR_WANT_READ: s="SSL_ERROR_WANT_READ"; break;
			case SSL_ERROR_WANT_WRITE: s="SSL_ERROR_WANT_WRITE"; break;
			case SSL_ERROR_WANT_CONNECT: s="SSL_ERROR_WANT_CONNECT"; break;
			case SSL_ERROR_WANT_ACCEPT: s="SSL_ERROR_WANT_ACCEPT"; break;
			case SSL_ERROR_WANT_X509_LOOKUP: s="SSL_ERROR_WANT_X509_LOOKUP"; break;
			case SSL_ERROR_WANT_ASYNC: s="SSL_ERROR_WANT_ASYNC"; break;
			case SSL_ERROR_WANT_ASYNC_JOB: s="SSL_ERROR_WANT_ASYNC_JOB"; break;
			case SSL_ERROR_SYSCALL: s="SSL_ERROR_SYSCALL"; break;
			case SSL_ERROR_SSL: s="SSL_ERROR_SSL"; break;
		}
		fprintf(stderr, "SSL error: %s\n", s.c_str());
		ERR_print_errors_fp(stderr);
		return 3;
	}
	verify_certificate(ssl);
	//send_certificate
	send_certificate(ssl, CertFile);
	//send_functionName
	SSL_write(ssl, funcName, strlen(funcName));
	//send_userName_recepients
	SSL_write(ssl, user_rcpt, strlen(user_rcpt));
	//receive msg and decrypt it
	char encrypt_msg[25600];
	char decrypt_msg[25600];
	SSL_read(ssl, encrypt_msg, sizeof(encrypt_msg));
	FILE *fp = fopen(KeyFile, "rb");
	if(!fp)
	{
		die("fopen() failed");
	}
	//rsa_priv = RSA_new();
	rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if(rsa == NULL)
	{
		die("read_rsa() failed");
	}
	fclose(fp);
	RSA_private_decrypt(256, (const unsigned char *)encrypt_msg, (unsigned char *)decrypt_msg, rsa, padding);;
	SSL_write(ssl, decrypt_msg, strlen(decrypt_msg));
	//read number of msgs
	char num_msg[10];
	int num_bytes = SSL_read(ssl, num_msg, sizeof(num_msg));
	num_msg[num_bytes] = '\0';
	int num = atoi(num_msg);
	// verify and decrpt
	for (int i = 0; i < num; i++)
	{
		BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
		X509_STORE *st = NULL;
		X509 *cacert = NULL;
		CMS_ContentInfo *cms = NULL;
		st = X509_STORE_new();
		char certBuf[2560];
		SSL_read(ssl, certBuf, sizeof(certBuf));
		//tbio = BIO_new(BIO_s_mem());
		//BIO_write(tbio, certBuf, cert_bytes + 1);
		tbio = BIO_new_file("../ca/intermediate/certs/cacert.pem", "r");
		cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
		if (cacert == NULL)
		{
			die("cacert is NULL");
		}
		if (!X509_STORE_add_cert(st, cacert))
		{
			die("add failed()\n");
		}
		//in = BIO_new_file("sign_out.txt","r");
		char verBuf[25600];
		int verBytes = SSL_read(ssl, verBuf, sizeof(verBuf));
		in = BIO_new(BIO_s_mem());
		BIO_write(in, verBuf, verBytes + 1);
		if (in == NULL)
		{
			die("in is NULL\n");
		}
		cms = SMIME_read_CMS(in, &cont);
		if (cms == NULL)
		{
			die("cms is NULL\n");
		}
		out = BIO_new_file("verify.txt", "w");
		if(!CMS_verify(cms, NULL, st, cont, out, 0))
		{
			die("vertify failed\n");
		}
		else
		{
			printf("verify success\n");
		}
		//decrypt msg
		CMS_ContentInfo_free(cms);
		X509_free(cacert);
		BIO_free(in);
		BIO_free(out);
		BIO_free(tbio);
		BIO_free(cont);
		EVP_PKEY *rkey = NULL;
		FILE *fp_key = fopen(KeyFile, "rb");
		if(!fp_key)
		{
			die("fopen() failed");
		}
		rkey = PEM_read_PrivateKey(fp_key, NULL, NULL, NULL);
		X509 *rcert = NULL;
		FILE *fp_cert = fopen(CertFile, "rb");
		if(!fp_cert)
		{
			die("fopen() failed");
		}
		rcert = PEM_read_X509(fp_cert, NULL, NULL, NULL);
		BIO *in_enc = BIO_new_file("verify.txt", "rb");
		CMS_ContentInfo *cms_enc = SMIME_read_CMS(in_enc, NULL);
		string store_path = userName + to_string(i) + ".txt";
		BIO *out_enc = BIO_new_file(store_path.c_str(), "w");
		CMS_decrypt(cms_enc, rkey, rcert, NULL, out_enc, 0);
		remove("verify.txt");
	}
	SSL_free(ssl);
	SSL_CTX_free(ctx);;
	BIO_free(bio_enc);
	BIO_free(in_sign);
	BIO_free(out_sign);
	X509_free(certificate);
	X509_free(scert);
	RSA_free(rsa);
	RSA_free(rsa_pubkey);
	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(skey);
	
	return 0;
}
