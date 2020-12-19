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
static string validUser[35] = {"addleness", "analects", "annalistic", "anthropomorphologically," "blepharosphincterectomy",
 "corecto", "durwaun", "dysphasia," "encampment", "endoscopic", "exilic", "forfend", "gorbellied", "gushiness", "muermo",
  "neckar", "outmate", "outroll", "overrich", "philosophicotheological", "pockwood", "polypose", "refluxed",
   "reinsure", "repine", "scerne", "starshine", "unauthoritativeness", "unminced", "unrosed", "untranquil", "urushinic", "vegetocarbonaceous", "wamara", "whaledom"};

static bool my_find(string str)
{
	for (int i = 0; i < 35; i++)
	{
		if(str == validUser[i])
		{
			return 1;
		}
	}
	return 0;
}
int main(int argc, char **argv)
{   
	/* ./sendmsg localhost 8888 username rcpt1 rcpt2 rcpt3 */
    if (argc <5)
    {
    	die("./sendmsg localhost 8888 username rcpt1 rcpt2 rcpt3");
	}	
    char *hostName = argv[1];
    int portNum  = atoi(argv[2]);
	string userName = argv[3];
	if (my_find(userName)==0)
	{
		die("wrong username");
	}
	string funcName_temp = "sendmsg()";
	const char *funcName = funcName_temp.c_str();
	string CertFile_temp = "../ca/intermediate/certs/www."+userName+ ".com.cert.pem";
	string KeyFile_temp  = "../ca/intermediate/private/www."+userName+".com.key.pem";
	const char *CertFile = CertFile_temp.c_str();
	const char *KeyFile  = KeyFile_temp.c_str();
	//prepare "username recpt1 recpt2 recpt3"
	string user_rcpt_tmp = "";
	for (int i = 4; i < argc; i++)
	{	
		if (my_find(argv[i]) == 0)
		{
			die("wrong recipients");
		}
		user_rcpt_tmp += argv[i];
		if(i != argc -1)
		{
			user_rcpt_tmp += " ";
		}
	}
	user_rcpt_tmp = userName + " " + user_rcpt_tmp;
	const char *user_rcpt = user_rcpt_tmp.c_str();

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
	//sleep(0.5);
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
	//recv recipients certificate
	int numOfrcpt = argc - 4;
	char certBuf[numOfrcpt][2560];
	int cert_size[numOfrcpt];
	for (int i = 0; i < numOfrcpt; i++)
	{
		int bytes = SSL_read(ssl, certBuf[i], sizeof(certBuf[i]));
		cert_size[i] = bytes;
	}
	//encrypt sign each message (read from stdin)
	std::istreambuf_iterator<char> begin(std::cin), end;
    std::string msg_content(begin, end);
	if(msg_content.size() > 2000)
	{
		die("msg size > 2000 bytes");
	}
	const char *msg = msg_content.c_str();
	for (int i = 0; i < numOfrcpt; i++)
	{	
		int flags1 = CMS_STREAM;
		BIO *bio_enc = BIO_new(BIO_s_mem());
		BIO_write(bio_enc, certBuf[i], cert_size[i]+1);
		X509 *certificate = PEM_read_bio_X509(bio_enc, NULL, NULL, NULL);
		BIO *in1 = NULL, *out1 = NULL;
   	 	STACK_OF(X509) *recips = NULL;
    	CMS_ContentInfo *cms1 = NULL;
		recips = sk_X509_new_null();
		sk_X509_push(recips, certificate);
		in1 = BIO_new(BIO_s_mem());
		BIO_write(in1, msg, strlen(msg));
		cms1 = CMS_encrypt(recips, in1, EVP_des_ede3_cbc(), flags1);
		string cipher_path = "cipher" + to_string(i) + ".txt";
		out1 = BIO_new_file(cipher_path.c_str(), "wb");
		SMIME_write_CMS(out1, cms1, in1, flags1);
		if(cms1 == NULL)
			printf("NULL\n");
		CMS_ContentInfo_free(cms1);
    	//X509_free(certificate);
    	sk_X509_pop_free(recips, X509_free);
    	BIO_free(in1);
    	BIO_free(out1);
		BIO_free(bio_enc);
	}
	for (int i = 0; i < numOfrcpt; i++)
	{
		int flags = CMS_DETACHED | CMS_STREAM;
		string cipher_path = "cipher" + to_string(i) + ".txt";
		BIO *in_sign = BIO_new_file(cipher_path.c_str(), "rb");
		BIO *tbio = BIO_new_file("../ca/intermediate/certs/signer.pem", "r");
		X509 *scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
		BIO_reset(tbio);
		EVP_PKEY *skey =  PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
		CMS_ContentInfo *cms = CMS_sign(scert, skey, NULL, in_sign, flags);
		if(!cms)
		{
			die("CMS_sing() failed");
		}
		BIO *out_sign = BIO_new_file("sign_out.txt", "w");
		if (!(flags & CMS_STREAM))
        	BIO_reset(in_sign);
		if(!SMIME_write_CMS(out_sign, cms, in_sign, flags))
		{
			die("SMITE_write_CMS() failed");
		}
		CMS_ContentInfo_free(cms);
		X509_free(scert);
		EVP_PKEY_free(skey);
		BIO_free(in_sign);
		BIO_free(out_sign);
		BIO_free(tbio);
		
		char output[25600]; //msg 
		FILE *fp_sign = fopen("sign_out.txt", "rb");
		if (fp_sign == NULL)
		{
			die("fopen() failed");
		}
		fseek(fp_sign, 0, SEEK_END);
		size_t size = ftell (fp_sign);
		rewind(fp_sign);
		if (fread(output, 1, size, fp_sign) != size)
		{
			die("fread() failed");
		}
		fclose(fp_sign);
		SSL_write(ssl, output, size);
		remove(cipher_path.c_str());
		remove("sign_out.txt");
	}
	
	SSL_free(ssl);
	SSL_CTX_free(ctx);;
	BIO_free(bio_enc);
	BIO_free(in_sign);
	BIO_free(out_sign);
	X509_free(certificate);
	//X509_free(scert);
	RSA_free(rsa);
	RSA_free(rsa_pubkey);
	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(skey);
	return 0;
}
