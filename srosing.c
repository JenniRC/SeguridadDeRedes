#include <openssl/sha.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdbool.h>
//gcc -Wall -g srosing.c -lssl -lcrypto -o sign
//./sign -v signature.pem myfile.txt pubkey.pem
//./sign myfile.txt privkey.pem
enum{
	BUF_LENGTH = 4096,
	MSG_TO_SIGN_SIZE = (4096/8),
	STDOUT = 1,
	PADDING_LEN = MSG_TO_SIGN_SIZE-SHA512_DIGEST_LENGTH,
	READ_LEN_DES_PEM = 512,
};
static const unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
									0x06, 0x09, 0x60, 0x86,
									0x48, 0x01, 0x65, 0x03,
									0x04, 0x02, 0x03, 0x05,
									0x00, 0x04, 0x40};
static const int flagerr=1;

static int
openFile(char *f, mode_t mode)
{
	int fd;
	fd = open(f, mode);
	if(fd < 0 ){
		err(1, "open: %s", f);
	}
	return fd;
}
static FILE *
openFFile(char *f)
{
	FILE * key;
	key = fopen(f,"r");
	if(key == NULL){
       	err(1,"fopen Error!!!");
    }
    return key;
}

void 
feedSha(SHA512_CTX *c,int fd,char *file,unsigned char md[])
{
	int l;
	if(SHA512_Init(c) == 0 ){
		err(1, "SHA512_Init");
	}
	char *buf = malloc(BUF_LENGTH);
	while ((l = read(fd, buf, BUF_LENGTH)) > 0){
		SHA512_Update(c, buf, l);
	}
	if(l < 0 ){
		err(1, "read error");
	}
	SHA512_Update(c, file, strlen(file));
	SHA512_Final(md,c);
	free(buf);
	close(fd);
}

void
pem (unsigned char sign[])
{
	BIO *b64,*bio;
	char begin[] = "---BEGIN SRO SIGNATURE---\n";
	char end[] = "---END SRO SIGNATURE---\n";
	write(STDOUT,begin,strlen(begin));
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fd(STDOUT,BIO_CLOSE);
	BIO_push(b64,bio);
	BIO_write(b64,sign,MSG_TO_SIGN_SIZE);
	BIO_flush(b64);
	write(STDOUT,end,strlen(end));
	BIO_free_all(b64);
}

void 
pem_desaplana (FILE *f,unsigned char *buf)
{
	BIO *bio, *b64;
 	int inlen;
 	b64 = BIO_new(BIO_f_base64());
 	bio = BIO_new_fp(f, BIO_NOCLOSE);
 	BIO_push(b64,bio);
 	while((inlen = BIO_read(b64, buf, READ_LEN_DES_PEM)) > 0){}
 	BIO_free_all(b64);
 	fclose(f);
}

void
create_padding(unsigned char padding[])
{
	int ID_len = sizeof(EMSASHA512ID);
	int t_len = SHA512_DIGEST_LENGTH + ID_len;
	int ps_len = MSG_TO_SIGN_SIZE-t_len-3;
	unsigned char PS[ps_len];
	unsigned char *aux = NULL;
	int i;
	for (i=0;i< ps_len;i++){
		PS[i] = 0xFF;
	}
	unsigned char zero[] = {0x00};
	unsigned char one[] = {0x01};
	memcpy(padding,zero,sizeof(zero));
	aux = padding + sizeof(zero);
	memcpy(aux,one,sizeof(one));
	aux = aux + sizeof(one);
	memcpy(aux,PS,ps_len);
	aux=aux+ps_len;
	memcpy(aux,zero,sizeof(zero));
	aux=aux+sizeof(zero);
	memcpy(aux,EMSASHA512ID,ID_len);
}

bool
check_padding(unsigned char sign[])
{
	unsigned char padding[PADDING_LEN];
	create_padding(padding);
	unsigned char padding_sign[PADDING_LEN];
	memcpy(padding_sign,sign,PADDING_LEN);
	return (memcmp(padding,padding_sign,PADDING_LEN)==0);
}

bool
check_hash(unsigned char sign[],int fd,char *file_path)
{
	unsigned char *aux;
	SHA512_CTX context;
	aux = sign + PADDING_LEN;
	unsigned char hash_origin[SHA512_DIGEST_LENGTH];
	unsigned char hash_file[SHA512_DIGEST_LENGTH];
	memcpy(hash_origin,aux,SHA512_DIGEST_LENGTH);
	feedSha(&context,fd,file_path,hash_file);
	return (memcmp(hash_origin,hash_file,SHA512_DIGEST_LENGTH)==0);
}

bool
decode(unsigned char *buf,RSA *RSA_key,int file_to_check,char *file_path)
{
	unsigned char sign_decode[MSG_TO_SIGN_SIZE];
	if ((RSA_public_decrypt(RSA_size(RSA_key),buf,sign_decode,RSA_key,RSA_NO_PADDING)!=-1) && check_padding(sign_decode)){
			return check_hash(sign_decode,file_to_check,file_path);
	}else{
		return false;
	}
}

void
create_msg(unsigned char msg[],unsigned char hash[])
{
	unsigned char padding[PADDING_LEN];
	create_padding(padding);
	unsigned char *aux;
	memcpy(msg,padding,PADDING_LEN);
	aux = msg + PADDING_LEN;
	memcpy(aux,hash,SHA512_DIGEST_LENGTH);
}

void
sign_hash(unsigned char hash[], RSA *RSA_key)
{
	unsigned char msg[MSG_TO_SIGN_SIZE];
	create_msg(msg,hash);
	int rsa_size = RSA_size(RSA_key);
	unsigned char sign[rsa_size];
	RSA_private_encrypt(MSG_TO_SIGN_SIZE,msg,sign,RSA_key,RSA_NO_PADDING);
	pem(sign);
}

int 
main(int argc, char *argv[]){
	SHA512_CTX context;
	int fd,file_check;
	FILE *key;
	unsigned char md[SHA512_DIGEST_LENGTH];
	unsigned char buf[MSG_TO_SIGN_SIZE];
	RSA *RSA_key = RSA_new();
	int flag=0;

	if(argc > 2){
		if(strcmp(argv[1],"-v")==0)	flag=1;
	}
	if(argc == 3){
		fd=openFile(argv[1],O_RDONLY);
		key = openFFile(argv[2]);
		feedSha(&context,fd,argv[1],md);
		RSA_key = PEM_read_RSAPrivateKey(key,NULL,NULL,NULL);
		if(RSA_key == NULL)		err(1, "PEM_read_RSAPrivateKey");

		sign_hash(md,RSA_key);
		close(fd);
		exit(EXIT_SUCCESS);
	}
	if((argc==5) & flag){
		FILE * sign = openFFile(argv[2]);
		key = openFFile(argv[4]);
		file_check = openFile(argv[3],O_RDONLY);
		pem_desaplana(sign,buf);
		RSA_key = PEM_read_RSA_PUBKEY(key,NULL,NULL,NULL);
		if(RSA_key == NULL)		err(1, "PEM_read_RSAPublicKey");
		if(decode(buf,RSA_key,file_check,argv[3])){
			close(file_check);
			exit(EXIT_SUCCESS);
		}else{
			if(flagerr)	err(1, "Incorrect signature");
			exit(EXIT_FAILURE);
		}
	}
	if((argc!=3) & !flag & flagerr){
		err(1, "Incorrect arguments : ./sign <file_to_sign> <private_key_RSA>\n");
		exit(EXIT_FAILURE);
	}
	if((argc!=5) & flag & flagerr){
		err(1, "Incorrect arguments : ./sign [-v] <file_sign> <signed_data> <public_key_RSA>\n");
		exit(EXIT_FAILURE);
	}
}
