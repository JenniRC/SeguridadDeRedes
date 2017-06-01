#include <openssl/sha.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>

static const int KEY = 64;
static const int SHA_DIGESTSIZE = 20;
static const int DEBUG=0;
void 
feedSha2(SHA_CTX *ctx, unsigned char *k_xpd){
	if(SHA1_Init(ctx) == 0) {
		err(1, "SHA1_Init");
	}
	if(SHA1_Update(ctx, k_xpd, KEY)==0){
		err(1, "SHA1_Update");
	}
}
int 
readDataFile(int fd,SHA_CTX *ctx)
{
	int l=0;
	int nr=0;
	unsigned char data[1024];
	memset(data , 0, 1024 );
	while ((l = read(fd, data, 1024)) > 0){
		nr=nr+l;
		if(DEBUG){
			fprintf(stderr, "he leido %d bytes en total \n",nr );
		}
		if(SHA1_Update(ctx, data, l)==0){
			err(1, "SHA1_Update");
		}
	}
	close(fd);
	return nr;
}
int
feedSha1(SHA_CTX *ctx, unsigned char *k_xpd,unsigned char *md,int fddata)
{
	if(SHA1_Init(ctx) == 0) {
		err(1, "SHA1_Init");
	}
    if(SHA1_Update(ctx, k_xpd, KEY)==0){
		err(1, "SHA1_Update");
	}
   	readDataFile(fddata,ctx);
    if(SHA1_Final(md,ctx)==0){
    	err(1,"SHA1_Final");
    }
	return 1;
}
void
doPadding(unsigned char *k_ipad,unsigned char *k_opad,unsigned char *key)
{
	memset(k_ipad , 0, KEY );
    memset(k_opad , 0, KEY );
	int i;
	for (i = 0; i < KEY; i++) {
        k_ipad[i] = key[i]^0x36;
    	k_opad[i] = key[i]^0x5C;
    }
}
/*HMAC Algorithm H[ (k xor o_pad)|| H ((k xor i_pad) || M) ]*/
void
hmac_sha1(unsigned char * key, int keylen,int fddata)
{
    unsigned char   k_ipad[KEY],
                    k_opad[KEY],
    				md[SHA_DIGESTSIZE],
    				md2[SHA_DIGESTSIZE];
    int    i;
    SHA_CTX	ctx;
   	SHA_CTX	ctx2;
   	if(DEBUG){
   		fprintf(stderr, "Key in hex \n" );
    	for(i=0;i<KEY;i++){
    		fprintf(stderr, "%02x",key[i] );
    	}
    	fprintf(stderr, "\n" );
	}
    /*First step -> obtain (k xor i_pad) && (k xor o_pad)*/
    doPadding(k_ipad,k_opad,key);
    if(DEBUG){ 
    	fprintf(stderr, "K_ipad in hex \n" );
    	for(i=0;i<KEY;i++){
    		fprintf(stderr, "%02x",k_ipad[i] );
   		}
        fprintf(stderr, "\n" );
    	fprintf(stderr, "K_opad in hex \n" );
    	for(i=0;i<KEY;i++){
    		fprintf(stderr, "%02x",k_opad[i] );
    	}
        fprintf(stderr, "\n" );
    }
   	/*Second step -> Obtain H[k xor ipad || m ] <- md */
    feedSha1(&ctx,k_ipad,md,fddata);
    if(DEBUG){
    	for (i = 0; i < SHA_DIGESTSIZE; i++) {
        	fprintf(stderr,"%02x",md[i] );
    	}
        fprintf(stderr, "\n" );
    }    
    /*Third step -> [(k xor o_pad)|| H ((k xor i_pad) || M) ]*/
    feedSha2(&ctx2,k_opad);
    if (SHA1_Update(&ctx2,md ,SHA_DIGESTSIZE)==0){
    	err(1, "SHA1_Update");
    }
    /*Fourth step -> H[ (k xor o_pad)|| H ((k xor i_pad) || M) ]*/
    memset(md2 , 0, SHA_DIGESTSIZE );
    if(SHA1_Final(md2,&ctx2)==0){
    	err(1,"SHA1_Final");
    }
	for (i = 0; i < SHA_DIGESTSIZE; i++) {
        printf("%02x",md2[i] );
    }
    printf( "\n" );
}
int
openFile(char *f, mode_t mode)
{
	int fd;
	fd = open(f, mode);
	if(fd < 0 ){
		err(1, "open: %s", f);
	}
	return fd;
}
int 
readKeyFile(int fd,unsigned char *key)
{
	int l;
	int nr=0;
	while (((l = read(fd, key, KEY)) > 0) && (nr+l<=KEY)){
		nr=nr+l;
		if(nr > KEY){
			break;
		}
	}
	close(fd);
	return nr;
}

int
main(int argc, char *argv[]){

	if (argc != 3) {
		err(1, "Incorrect arguments");
		exit(EXIT_FAILURE);
	}
	unsigned char key[KEY];
	memset(key , 0, KEY );

	int fdkey=openFile(argv[2],O_RDONLY);
	int fddata=openFile(argv[1],O_RDONLY);

    int keylen=readKeyFile(fdkey,key);
    hmac_sha1( key, keylen, fddata);
	exit(EXIT_SUCCESS);
}
