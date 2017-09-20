#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>

/*

Found this in /proc/crypto
name         : cbc(aes)
driver       : cbc-aes-aesni
module       : aesni_intel
priority     : 400
refcnt       : 1
selftest     : passed
internal     : no
type         : ablkcipher
async        : yes
blocksize    : 16
min keysize  : 16
max keysize  : 32
ivsize       : 16
geniv        : <default>

name         : ecb(aes)
driver       : ecb-aes-aesni
module       : aesni_intel
priority     : 400
refcnt       : 1
selftest     : passed
internal     : no
type         : ablkcipher
async        : yes
blocksize    : 16
min keysize  : 16
max keysize  : 32
ivsize       : 0
geniv        : <default>


*/

// These don't seem to be exported by whatever should be providing them
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct enc_t {
  int opfd;
  int tfmfd;
  	struct sockaddr_alg sa;
    struct msghdr msg;
  	struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)];
    char buf[16];
  	struct af_alg_iv *iv;
  	struct iovec iov;
  	int i;
};

void enc_init(struct enc_t *args) {
  //AF_ALG example
  printf("Checking if AF_ALG is available.\r\n");

  //Check if AF_ALG is available
  int sock;
  if((sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1){
    fprintf(stderr, "Error: %s\r\n", strerror(errno));
  } else {
    close(sock);
    printf("AF_ALG is available.\r\n");
  }

  //Set up cipher mode
  memset(&args->sa, 0x0, sizeof(struct sockaddr_alg));
  args->sa.salg_family = AF_ALG;
  strncpy(&args->sa.salg_type, "ablkcipher", sizeof("ablkcipher"));
  strncpy(&args->sa.salg_name, "cbc(aes)", sizeof("cbc(aes)"));

  printf("type: %s\r\n", args->sa.salg_type);
  printf("name: %s\r\n", args->sa.salg_name);


  //Clear out structs
  memset(&args->msg, 0x0, sizeof(struct msghdr));
  memset(args->cbuf, 0x0, CMSG_SPACE(4) + CMSG_SPACE(20));

  //Open socket
  if((args->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1){
    fprintf(stderr, "Error opening socket: %s\r\n", strerror(errno));
  }

  //Bind to socket
  if(bind(args->tfmfd, (struct sockaddr *)&args->sa, sizeof(args->sa)) != 0){
    fprintf(stderr, "Failed to bind: %s\r\n", strerror(errno));
  }
}

enc_set_key(struct enc_t *args, const char *key) {
  setsockopt(args->tfmfd, SOL_ALG, ALG_SET_KEY, key, 16);

	if((args->opfd = accept(args->tfmfd, NULL, 0)) < 0) {
    fprintf(stderr, "Failed to accept: %s\r\n", strerror(errno));
  };
}

enc_enc(struct enc_t *args, char * dst, const char *src) {
  args->msg.msg_control = args->cbuf;
	args->msg.msg_controllen = sizeof(args->cbuf);

  args->cmsg = CMSG_FIRSTHDR(&args->msg);
  if(args->cmsg == NULL){
    fprintf(stderr, "CMSG error\r\n");
  }

	args->cmsg->cmsg_level = SOL_ALG;
	args->cmsg->cmsg_type = ALG_SET_OP;
	args->cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(args->cmsg) = ALG_OP_ENCRYPT;

	args->cmsg = CMSG_NXTHDR(&args->msg, args->cmsg);
  if(args->cmsg == NULL) {
    fprintf(stderr, "error with cmsg\r\n");
    exit(0);
  }

	args->cmsg->cmsg_level = SOL_ALG;
	args->cmsg->cmsg_type = ALG_SET_IV;
	args->cmsg->cmsg_len = CMSG_LEN(20);
	args->iv = (void *)CMSG_DATA(args->cmsg);
	args->iv->ivlen = 16;
	memcpy(args->iv->iv, "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
		       "\xb4\x22\xda\x80\x2c\x9f\xac\x41", 16);

	args->iov.iov_base = "Single block msg";
	args->iov.iov_len = 16;

	args->msg.msg_iov = &args->iov;
	args->msg.msg_iovlen = 1;

  int sent;
	if((sent = sendmsg(args->opfd, &args->msg, MSG_MORE)) != 16){
    fprintf(stderr, "Only sent %d bytes!\r\n", sent);
  }
  int r;
  if((r = read(args->opfd, dst, 16)) != 16){
    fprintf(stderr, "Only read %d bytes!\r\n", r);
  }


}

enc_close(struct enc_t *args){
  close(args->opfd);
  close(args->tfmfd);
}

enc_print(char *data, size_t len){
  int i;
  for (i = 0; i < len; i++) {
    printf("%02x", (unsigned char)data[i]);
  }
  printf("\n");
}

int main(void) {
  struct enc_t e;
  char result[16];
  memset(result, 0x00, 16);

  char input[16];
  strncpy(input, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);

  const char key[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

  enc_init(&e);
  enc_set_key(&e, key);
  enc_enc(&e, result, input);
  enc_close(&e);


  enc_print(input, 16);
  enc_print(key, 16);
  enc_print(result, 16);


  //
  //
	// int opfd;
	// int tfmfd;
	// struct sockaddr_alg sa = {
	// 	.salg_family = AF_ALG,
	// 	.salg_type = "ablkcipher",
	// 	.salg_name = "cbc(aes)"
	// };
	// struct msghdr msg = {};
	// struct cmsghdr *cmsg;
  //
  // // Must be cleared!
	// char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {};
  //
	// char buf[16];
	// struct af_alg_iv *iv;
	// struct iovec iov;
	// int i;
  //
	// tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  //
	// bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
  //
	// setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY,
	// 	   "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
	// 	   "\x51\x2e\x03\xd5\x34\x12\x00\x06", 16);
  //
	// opfd = accept(tfmfd, NULL, 0);
  //
	// msg.msg_control = cbuf;
	// msg.msg_controllen = sizeof(cbuf);
  //
	// cmsg = CMSG_FIRSTHDR(&msg);
	// cmsg->cmsg_level = SOL_ALG;
	// cmsg->cmsg_type = ALG_SET_OP;
	// cmsg->cmsg_len = CMSG_LEN(4);
	// *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;
  //
	// cmsg = CMSG_NXTHDR(&msg, cmsg);
  // if(cmsg == NULL) {
  //   fprintf(stderr, "error with cmsg\r\n");
  //   exit(0);
  // }
  //
	// cmsg->cmsg_level = SOL_ALG;
	// cmsg->cmsg_type = ALG_SET_IV;
	// cmsg->cmsg_len = CMSG_LEN(20);
	// iv = (void *)CMSG_DATA(cmsg);
	// iv->ivlen = 16;
	// memcpy(iv->iv, "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
	// 	       "\xb4\x22\xda\x80\x2c\x9f\xac\x41", 16);
  //
	// iov.iov_base = "Single block msg";
	// iov.iov_len = 16;
  //
	// msg.msg_iov = &iov;
	// msg.msg_iovlen = 1;
  //
	// sendmsg(opfd, &msg, MSG_MORE);
	// read(opfd, buf, 16);
  //
	// for (i = 0; i < 16; i++) {
	// 	printf("%02x", (unsigned char)buf[i]);
	// }
	// printf("\n");
  //
	// close(opfd);
	// close(tfmfd);
  //
	// return 0;
}
