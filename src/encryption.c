#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>


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

int enc_init(struct enc_t *args) {
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
  strncpy(&args->sa.salg_type, "skcipher", sizeof(args->sa.salg_type));
  strncpy(&args->sa.salg_name, "cbc(aes)", sizeof(args->sa.salg_name));

  printf("type: %s\r\n", args->sa.salg_type);
  printf("name: %s\r\n", args->sa.salg_name);


  //Clear out structs
  memset(&args->msg, 0x0, sizeof(struct msghdr));
  memset(args->cbuf, 0x0, CMSG_SPACE(4) + CMSG_SPACE(20));

  //Open socket
  if((args->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1){
    fprintf(stderr, "Error opening socket: %s\r\n", strerror(errno));
    return EXIT_FAILURE;
  }

  //Bind to socket
  if(bind(args->tfmfd, (struct sockaddr *)&args->sa, sizeof(args->sa)) != 0){
    fprintf(stderr, "Failed to bind: %s\r\n", strerror(errno));
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
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
	memcpy(args->iv->iv, "\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00", 16);

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

  if(enc_init(&e) != EXIT_SUCCESS){
    return EXIT_FAILURE;
  };
  enc_set_key(&e, key);
  enc_enc(&e, result, input);
  enc_close(&e);


  enc_print(input, 16);
  enc_print(key, 16);
  enc_print(result, 16);

}
