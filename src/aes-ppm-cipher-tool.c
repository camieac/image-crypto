/**
* @file aes-ppm-cipher-tool.c
* @author Cameron A. Craig
* @date 28 Dec 2017
* @copyright 2017 Cameron A. Craig
* @brief A tool to encrypt PPM images.
*        Used to illustrate AES ECB pattern vunerbility.
* @note  This is for illustration purposes only. Data is lost during
*        the encryption process, making decryption impossible.
* Example command:
* ./aes-ppm-cipher-tool -k 0000000000000000 -i 0000000000000000 -f ../img/scotland_20.ppm -w 20 -h 12
*
* @license GNU GPL v3.0
*/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>

// Default key and IV value is all zeros
static char key[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static char iv[]  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static char ppm_filename[] = "image.ppm";


// These don't seem to be exported by whatever should be providing them
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define AES_BLOCK_SIZE 16

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

	struct {
		bool encrypt;
		bool cbc;
		char * filename;
		int image_width;
		int image_height;
	} config
};

int enc_init(struct enc_t *args) {
  printf("Checking if AF_ALG is available.\r\n");
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

enc_enc(struct enc_t *args, char * dst, struct iovec *src_iov, size_t num_iov) {
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
		exit(EXIT_FAILURE);
	}

	args->cmsg->cmsg_level = SOL_ALG;
	args->cmsg->cmsg_type = ALG_SET_IV;
	args->cmsg->cmsg_len = CMSG_LEN(20);
	args->iv = (void *)CMSG_DATA(args->cmsg);
	args->iv->ivlen = 16;

	memcpy(args->iv->iv, iv, 16);

	args->msg.msg_iov = src_iov;
	args->msg.msg_iovlen = num_iov;

	int sent;
	if((sent = sendmsg(args->opfd, &args->msg, MSG_MORE)) == -1){
		fprintf(stderr, "Only sent %d bytes!\r\n", sent);
		fprintf(stderr, "Error: %s\r\n", strerror(errno));
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

write_buffer_to_file(unsigned char *buffer, size_t len, char *filename) {
	/* Write your buffer to disk. */
	FILE *f = fopen(filename,"wb");

	if (f){
	    fwrite(buffer, len, 1, f);
	    puts("Wrote to file!");
	} else {
	    puts("Something wrong writing to File.");
	}

	fclose(f);
}

size_t read_file_to_buffer(char * filename, unsigned char **buffer) {
	if (*buffer != NULL) {
		printf("error\r\n");
	}

	printf("Opening file\r\n");
	FILE *fp = fopen(filename, "rb");

	if(fp == NULL) {
		printf("Failed to open file.\r\n");
		exit(EXIT_FAILURE);
	}

	printf("Seeeking to end of file\r\n");
	if (fseek(fp, 0L, SEEK_END) != 0) {
		printf("Could not go to end of file.\r\n");
		exit(EXIT_FAILURE);
	}

	/* Get the size of the file. */
	long bufsize = ftell(fp);
	if (bufsize == -1) { /* Error */ }

	/* Allocate our buffer to that size. */
	*buffer = malloc(sizeof(char) * (bufsize + 1));

	printf("allocated %ld bytes for ppm file\r\n", bufsize);

	printf("Seeking to start of the file\r\n");
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		printf("Failed to seek to start of file\r\n");
		exit(EXIT_FAILURE);
	}

	printf("Reading file into memory\r\n");
	size_t newLen = fread(*buffer, sizeof(char), bufsize, fp);
	if (ferror(fp) != 0) {
		printf("Error reading file");
		exit(EXIT_FAILURE);
	}
	// printf("Terminating file\r\n");
	// buffer[newLen++] = '\0'; /* Just to be safe. */

	printf("Closing file\r\n");
	fclose(fp);

	//free(buffer); /* Don't forget to call free() later! */
	return sizeof(char) * (bufsize + 1);
}

int main(int argc, char *argv[]) {
	//We store most things in this struct
	struct enc_t e;

	/* Read options from the command line */
	//Encrypt by defualt
	e.config.encrypt = true;

	// ECB is default
	e.config.cbc = false;

	// clear filename
	e.config.filename = NULL;

	int bflag = 0;
	char *cvalue = NULL;
	int index;

	int opterr = 0;

	int c;
	while ((c = getopt (argc, argv, "edk:i:mf:w:h:")) != -1) {
		switch (c) {
			// Encrypt flag
			case 'e':
				e.config.encrypt = true;
				break;
			//Decrypt flag
			case 'd':
				e.config.encrypt = false;
				break;
			//Key (ASCII)
			case 'k':
				strncpy(key, optarg, 16);
				break;
			//IV
			case 'i':
				strncpy(iv, optarg, 16);
				break;
			//AES mode (ecb or cbc)
			case 'm':
				if(strncmp("cbc", optarg, 3) == 0){
					e.config.cbc = true;
				} else if (strncmp("ecb", optarg, 3) == 0) {
					e.config.cbc = false;
				} else {
					printf("Unrecognised AES mode, using ECB.\r\n");
				}
			//input PPM file name
			case 'f':
				e.config.filename = malloc(sizeof(optarg));
				if(e.config.filename == NULL) {
					printf("Failed to allocate filename.\r\n");
				}
				strncpy(e.config.filename, optarg, strlen(optarg));
				break;
			//image width and height (TODO: read from PPM)
			case 'w':
				e.config.image_width = atoi(optarg);
				break;
			case 'h':
				e.config.image_height = atoi(optarg);
				break;

			default:
				printf("Invalid argument given\r\n");
				abort();
		}
	}

	//Make sure we have got valid config
	if (e.config.filename == NULL) {
		printf("Please provide an input filename.\r\n");
		exit(EXIT_FAILURE);
	}

	for (index = optind; index < argc; index++) {
		printf ("Non-option argument %s\n", argv[index]);
	}
	/* Read in the PPM file */
	unsigned char * buffer = NULL;
	//Buffer will return allocated
	size_t allocated = read_file_to_buffer(e.config.filename, &buffer);

	printf("PPM type: %c%c\r\n", buffer[0], buffer[1]);

	/* Constuct a scatter/gather list to encrypt the PPM image
	   using one block per pixel.

	   Each pixel is (3*8 bits)	3 bytes.
	   AES Block size is		16 bytes
	*/
	int num_pixels = e.config.image_width * e.config.image_height;
	struct iovec input_iov[num_pixels*2];
	int p;

	size_t pixel_size = 3;
	size_t null_padding_size = AES_BLOCK_SIZE - pixel_size;

	unsigned char *null_padding_buffer = malloc(null_padding_size);
	int offset = 0;
	for (p = 0; p < (num_pixels*2); p += 2) {
		//Pixel data
		input_iov[p].iov_base = buffer + offset;
		offset += pixel_size;
		input_iov[p].iov_len = pixel_size;

		//Null padding
		input_iov[p+1].iov_base = null_padding_buffer;
		input_iov[p+1].iov_len = null_padding_size;
	}


	char result[16];
	memset(result, 0x00, 16);

	char input[16];
	strncpy(input, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);

	if(enc_init(&e) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	enc_set_key(&e, key);

	enc_print(input, 16);
	printf("key: ");
	enc_print(key, 16);

	printf("iv: ");
	enc_print(iv, 16);

	printf("filename: %s\r\n", e.config.filename);

	printf("width: %d\r\n", e.config.image_width);
	printf("height: %d\r\n", e.config.image_height);
	enc_enc(&e, result, input_iov, num_pixels*2);
	enc_close(&e);



	enc_print(result, 16);

	char output_filename[] = "out.ppm";
	write_buffer_to_file(buffer, allocated, output_filename);

	free(buffer);
	free(null_padding_buffer);

}
