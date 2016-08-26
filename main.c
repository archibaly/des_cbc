#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbc.h"

void dump_packet(const unsigned char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if ((i % 2) == 0) {
			printf(" ");
		}   
		if ((i % 16) == 0) {
			printf("\n");
		}   
		printf("%02x", buf[i]);
	}   
	printf("\n");
}

int main()
{
	char *clear_text = "12345678901";

	int len = strlen(clear_text);

	unsigned char *cipher_text = des_cbc_encrypt((unsigned char *)clear_text, &len,
												 (unsigned char *)"comedali", 8, (unsigned char *)"88969271", 8);
	dump_packet(cipher_text, len);

	unsigned char *clear = des_cbc_decrypt(cipher_text, &len, (unsigned char *)"comedali", 8, (unsigned char *)"88969271", 8);

	dump_packet(clear, len);

	free(cipher_text);
	free(clear);

	return 0;
}
