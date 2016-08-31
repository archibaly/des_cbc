#include <stdlib.h>
#include <string.h>

#include "des.h"
#include "cbc.h"

unsigned char *des_cbc_encrypt(const unsigned char *clear_text, int *text_len,
							   const unsigned char *key, int key_len,
							   const unsigned char *iv, int iv_len)
{
	int i;
	DES_cblock key_encrypt, ivec;

	memset(key_encrypt, 0, sizeof(key_encrypt));
	memset(ivec, 0, sizeof(ivec));

	if (key_len <= 8) 
		memcpy(key_encrypt, key, key_len);
	else 
		memcpy(key_encrypt, key, 8);

	if (iv_len <= 8) 
		memcpy(ivec, iv, iv_len);
	else 
		memcpy(ivec, iv, 8);

	DES_key_schedule key_schedule;
	DES_set_key_unchecked(&key_encrypt, &key_schedule);	

	/* PKCS7 padding */
	unsigned char padding_len = 8 - *text_len % 8;

	int len = *text_len + padding_len;
	unsigned char *cipher_text = malloc(len);
	if (!cipher_text) {
		return NULL;
	}

	memcpy(cipher_text, clear_text, *text_len);
	for (i = 0; i < padding_len; i++)
		cipher_text[*text_len + i] = padding_len;

	DES_ncbc_encrypt(cipher_text, cipher_text, len, &key_schedule, &ivec, DES_ENCRYPT);

	*text_len = len;

	return cipher_text;
}

unsigned char *des_cbc_decrypt(const unsigned char *cipher_text, int *text_len,
							   const unsigned char *key, int key_len,
							   const unsigned char *iv, int iv_len)
{
	DES_cblock key_encrypt, ivec;

	memset(key_encrypt, 0, sizeof(key_encrypt));
	memset(ivec, 0, sizeof(ivec));

	if (key_len <= 8) 
		memcpy(key_encrypt, key, key_len);
	else 
		memcpy(key_encrypt, key, 8);

	if (iv_len <= 8) 
		memcpy(ivec, iv, iv_len);
	else 
		memcpy(ivec, iv, 8);

	DES_key_schedule key_schedule;
	DES_set_key_unchecked(&key_encrypt, &key_schedule);	

	unsigned char *clear_text = malloc(*text_len + 1);
	if (!clear_text)
		return NULL;

	DES_ncbc_encrypt(cipher_text, clear_text, *text_len, &key_schedule, &ivec, DES_DECRYPT);

	int padding_len = clear_text[*text_len - 1];

	if (padding_len >= 1 && padding_len <= 8) {
		*text_len -= padding_len;
	} else {
		free(clear_text);
		return NULL;
	}

	return clear_text;
}
