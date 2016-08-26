#ifndef _CBC_H_
#define _CBC_H_

unsigned char *des_cbc_encrypt(const unsigned char *clear_text, int *text_len,
							   const unsigned char *key, int key_len,
							   const unsigned char *iv, int iv_len);

unsigned char *des_cbc_decrypt(const unsigned char *cipher_text, int *text_len,
								  const unsigned char *key, int key_len,
								  const unsigned char *iv, int iv_len);
#endif /* _CBC_H_ */
