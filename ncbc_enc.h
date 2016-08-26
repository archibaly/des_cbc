#ifndef _NCBC_ENC_H_
#define _NCBC_ENC_H_

void DES_ncbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, DES_key_schedule *_schedule,
                      DES_cblock *ivec, int enc);

#endif /* _NCBC_ENC_H_ */
