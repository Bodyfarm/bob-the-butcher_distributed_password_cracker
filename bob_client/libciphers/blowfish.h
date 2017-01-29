/* modified 19jul1996 by robey -- uses autoconf values now */
#ifndef _H_BLOWFISH
#define _H_BLOWFISH

#define bf_N             16
#define noErr            0
#define DATAERROR        -1

/* choose a byte order for your hardware */

#ifdef WORDS_BIGENDIAN
union aword {
  uint32_t word;
  unsigned char byte[4];
  struct {
    unsigned int byte0:8;
    unsigned int byte1:8;
    unsigned int byte2:8;
    unsigned int byte3:8;
  } w;
};
#else
union aword {
  uint32_t word;
  unsigned char byte[4];
  struct {
    unsigned int byte3:8;
    unsigned int byte2:8;
    unsigned int byte1:8;
    unsigned int byte0:8;
  } w;
};
#endif	

void blowfish_encrypt_pass(char *text, char *new);
void blowfish_first_init(void);

#endif
