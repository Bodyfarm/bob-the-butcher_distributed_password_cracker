#ifndef   __RW_H__
# define  __RW_H__

# define ARCH_INDEX(x) ((ARCH_INDEX_TYPE)(u_char)(x))

# ifndef BUFSIZE
#  define BUFSIZE 1024
#endif

# define MAX_PACKET_SIZE 65535

extern char itoa64[64], atoi64[0x100];
extern char itoa16[16], atoi16[0x100];
extern char idx2chr[0x100];
extern char incrementer[0x100];

void    atoi_init(void);
void    incrementer_init(unsigned int);

typedef struct      s_rw
{
    int      size;
    u_char   * buf;
    u_char   * ptr;
}                   t_rw;

u_char      *read_netstring(struct s_rw *);
u_char      read_u_char(struct s_rw *);
uint32_t    read_uint32_t(struct s_rw *);
uint64_t    read_uint64_t(struct s_rw *);
struct s_rw * rw_init(u_char * buf, int size);
void rw_free(struct s_rw * rw);

#ifdef DEBUG
#define RW_SIZE_CHECK(x, s) \
	if( ( ((x)->ptr - (x)->buf + (s)) > (x)->size) ) { printf(" ERROR ERROR\n"); return 0; }
#else
#define RW_SIZE_CHECK(x, s) \
	if( ( ((x)->ptr - (x)->buf + (s)) > (x)->size) ) return 0;
#endif

typedef struct s_str
{
	unsigned char * buf;
	unsigned int strsize;
	unsigned int bufsize;
} t_str;


#define STRMASK	7
#define STRLEN(x) (x)->strsize
#define BUFLEN(x) (x)->bufsize
#define STRING(x) (x)->buf

t_str * str_init(unsigned int size);
t_str * str_create(unsigned char * string);
t_str * strn_create(unsigned char * string, unsigned int size);
void str_copy(t_str * dst, t_str * src);
void strn_copy(t_str * dst, t_str * src, unsigned int size);
t_str * str_dup(t_str * src);
void str_append_char(t_str * str, u_char x);
void str_append_int32(t_str * str, uint32_t x);
void str_append_int64(t_str * str, uint64_t x);
void str_append_str(t_str * dst, t_str * src);
void str_append_netstring(t_str * dst, unsigned char * src, uint32_t size);
void str_set(t_str * str, unsigned char * text, unsigned int len);
unsigned int str_cmp(t_str * str1, t_str * str2);
void str_free(t_str * str);

char * read_netstr(unsigned char * buf, int maxlen);
uint32_t get_int32_from_buf(unsigned char * buf);
uint64_t get_int64_from_buf(unsigned char * buf);
void put_int64_in_buf(unsigned char * buf, uint64_t val);
void put_int32_in_buf(unsigned char * buf, uint32_t val);

void dump_stuff(unsigned char * stuff, int size);
void dump_stuff_mmx(unsigned char * stuff, int size, int index);
unsigned char upper(unsigned char b);
void to_upper(unsigned char * b);

#ifndef ENDIAN_SHIFT8_L
# ifdef WORDS_BIGENDIAN
#  define ENDIAN_SHIFT8_L
#  define ENDIAN_SHIFT8_R
# else
#  define ENDIAN_SHIFT8_L  << 8
#  define ENDIAN_SHIFT8_R  >> 8
# endif
#endif

/*
 *  * this is terrible ... but fast
 *   */
static inline int to_unicode_l(uint16_t *dst, unsigned char *src)
{
	        unsigned int i = 0;

#ifdef WORDS_BIGENDIAN
		while( (dst[i] = src[i] << 8) )
#else
		while( (dst[i] = src[i] ) )
#endif
			i++;
		return i;
}

static inline int to_unicode_b(uint16_t *dst, unsigned char *src)
{
	unsigned int i = 0;
	while ( (dst[i] = (src[i] ENDIAN_SHIFT8_L) ) )
		i++;
	return i;
}


#endif /* __RW_H__ */
