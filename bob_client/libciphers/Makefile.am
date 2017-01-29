noinst_LIBRARIES = libciphers.a

if AMD64
ASMOBJECTS= \
	    md4-amd64.S \
	    md5-amd64.S \
	    sha1-amd64.S \
	    DES_bs_b.c
INCLUDE_DIST=
endif
if X86CPU
if X86MMX 
ASMOBJECTS=md4-mmx.S \
	   md5-mmx.S \
	   stages_sse2_md5.S \
	   stages_mmx_md5.S \
	   x86.S \
	   x86-mmx.S \
	   sha1-mmx.S
INCLUDE_DIST= DES_bs_b.c
else
ASMOBJECTS=x86.S
INCLUDE_DIST= DES_bs_b.c
endif
endif

if SPARC
ASMOBJECTS= DES_bs_b.c
INCLUDE_DIST= 
endif

libciphers_a_SOURCES = MD5_std.c\
                       md5.c \
                       md4.c \
                       des.c \
                       sha1.c \
		       DES_std.c \
		       DES_bs.c \
                       blowfish.c \
		       $(ASMOBJECTS)

noinst_HEADERS = MD5_std.h \
                 md5.h \
                 md4.h \
                 des.h \
                 sha.h \
                 sha_locl.h \
                 blowfish.h \
		 DES_bs.h \
		 DES_std.h \
		 john-x86mmx.h \
		 john-x86-64mmx.h \
		 john-x86.h \
		 john-sparc.h \
		 blowfish.h \
		 bf_tab.h \
		 DES_bs_n.c \
		 $(INCLUDE_DIST)

INCLUDES = -I${top_srcdir}/bob_client -I${top_srcdir}/librw -I${top_srcdir} -I../../librw
AM_CCASFLAGS = ${DEFS} ${DEFAULT_INCLUDES} ${INCLUDES}
