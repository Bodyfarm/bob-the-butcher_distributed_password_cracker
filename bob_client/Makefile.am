SUBDIRS =   libciphers \
            format_eggdrop \
            format_lotus5 \
            format_md5 \
            format_mscash \
            format_mysql \
            format_oracle \
            format_nt \
            format_des \
            format_nsldap \
            format_rawsha1 \
            format_bsdi \
            format_rawMD5

bin_PROGRAMS = bob_client
bob_client_SOURCES = client.c client_connect.c log.c format.c crack.c salts.c standalone.c timer.c data_server.c
bob_client_DEPENDENCIES = \
    ${top_srcdir}/bob_client/format_eggdrop/libformat_eggdrop.a\
    ${top_srcdir}/bob_client/format_lotus5/libformat_lotus5.a\
    ${top_srcdir}/bob_client/format_md5/libformat_md5.a\
    ${top_srcdir}/bob_client/format_mscash/libformat_mscash.a\
    ${top_srcdir}/bob_client/format_mysql/libformat_mysql.a\
    ${top_srcdir}/bob_client/format_nt/libformat_nt.a\
    ${top_srcdir}/bob_client/format_rawMD5/libformat_rawMD5.a\
    ${top_srcdir}/bob_client/format_des/libformat_des.a\
    ${top_srcdir}/bob_client/format_nsldap/libformat_nsldap.a\
    ${top_srcdir}/bob_client/format_rawsha1/libformat_rawsha1.a\
    ${top_srcdir}/bob_client/format_bsdi/libformat_bsdi.a\
    ${top_srcdir}/bob_client/format_oracle/libformat_oracle.a\
    ${top_srcdir}/bob_client/libciphers/libciphers.a\
    ${top_srcdir}/librw/librw.a


noinst_HEADERS = client_connect.h crack.h format.h params.h salts.h client.h log.h standalone.h data.h timer.h space.h

bob_client_LDADD =  \
     -lformat_mscash \
     -lformat_lotus5 \
     -lformat_eggdrop \
     -lformat_md5 \
     -lformat_mysql \
     -lformat_nt \
     -lformat_oracle \
     -lformat_rawMD5 \
     -lformat_des \
     -lformat_nsldap \
     -lformat_rawsha1 \
     -lformat_bsdi \
     -Lformat_des \
     -Lformat_nsldap \
     -Lformat_rawsha1 \
     -Lformat_bsdi \
     -Lformat_mscash \
     -Lformat_lotus5 \
     -Lformat_eggdrop \
     -Lformat_md5 \
     -Lformat_mysql \
     -Lformat_nt \
     -Lformat_oracle \
     -Lformat_rawMD5 \
     -Llibciphers \
     -lciphers \
     -L${top_srcdir}/librw -L../librw \
     -lrw \
     -L${top_srcdir}/compat  -L../compat -lcompat \
     -L${top_srcdir}/network -L../network -lnetwork

INCLUDES = -I${top_srcdir}/librw -I${top_srcdir}/compat -I${top_srcdir}/network -I${top_srcdir}
