bin_PROGRAMS        = bob_admin
bob_admin_SOURCES   = main.c job.c client.c
noinst_HEADERS = bob_admin.h client.h job.h

bob_admin_LDADD = 	-L${top_srcdir}/compat -L../compat -lcompat \
			-L${top_srcdir}/network -L../network -lnetwork -L../librw -lrw
INCLUDES = 	-I${top_srcdir}/compat \
		-I${top_srcdir}/network \
		-I${top_srcdir}/librw \
		-I${top_srcdir}
