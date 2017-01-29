bin_PROGRAMS = bob_server
bob_server_SOURCES = main.c jobs.c file.c signal.c array_client.c data.c data-admin.c data-client.c passwords.c uptime.c clients.c space.c
noinst_HEADERS = array_client.h  bob_server.h  data.h  file.h  jobs.h   params.h  passwords.h  signal.h uptime.h clients.h space.h
bob_server_LDADD  = 	-L${top_srcdir}/compat -lcompat \
			-L${top_srcdir}/network -L../network -lnetwork -L../librw -lrw ${EVENTINC} ${EVENTLIB}
INCLUDES = 	-I${top_srcdir}/compat \
		-I${top_srcdir}/network \
		-I${top_srcdir}/librw \
		-I${top_srcdir}
