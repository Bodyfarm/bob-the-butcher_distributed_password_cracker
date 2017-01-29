#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(Bob the butcher, 0.7.1, bartavelle@bandecon.com)
AC_CANONICAL_TARGET([])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AM_PROG_AS
AC_PROG_RANLIB
AC_PROG_YACC
AC_PROG_LEX

CFLAGS="-Wall -g2 -O2"
AM_CCASFLAGS="-I.."

if test "$prefix" = "NONE"; then
    prefix="/usr/local"
fi

case "$host_os" in
cygwin*)
    AC_DEFINE([UNDERSCORES], [1], [Defines UNDERSCORES to asm compiler])
    ;;
*)
    ;;
esac

case "$host_cpu" in
alpha*)
	AC_DEFINE([ARCH_INDEX_TYPE], [unsigned long], [Setting arch index])
	;;
*)
	AC_DEFINE([ARCH_INDEX_TYPE], [unsigned int], [Setting arch index])
	;;
esac

# disable sse2
AC_MSG_CHECKING(wether to disable or not SSE2 support)
AC_ARG_ENABLE(sse2,
	 [  --disable-sse2         disables SSE2 support (and enables MMX)],
	      CFLAGS="$CFLAGS -DNOSSE2";
	      AC_DEFINE([MMX_COEF], [2], [Setting SIMD width 64 bits])
	      AC_DEFINE([MMX_TYPE], ["MMX"], [Setting SIMD type MMX])
	      AC_MSG_RESULT(disabled),
	      AC_MSG_RESULT(not disabled))

case "$host_cpu" in
x86_64)
	AC_DEFINE([MMX_COEF], [8], [Setting SIMD width 128x2 bits])
	AC_DEFINE([MMX_TYPE], ["AMD64"], [Setting SIMD type AMD64])
	AC_DEFINE([JOHN_ARCH], ["john-x86-64mmx.h"], [Setting John architecture options])
	AC_MSG_RESULT(SSE2 is enabled)
	AM_CONDITIONAL(AMD64, true)
	AM_CONDITIONAL(X86MMX, false)
	AM_CONDITIONAL(X86CPU, false)
	AM_CONDITIONAL(SPARC, false)
	;;
i686)
	AC_DEFINE([MMX_COEF], [4], [Setting SIMD width 128 bits])
	AC_DEFINE([MMX_TYPE], ["SSE2"], [Setting SIMD type SSE2])
	AC_DEFINE([JOHN_ARCH], ["john-x86mmx.h"], [Setting John architecture options])
	AC_MSG_RESULT(SSE2 is enabled)
	AM_CONDITIONAL(AMD64, false)
	AM_CONDITIONAL(X86MMX, true)
	AM_CONDITIONAL(X86CPU, true)
	AM_CONDITIONAL(SPARC, false)
	;;
i586)
	AC_DEFINE([MMX_COEF], [2], [Setting SIMD width 64 bits])
	AC_DEFINE([MMX_TYPE], ["MMX"], [Setting SIMD type MMX])
	AC_DEFINE([JOHN_ARCH], ["john-x86mmx.h"], [Setting John architecture options])
	AC_MSG_RESULT(MMX is enabled)
	AM_CONDITIONAL(AMD64, false)
	AM_CONDITIONAL(X86MMX, true)
	AM_CONDITIONAL(X86CPU, true)
	AM_CONDITIONAL(SPARC, false)
	;;
i386|i486)
	AC_DEFINE([JOHN_ARCH], ["john-x86.h"], [Setting John architecture options])
	AM_CONDITIONAL(AMD64, false)
	AM_CONDITIONAL(X86CPU, true)
	AM_CONDITIONAL(X86MMX, false)
	AC_MSG_RESULT(x86 ASM is enabled)
	AM_CONDITIONAL(SPARC, false)
	;;
sparc)
	AC_DEFINE([JOHN_ARCH], ["john-sparc.h"], [Setting John architecture options])
	AM_CONDITIONAL(AMD64, false)
	AM_CONDITIONAL(X86CPU, false)
	AM_CONDITIONAL(X86MMX, false)
	AC_MSG_RESULT(SPARC cpu is enabled)
	AM_CONDITIONAL(SPARC, true)
	;;
*)
	AC_ERROR(unsupported cpu $host_cpu)
	;;
esac

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ sysctl.h inttypes.h sys/types.h ])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_BIGENDIAN
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(u_char)
AC_HEADER_TIME

AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, floor)

AC_DEFINE([BUFSIZE], [1024], [Defines the max buffer size])
AC_DEFINE([USAGE_EXIT], [1], [Defines usage exit code])
AC_DEFINE([MEM_EXIT],   [2], [Defines memory exit code])
AC_DEFINE([NET_EXIT],   [3], [Defines network exit code])

AC_CONFIG_LIBOBJ_DIR([compat])
AC_REPLACE_FUNCS([strnlen])
AC_REPLACE_FUNCS([strndup])
AC_REPLACE_FUNCS([memcmp])
AC_REPLACE_FUNCS([memset])
AC_REPLACE_FUNCS([sigset])
AC_REPLACE_FUNCS([get_full_login])

# dmalloc switches
AM_WITH_DMALLOC

# enable debug
AC_MSG_CHECKING(wether to enable debug mode)
AC_ARG_ENABLE(debug,
	[  --enable-debug          set debug mode],
	CFLAGS="$CFLAGS -pg";
	AC_DEFINE(DEBUG, 1, [define if debug is enabled])
	AC_MSG_RESULT(yes),
	AC_MSG_RESULT(no))

# libevent
AC_MSG_CHECKING(for libevent)
AC_ARG_WITH(libevent,
[  --with-libevent=DIR     use libevent build directory],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/event.h -a -f $withval/libevent.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        EVENTINC="-I$withval"
        EVENTLIB="-L$withval -levent"
     elif test -f $withval/include/event.h -a -f $withval/lib/libevent.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        EVENTINC="-I$withval/include"
        EVENTLIB="-L$withval/lib -levent"
     else
        AC_ERROR(event.h or libevent.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/event.h; then
     EVENTINC="-I${prefix}/include"
     EVENTLIB="-L${prefix}/lib -levent"
  elif test -f /usr/include/event/event.h; then
     EVENTINC="-I/usr/include/event"
     EVENTLIB="-levent"
  elif test -f /usr/include/event.h; then
     EVENTLIB="-levent"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libevent not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(EVENTINC)
AC_SUBST(EVENTLIB)

#//LIBS="$LIBS $EVENTLIB"
#//CFLAGS="$CFLAGS $EVENTINC"

#AC_CHECK_LIB(event,
#    event_priority_init,,
#    AC_MSG_ERROR(["libevent is too old - you need to install a newer version. Check http:://www.monkey.org/~provos/libevent/" ]))

AC_CONFIG_FILES([Makefile
		 compat/Makefile
		 librw/Makefile
		 network/Makefile
		 bob_server/Makefile
		 bob_admin/Makefile
		 bob_python_server/Makefile
		 bob_client/Makefile
		 bob_client/format_bsdi/Makefile
		 bob_client/format_des/Makefile
		 bob_client/format_eggdrop/Makefile
		 bob_client/format_lotus5/Makefile
		 bob_client/format_md5/Makefile
		 bob_client/format_mscash/Makefile
		 bob_client/format_mysql/Makefile
		 bob_client/format_nsldap/Makefile
		 bob_client/format_nt/Makefile
		 bob_client/format_oracle/Makefile
		 bob_client/format_rawMD5/Makefile
		 bob_client/format_rawsha1/Makefile
		 bob_client/libciphers/Makefile
         ])

AC_OUTPUT

