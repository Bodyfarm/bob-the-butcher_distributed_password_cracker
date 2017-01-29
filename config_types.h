#ifndef   __CONFIG_TYPES_H__
# define  __CONFIG_TYPES_H__

# include "config.h"

#ifdef HAVE_STDINT_H
# ifndef INASM
#  include <inttypes.h>
#  include <sys/types.h>
# endif
#else
#ifndef _STDINT_H
# define _STDINT_H
#   if SIZEOF_INT == 4 
    typedef int int32_t;
    typedef unsigned int uint32_t;
#   elif SIZEOF_INT == 4
    typedef long int32_t;
    typedef unsigned long uint32_t;
#   endif

#  if SIZEOF_INT == 8
   typedef int int64_t;
   typedef unsigned int uint64_t;
#  elif SIZEOF_LONG == 8
   typedef long int64_t;
   typedef unsigned long uint64_t;
#  elif SIZEOF_LONG_LONG == 8
   typedef long long int64_t;
   typedef unsigned long long uint64_t;
#  endif

#  if SIZEOF_INT == 2
   typedef int int16_t;
   typedef unsigned int uint16_t;
#  elif SIZEOF_SHORT == 2
   typedef short int16_t;
   typedef unsigned short uint16_t;
#  endif

   typedef unsigned char u_char;
#endif
#endif 
   
   
#endif  /* __CONFIG_TYPES_H__ */
