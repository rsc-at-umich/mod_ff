/*
        Utility definitions for various things

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: utility.h,v 1.6 2012/12/21 17:04:40 rsc Exp $
*/

#if !defined(UTILITY_H)
#  define UTILITY_H "$Id: utility.h,v 1.6 2012/12/21 17:04:40 rsc Exp $"

#  include <stdarg.h>
#  include <time.h>
#  include <sys/types.h>

/* Making differences easier... */

#define _DELTA(_field,_code,_old,_new,_delta,_rc) {	\
  if ((_old)->_field <= (_new)->_field) 			\
  {							\
      (_delta)->_field = (_new)->_field - (_old)->_field; \
  } else {						\
      _rc  += (_code);					\
  }		}


#define __FUNC(name)  static const char _func[] __attribute__((unused)) = #name

/*
 * postmortem_xxx() routines return a string showing memory usage. 
 *
 * If pedantic == 0, then an empty string is given if allocs == frees,
 * else if pedantic != 0, then a full report is given.
 */
typedef struct {
    unsigned long long c_alloc;
    unsigned long long c_free;
} alloc_free_count_t;

typedef int (*vfprintf_like_log_hook_t) (void *context, const char *fmt, va_list ap);

extern void count_alloc (alloc_free_count_t *ctr);
extern void count_free (alloc_free_count_t *ctr);
extern char *postmortem_alloc_free (char *buffer, size_t bufflen, 
				    const alloc_free_count_t *ctr, 
				    long long expected,
				    const char *title, int pedantic);
extern char  *tick_toa (char *buff, size_t bufflen, time_t tick, const char *pfx,
			const char *timefmt, int verbose);

typedef struct {
     char         *suffix;	/* Like "K", "H", etc. */
     unsigned int  scale;	/* Like (1000), (3600), etc. */
} ul_scale_t;


extern unsigned long str_to_scaled_ul (const ul_scale_t *s, const char *str, char *buff, size_t bufflen,
				       long long maxv, char **p_errmsg);
extern unsigned long str_to_ul (const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg);
extern time_t str_to_time (const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg);

/* Like strcmp(), except that string 'target' is delimited by 'delim' instead of '\0' */

extern int strcasecmp_delim (const char *search, const char *target, int target_delim, const char **p_delim);

/* Return 'str' starting after whitespace elimination */
extern const char *strtrim (const char *str); 

/* Remove white space from the right hand end of a string by modifying 'str'  */
extern char *strrtrim (char *str);

#endif /* defined(UTILITY_H) */
