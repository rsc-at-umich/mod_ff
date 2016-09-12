/*
        Miscellaneous utility routines

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: utility.c,v 1.6 2012/12/20 03:01:24 rsc Exp $
*/


#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/resource.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/*
 * Get local externals
 */
#include "utility.h"


void
count_alloc (alloc_free_count_t *ctr)
{
    if (ctr != (alloc_free_count_t *) NULL)
    {
	ctr->c_alloc ++;
    }

    return;

} /* end of count_alloc() */


void
count_free (alloc_free_count_t *ctr)
{
    if (ctr != (alloc_free_count_t *) NULL)
    {
	ctr->c_free ++;
    }

    return;

} /* end of count_free() */


char *
postmortem_alloc_free (char *buffer, size_t bufflen, const alloc_free_count_t *ctr,
		       long long expected, const char *title, int pedantic)
{
    long long diff;
    char *pos;
    int len;

    /* Give us nothing and we'll give you nothing back. */
    if (!buffer || (bufflen < 10))
    {
        return (buffer);
    }

    *buffer = '\0';
    
    diff = ctr->c_alloc - ctr->c_free;
    if (pedantic == 0)
    {
        /* It all matches. We're cool. */
        if ((diff == 0) && ((expected == 0) || (expected == -1)))
	{
	    return (buffer);
	}
    }

    /* Ooops. */
    snprintf (buffer, bufflen, "%s%srem %lld", (title != (char *) NULL ? title : ""),
	      (title != (char *) NULL ? ": " :  "" ) , diff);
    
    len = strlen(buffer);
    pos = buffer + len;
    bufflen -= len;

    if ((expected != -1) && (expected != diff))
    {
        snprintf (pos, bufflen, ", xpctd %lld", expected);
	len = strlen (pos);
	pos  += len;
	bufflen -= len;
    }
    snprintf (pos, bufflen, ", alloc=%llu, free=%llu", ctr->c_alloc, ctr->c_free);

    return (buffer);

} /* end of postmortem_alloc_free() */


char *
tick_toa (char *buff, size_t bufflen, time_t tick, const char *pfx, const char *timefmt, int verbose)
{
    struct tm  tock_buff;
    struct tm *tock_tm;
    char   *pos = buff;
    unsigned int len;
    unsigned int seconds;
    unsigned int minutes;
    unsigned int hours;
    unsigned int days;
    time_t rem;

    *buff = '\0';

    if (pfx)
    {
        strncat (buff, pfx, bufflen);
	len = strlen (pfx);
	pos += len;
	bufflen -= len;
    }

    /* Assume ticks of less than a year are relative times. */
    if (tick > 365 * 24 * 3600)
    {
    	if (timefmt)
	{
            tock_tm = localtime_r (&tick, &tock_buff);
	    strftime (pos, bufflen, timefmt, tock_tm);
	}

	return buff;
    }

    if (verbose && (tick == 0))
    {
        strncat (buff, "0", bufflen);

	return buff;
    }

    seconds = tick % 60;
    rem = tick / 60;
    minutes = rem % 60;
    rem = rem / 60;
    hours = rem % 24;
    days = rem / 24;
    
    if (days > 0)
    {
        snprintf(pos, bufflen, "%ud", days);
    }

    if (hours > 0)
    {
        if (*pos != '\0')
	{
	    strcat (pos, " ");
	    len = strlen(pos);
	    bufflen -= len;
	    pos += len;
	}
	snprintf(pos, bufflen, "%uh", hours);
    }

    if (minutes > 0)
    {
        if (*pos != '\0')
	{
	    strcat (pos, " ");
	    len = strlen(pos);
	    bufflen -= len;
	    pos += len;
	}
	snprintf(pos, bufflen, "%um", minutes);
    }

    if (seconds > 0)
    {
        if (*pos != '\0')
	{
	   strcat (pos, " ");
	    len = strlen(pos); 
	    bufflen -= len;
	    pos += len; 
	}

	snprintf(pos, bufflen, "%us", seconds);
    }

    return buff;

} /* end of tick_toa (char *buff, size_t bufflen, time_t tick, const char *pfx, const char *timefmt, int verbose) */


unsigned long 
str_to_scaled_ul (const ul_scale_t *s, const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg)
{
    long long lsiz;
    char *endptr = (char *) NULL;

    lsiz = strtoll (str, &endptr, 0);
    if (endptr && (*endptr != '\0') && (s != (ul_scale_t *) NULL))
    {
      for (; s->suffix != (char *) NULL; s++)
	{
	    if (strcmp(s->suffix, endptr) == 0)
	    {
	        lsiz *= s->scale;
		endptr += strlen (s->suffix);
		break;
	    }
	}

	if (*endptr) 
	{
	    snprintf (buff, bufflen, "unrecognized suffix '%s' in '%s'", endptr, str);
  	    *p_errmsg = buff;
	    return (0);
	}

    }

    if (endptr && (*endptr == '\0') ) {
	/* It's numerically valid. */

        if ((0 <= lsiz) && (lsiz <= maxv)) {
	    /* It's in range. */
	    *p_errmsg = (char *) NULL;
	    return lsiz;
	}

        snprintf (buff, bufflen, "'%s' is out of range (0 .. %lld)", str, maxv);
	*p_errmsg = buff;
	return (0);
    }

    snprintf (buff, bufflen, "'%s' is not a number of range (0 to %lld)", str, maxv);
    *p_errmsg = buff;

    return (0);
  
} /* end of str_to_scaled_ul (const ul_scale_t *s, const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg) */


unsigned long
str_to_ul (const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg)
{
    static const ul_scale_t iso_scale[] = 
      {
	{ "k", 1024},
	{ "K", 1000 },
	{ "m", 1024 * 1024 },
	{ "M", 1000 * 1000 },
	{ "g", 1024 * 1024 * 1024 },
	{ "G", 1000 * 1000 * 1000 },
	/* end of list */
	{ (char *) NULL, 0}
      };
      
    return str_to_scaled_ul (iso_scale, str, buff, bufflen, maxv, p_errmsg);

} /* end of str_to_ul (const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg) */


time_t
str_to_time (const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg)
{
    static const ul_scale_t time_scale[] = 
      {
	{ "m", 60},
	{ "min", 60},
	{ "minute", 60},
	{ "minutes", 60},
	{ "h", 60 * 60 },
	{ "hour", 60 * 60 },
	{ "hours", 60 * 60 },
	{ "d", 24 * 60 * 60 },
	{ "day", 24 * 60 * 60 },
	{ "days", 24 * 60 * 60 },
	{ "w", 7 * 24 * 60 * 60 },
	{ "week", 7 * 24 * 60 * 60 },
	{ "weeks", 7 * 24 * 60 * 60 },
	/* end of list */
	{ (char *) NULL, 0}
      };
      
    return str_to_scaled_ul (time_scale, str, buff, bufflen, maxv, p_errmsg);

} /* end of str_to_time (const char *str, char *buff, size_t bufflen, long long maxv, char **p_errmsg) */


int
strcasecmp_delim (const char *search, const char *target, int target_delim, 
		  const char **p_delim)
{
    size_t  target_len;
    size_t  search_len;
    const char *s = search;
    const char *t = target;
    const char   *found;

    if ((search == (char *) NULL) || (target == (char *) NULL))
      return (-15);
    
    search_len = strlen (search);

    /* Degenerate case. */
    if (target_delim == 0)
    {
        if (p_delim != (const char **) NULL)
	{
	    *(p_delim) = target + strlen (target);
	}
        return (strcasecmp (search, target));
    }

    found = strchr (target, target_delim);
    if (! found)
    {
        if (p_delim != (const char **) NULL)
	{
	    *(p_delim) = target + strlen (target);
	}
	return (strcasecmp(search, target));
    }


    /* Assumes that addresses so target > found always. */
    target_len = found - target;
    if (p_delim != (const char **) NULL)
        *p_delim = found;

    /* Note: target_len *MUST* be less than strlen(target),
       and so *t will NEVER be '\0' at the end of this loop

       I think.
    */
    for (; (search_len > 0) && (target_len > 0) && *s && *t;
	 t++, s++, search_len--, target_len--)
    {
      if (toupper(*s) < toupper(*t))
	return (-1);

      if (toupper(*s) > toupper(*t))
	return (1);
    }
    
    /* Reached the end. */

    /* implicit: search_len == target_len */

    if (search_len == 0)
    {
        if (target_len == 0)
	    return (0);

        /* Implicit: target_len > 0 */
	return (1);
    }

    if (target_len == 0)
        return (-1);
    
    /*
     * This should be impossible, as the only way for this
     * to happen is if strlen(target) < target_len (and
     * strchr() failed.
     */

    return (0xDEADBEEF);  /* Probably negative. */
    
} /* end of strcasecmp_delim() */


const char *
strtrim (const char *str)
{
    if (str== (char *) NULL)
        return ((char *) NULL);

    
    while (isspace(*str))
      str++;

    return (str);
} /* end of strtrim() */

char *
strrtrim (char *str)
{
    size_t len;
    char *pos = str;

    if (str == (char *) NULL)
        return ((char *) NULL);

    for (len = strlen (str); len > 0; len--)
    {
        pos = str + len;

	if (!isspace (*pos))
	  return (str);
	
	*pos = '\0';
    }
    
    return (str);
} /* end of strttrim () */
