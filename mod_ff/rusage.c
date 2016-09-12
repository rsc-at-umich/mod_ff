/*
        Utility routines for manipulating struct timeval

	Copyright 2012-2013 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: rusage.c,v 1.7 2013/01/04 21:04:48 rsc Exp $
*/

#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/resource.h>
#include <string.h>
#include <stdio.h>
/*
 * Get local externals
 */
#include "timevals.h"
#include "rusage.h"
#include "utility.h"

int
delta_rusage (const struct rusage *old, const struct rusage *new, struct rusage *delta)
{
    int rc = 0;

    memset ((void *) delta, 0, sizeof (struct rusage));

#define DELTA_RUSAGE(_field,_code) _DELTA(_field,_code,old,new,delta,rc)

    rc += delta_timeval (&(old->ru_utime), &(new->ru_utime), &(delta->ru_utime));
    rc += delta_timeval (&(old->ru_stime), &(new->ru_stime), &(delta->ru_stime));

    DELTA_RUSAGE(ru_maxrss,1);
    DELTA_RUSAGE(ru_ixrss,1);
    DELTA_RUSAGE(ru_idrss,1);
    DELTA_RUSAGE(ru_isrss,1);
    DELTA_RUSAGE(ru_minflt,1);
    DELTA_RUSAGE(ru_majflt,1);
    DELTA_RUSAGE(ru_nswap,1);
    DELTA_RUSAGE(ru_inblock,1);
    DELTA_RUSAGE(ru_oublock,1);
    DELTA_RUSAGE(ru_msgsnd,1);
    DELTA_RUSAGE(ru_msgrcv,1);
    DELTA_RUSAGE(ru_nsignals,1);
    DELTA_RUSAGE(ru_nvcsw,1);
    DELTA_RUSAGE(ru_nivcsw,1);

    return (rc);

} /*  end of delta_rusage () */

int
sum_rusage (const struct rusage *a, const struct rusage *b, struct rusage *sum)
{
    sum_timeval (&(a->ru_utime), &(b->ru_utime), &(sum->ru_utime));
    sum_timeval (&(a->ru_stime), &(b->ru_stime), &(sum->ru_stime));

#define SUM_RUSAGE(_field) sum->_field = a->_field + b->_field

    SUM_RUSAGE(ru_maxrss);
    SUM_RUSAGE(ru_ixrss);
    SUM_RUSAGE(ru_idrss);
    SUM_RUSAGE(ru_isrss);
    SUM_RUSAGE(ru_minflt);
    SUM_RUSAGE(ru_majflt);
    SUM_RUSAGE(ru_nswap);
    SUM_RUSAGE(ru_inblock);
    SUM_RUSAGE(ru_oublock);
    SUM_RUSAGE(ru_msgsnd);
    SUM_RUSAGE(ru_msgrcv);
    SUM_RUSAGE(ru_nsignals);
    SUM_RUSAGE(ru_nvcsw);
    SUM_RUSAGE(ru_nivcsw);

    /* Success */
    return (0);

} /* end of sum_rusage() */



int
cmp_rusage (const struct rusage *a, const struct rusage *b)
{
    if (a == b)
       return (0);

    if (memcmp (a, b, sizeof (struct rusage)) == 0)
       return (0);

    /* It's REALLY hard to compare larger or smaller */

    return (1);

} /* end of cmp_rusage() */



char *
rusage_toa (char *buff, size_t bufflen, const struct rusage *r, const char *sep, int verbose)
{
    char *pos = buff;
    int   count = 0;

    if (sep == (char *) NULL)
        sep = "; ";

    *buff = '\0';

#define RUSAGE_TIMEVAL_TOA(_field,_name) {			\
    unsigned int len; 						\
    char *t;							\
    char temp[64];						\
    if ((verbose) || (r->_field.tv_sec != 0) || (r->_field.tv_usec != 0)) { \
        if (count > 0) {					\
	    strncat (pos, sep, bufflen);			\
	    len = strlen(pos);					\
	    pos += len;						\
	    bufflen -= len;					\
	}							\
        temp[0] = '\0';						\
        t = timeval_toa (temp, sizeof(temp), &(r->_field), verbose);	\
	snprintf (pos, bufflen, _name "=%s", t);		\
	count++;						\
	len = strlen(pos);					\
	bufflen -= len;						\
	pos += len;						\
    } }


#define RUSAGE_LONG_TOA(_field,_name) {				\
    unsigned int len; 						\
    if ((verbose) || (r->_field != 0)) {			\
        if (count > 0) {					\
	    strncat (pos, sep, bufflen);			\
	    len = strlen(pos);					\
	    pos += len;						\
	    bufflen -= len;					\
	}							\
	snprintf (pos, bufflen, _name "=%ld", r->_field);	\
	count++;						\
	len = strlen(pos);					\
	bufflen -= len;						\
	pos += len;						\
    } }
    
    RUSAGE_TIMEVAL_TOA(ru_utime, "utime");
    RUSAGE_TIMEVAL_TOA(ru_stime, "stime");

    RUSAGE_LONG_TOA(ru_maxrss, "maxrss");
    RUSAGE_LONG_TOA(ru_ixrss, "ixrss");
    RUSAGE_LONG_TOA(ru_idrss, "idrss");
    RUSAGE_LONG_TOA(ru_isrss, "isrss");
    RUSAGE_LONG_TOA(ru_minflt, "minflt");
    RUSAGE_LONG_TOA(ru_majflt, "majflt");
    RUSAGE_LONG_TOA(ru_inblock, "inblock"); 
    RUSAGE_LONG_TOA(ru_oublock, "oublock"); 
    RUSAGE_LONG_TOA(ru_msgsnd, "msgsnd");
    RUSAGE_LONG_TOA(ru_msgrcv, "msgrcv");
    RUSAGE_LONG_TOA(ru_nsignals, "nsignals");
    RUSAGE_LONG_TOA(ru_nvcsw, "nvcsw");
    RUSAGE_LONG_TOA(ru_nivcsw, "nivcsw");

    return buff;

} /* end of rusage_toa() */
