/*
        Utility routines for manipulating struct timeval

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: timevals.c,v 1.4 2012/12/07 02:03:19 rsc Exp $
*/

#include <unistd.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <string.h>
#include <stdio.h>

#include "timevals.h"

int 
normalize_timeval (struct timeval *tv)
{
    unsigned int rollover;	 /* to normalize the results */

    if (tv == (struct timeval *) NULL)
        return (-1);

    if ( tv->tv_usec > 1000000 )
    {	
        rollover = (tv->tv_usec / 1000000);

        tv->tv_usec = (tv->tv_usec % 1000000);
	tv->tv_sec -= rollover;
    } 

    return (0);

} /* end of normalize_timeval() */ 

int
delta_timeval (const struct timeval *old, const struct timeval *new, struct timeval *delta)
{
    if ( old->tv_sec <= new->tv_sec)
    {	
        delta->tv_sec = new->tv_sec - old->tv_sec;	
	
	if (new->tv_usec < old->tv_usec)
	{
	    delta->tv_usec = (new->tv_usec + 1000000 )- old->tv_usec; 
	    delta->tv_sec -= 1;
	}
	else
	{
	    delta->tv_usec = new->tv_usec - old->tv_usec; 
	}

	(void) normalize_timeval (delta);

	return (0);
    }

    /* Error fall through */

    memset ((void *) delta, 0, sizeof(struct timeval));

    return (1);
    
} /* end of delta_timeval() */



int
sum_timeval (const struct timeval *a, const struct timeval *b, struct timeval *sum)
{
    /* Error checking of a sort. */
    if ((a == (struct timeval *) NULL) || (b == (struct timeval *) NULL) || (sum == (struct timeval *) NULL))
        return (-1);

    sum->tv_sec = b->tv_sec + a->tv_sec;	
    sum->tv_usec = b->tv_usec + a->tv_usec; 

    (void) normalize_timeval (sum);

    return (0);
    
} /* end of sum_timeval() */

/* Assumes normalized timeval's */
int
cmp_timeval (const struct timeval *a, const struct timeval *b)
{
    if (a == b)
        return (0);

    if ((a == (struct timeval *) NULL) || (b == (struct timeval *) NULL))
        return (-2);


    if (a->tv_sec > b->tv_sec)
        return (1);

    if (a->tv_sec < b->tv_sec)
        return (-1);

    /* tv_sec are equal */

    if (a->tv_usec > b->tv_usec)
        return (1);

    if (a->tv_usec < b->tv_usec)
        return (-1);

    return (0);

} /* end of cmp_timeval() */



char *
timeval_toa (char *buff, size_t bufflen, const struct timeval *tv, int verbose)
{
    if ((buff == (char *) NULL) || (bufflen == 0) || (tv == (struct timeval * ) NULL))
    {
        return "invalid";
    }
    
    *buff = '\0';

    if ((tv->tv_sec == 0) && (tv->tv_usec == 0))
    {
        strncpy (buff, "0", bufflen);
    }

    else if (tv->tv_sec == 0)
    {
        snprintf (buff, bufflen, "%luus", (unsigned long) (tv->tv_usec));
    }
    
    else if (tv->tv_usec == 0)
    {
        snprintf (buff, bufflen, "%lu", (unsigned long) (tv->tv_sec));
    }
    
    else 
    {
      snprintf (buff, bufflen, "%lu.%6.6lu", (unsigned long)(tv->tv_sec), 
		(unsigned long)(tv->tv_usec));
    }

    return buff;
    
} /* end of timeval_toa() */
