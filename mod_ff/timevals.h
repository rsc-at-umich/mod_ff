/*
        Utility routines for manipulating struct timeval

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: timevals.h,v 1.1 2012/12/06 04:19:54 rsc Exp $
*/

#if !defined(TIMEVALS_H)
#  define TIMEVALS_H "$Id: timevals.h,v 1.1 2012/12/06 04:19:54 rsc Exp $"

#  include <time.h>

extern int    normalize_timeval (struct timeval *tv);
extern int    delta_timeval (const struct timeval *old, const struct timeval *new, struct timeval *delta);
extern int    sum_timeval (const struct timeval *a, const struct timeval *b, struct timeval *sum);
extern int    cmp_timeval (const struct timeval *a, const struct timeval *b);
extern char  *timeval_toa (char *buff, size_t bufflen, const struct timeval *tv, int verbose); 

#endif /* TIMEVALS_H */
