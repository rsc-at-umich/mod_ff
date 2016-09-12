/*
        Utility routines for manipulating struct rusage

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: rusage.h,v 1.2 2012/12/06 22:29:55 rsc Exp $
*/

#if !defined(RUSAGE_H)
#  define RUSAGE_H "$Id: rusage.h,v 1.2 2012/12/06 22:29:55 rsc Exp $"

#  include <sys/time.h>
#  include <sys/resource.h>
#  include <unistd.h>

extern int    delta_rusage (const struct rusage *old, const struct rusage *new, struct rusage *delta);
extern int    sum_rusage (const struct rusage *a, const struct rusage *b, struct rusage *sum);
extern int    cmp_rusage (const struct rusage *a, const struct rusage *b); 
extern char  *rusage_toa (char *buff, size_t bufflen, const struct rusage *r, const char *sep, int verbose); 

#endif /* defined(RUSAGE_H) */ 
