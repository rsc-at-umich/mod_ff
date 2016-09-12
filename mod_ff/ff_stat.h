/*
        Define and manipulate the basic ff_stat_t and ff_threshold_t structures

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: ff_stat.h,v 1.7 2013/01/04 21:04:48 rsc Exp $
*/

#if !defined(FF_STAT_H)
#  define FF_STAT_H "$Id: ff_stat.h,v 1.7 2013/01/04 21:04:48 rsc Exp $"
/*
 * Get local externals
 */
#include "timevals.h"
#include "rusage.h"
#include "procinfo.h"

typedef struct {
   unsigned long vmsize;	/* Virtual memory size in BYTES */
   unsigned long utime;		/* User-mode time */
   unsigned long stime;		/* Kernel (system) mode time */
   unsigned long cutime;	/* Child user-mode time */
   unsigned long cstime;	/* Child Kernel (system) mode time */
   unsigned long minflt;	/* Minor fault count */
   unsigned long majflt;	/* Major (real swap) fault count */
   unsigned long cminflt;	/* Child minor fault count */
   unsigned long cmajflt;	/* Child major (real swap) fault count */
   unsigned      rss;		/* Resident set size in PAGES */
   unsigned      fds;		/* Number of file-descriptors */
   time_t	 tick;		/* Wall clock time as returned by time() */
   struct rusage overhead;	/* For calculating how much load we add. */ 
   proc_statm_info_t statm;	/* For delta /proc/self/statm stuff */

   proc_fd_info_list_t *fds_info; /* The fds.  Oooh. */
} ff_stat_t;

#define COUNT_EXPECTED_FF_PROTO_ARGS COUNT_EXPECTED_FD_INFO_PROTO_ARGS

#define PASS_EXPECTED_FF_PARAMETERS(_p_fil, _p_fi, _p_fi_p) PASS_EXPECTED_FD_INFO_PARAMETERS(_p_fil,_p_fi,_p_fi_p)

typedef void (*count_expected_ff_t) (const ff_stat_t *ff, COUNT_EXPECTED_FF_PROTO_ARGS);
typedef  ff_stat_t * (*next_expected_ff_stat_t) (void *context);

extern count_expected_ff_t count_expected_ff;

extern char  *postmortem_ff_stat (char *buffer, size_t bufflen, 
				  next_expected_ff_stat_t next_expected_ff_stat,
				  count_expected_ff_t expected_ff,
				  int pedantic);

extern void   count_ff_stat (const ff_stat_t *ff, COUNT_EXPECTED_FF_PROTO_ARGS);
		     
extern int    get_ff_stat (const char *proc, ff_stat_t *ff, 
			   int overhead, int extra);

extern int    copy_ff_stat (ff_stat_t *dest, ff_stat_t *src);

extern int    move_ff_stat (ff_stat_t *dest, ff_stat_t *src);

extern unsigned int reset_ff_stat (ff_stat_t *ff);

extern void   cleanup_ff_stat (void);

extern int    delta_ff_stat (const ff_stat_t *old, const ff_stat_t *new,
			     ff_stat_t *delta, char *buffer, size_t bufflen);

extern char  *ff_stat_toa (char *buff, size_t bufflen, const ff_stat_t *ff,
			   const char *timefmt, const char *sep, int verbose);

/*
 * This modules per-server configuration structure.
 */

typedef struct {
	unsigned long vmsize;	/* Max VM per process before we quit. */
	unsigned long utime;
	unsigned long stime;
	unsigned long cutime;
	unsigned long cstime;
        unsigned long minflt;	/* Minor fault count */
        unsigned long majflt;	/* Major (real swap) fault count */
        unsigned long cminflt;	/* Child minor fault count */
        unsigned long cmajflt;	/* Child major (real swap) fault count */
	unsigned int  rss;	/* Max RSS per. process before we quit. */
	unsigned int  fds;	/* Max fds per. process before we quit. */
        time_t   tick;		/* Elapsed seconds. */

        proc_fd_info_list_t *fd_list;
} ff_threshold_t;

extern char *ff_threshold_toa (char *buff, size_t bufflen, const ff_threshold_t *thresh,
			       const char *pfx, const char *timefmt, const char *sep, int verbose);
extern int check_threshold (char *buff, size_t bufflen, const ff_threshold_t *thresh, 
			    const ff_stat_t *test, const char *timefmt, int verbose);
extern  void init_threshold (ff_threshold_t *thresh);


/* If something wants to log down deep, hook here. */

extern int ff_stat_log_debug_hook_register (void *context, vfprintf_like_log_hook_t logfunc, int level);

#endif /* DEFINED(FF_STAT_H) */
