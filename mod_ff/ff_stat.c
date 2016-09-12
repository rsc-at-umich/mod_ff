/*
        Manipulate the basic ff_stat_t and ff_threshold_t structures

	Copyright 2012-2013 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: ff_stat.c,v 1.12 2013/01/04 22:03:44 rsc Exp $

	This file implements MOST of the application utilities.
	It DOES NOT contain any dependencies on Apache.
*/

/*
 * Include the core server components.
 */
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

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
#include "procinfo.h"
#include "ff_stat.h"


#if !defined(FF_UNSET)
#  define FF_UNSET 0
#endif /* FF_UNSET */


ff_stat_t *(*next_expected_ff_stat) (void *context) = NULL;

static int log_debug (int level, const char *fmt, ...) __attribute__((format(printf,2,3)));

/*
 * When we're doing log hooking
 */

static void *log_debug_hook_context = (void *) NULL;
static vfprintf_like_log_hook_t log_debug_hook_func = (vfprintf_like_log_hook_t) NULL;
static int log_debug_hook_level = 0;

int
ff_stat_log_debug_hook_register (void *context, vfprintf_like_log_hook_t logfunc, int level)
{
    __FUNC(ff_stat_log_hook_register);

    log_debug_hook_context = context;
    log_debug_hook_func = logfunc;
    log_debug_hook_level = level;

    /* Pass it down another level. */
    proc_fd_info_log_debug_hook_register (context, logfunc, level);

    return (0);

} /* end of ff_stat_log_debug_hook_register() */


static int
log_debug(int level, const char *fmt, ...)
{
    int res = 0;
    va_list ap;

    va_start (ap, fmt);
    
    if ((level <= log_debug_hook_level) && (log_debug_hook_func != (vfprintf_like_log_hook_t) NULL))
    {
        res = log_debug_hook_func (log_debug_hook_context, fmt, ap);
    }
    va_end (ap);

    return res;
} /* end of log_debug() */



#if defined(NOT_NOW)
void 
count_expected_ff (const ff_stat_t *ff, COUNT_EXPECTED_FF_PROTO_ARGS)
/*
count_expected_ff_t
count_expected_ff
*/
{
    if (ff == (ff_stat_t *) NULL)
        return;

    /* Don't bother countin' if we've no place to count */
    if ((p_fd_info__path == (long long *) NULL) &&
	(p_fd_info_list == (long long *) NULL))
        return;
    
    /* As ugly as this is, it lets us change our macros around and change the
       arguments around with some code safety. (I.e.: things won't compile if
       we don't get it right, rather than failing mysteriously.
    */

    count_proc_fd_info_list (ff->fds_info,
		     PASS_PROC_FD_INFO_LIST_PARAMETERS(p_fd_info_list,p_fd_info__path));

    return;

} /* end of count_expected_ff() */
#endif /* defined(NOT_NOW) */

/*
 * ff_stat() doesn't directly allocate or free memory, but the routines it
 * calls on does. Ergo.. a postmortem and a placeholder. 
 */
char *
postmortem_ff_stat (char *buffer, size_t bufflen, 
		    next_expected_ff_stat_t next_expected_ff_stat,
		    count_expected_ff_t expected_ff,
		    int pedantic)
{
    long long fd_info = -1;
    long long fd_info__path = -1;
    long long fd_info_list = -1;

    if (! buffer | (bufflen < 10))
      return buffer;

    if ((expected_ff != (count_expected_ff_t) NULL) && (next_expected_ff_stat != NULL))
    {
        ff_stat_t *each_ff;
	void *context = (void *) NULL;

	for (each_ff = next_expected_ff_stat (&context);
	     each_ff;
	     each_ff = next_expected_ff_stat (&context))
	{
	    expected_ff (each_ff, PASS_EXPECTED_FF_PARAMETERS(&fd_info_list,
							      &fd_info,
							      &fd_info__path));
	}

	/* Note: 'context' should be NULL at this point. */
    }

    /*
      If there was other stuff allocated in `ff_stat_t', 
      we'd have to have more counters at this level and
      another function call to `postmortem' the counters into
      the buffer.
    */

    return postmortem_proc_fd_info_list (buffer, bufflen, fd_info, 
					 fd_info__path, fd_info_list,
					 pedantic);

} /* end of postmortem_ff_stat() */


void
count_ff_stat (const ff_stat_t *ff, COUNT_EXPECTED_FF_PROTO_ARGS)
{
    /* Don't try to count if we got nothin' ta count. */
    if (ff == (ff_stat_t *) NULL)
        return;

    /* Don't bother countin' if we've no place to count */
    if ((p_fd_info__path == (long long *) NULL) &&
	(p_fd_info_list == (long long *) NULL))
        return;

    count_proc_fd_info_list (ff->fds_info, 
			     PASS_PROC_FD_INFO_LIST_PARAMETERS(p_fd_info_list, p_fd_info__path));

    return;

} /* end of count_ff_stat () */


int
get_ff_stat (const char *pfx, ff_stat_t *ff, int overhead, int extra)
{
    char procname[1024];   /* Should be enough. */
    proc_stat_info_t st;
    int  fds;
    int  rc = 0;
    int  valid_rusage = 0;
    int  valid_proc_statm_info = 0;
    struct rusage ru_lo;
    struct rusage ru_hi;
    proc_statm_info_t stm_lo;
    proc_statm_info_t stm_hi;
    proc_fd_info_list_t **p_fds = (proc_fd_info_list_t **) NULL;

    if (overhead)
    {
        memset ((void *) &ru_lo, 0, sizeof(ru_lo)); 

	if ((valid_rusage = getrusage (RUSAGE_SELF, &ru_lo)) != 0)
	{
#if !defined(TRUST_GETRUSAGE)
	    ru_lo.ru_utime.tv_sec = 1234;
	    ru_lo.ru_utime.tv_usec = 5678;
	    ru_lo.ru_stime.tv_sec = 1234;
	    ru_lo.ru_stime.tv_usec = 5678;
#endif
	}
	else  {
	    memset ((void *) &ru_hi, 0, sizeof(ru_hi)); 
	}
    }

    (void) reset_ff_stat (ff);

    if (extra)
        p_fds = &(ff->fds_info);

    snprintf (procname, sizeof(procname), "%s/self", pfx);

    ff->tick = time((time_t *) NULL);


    /* Because Linux doesn't properly implement getrusage() ... */
    if (overhead > 1)
    {
        memset ((void *) &stm_lo, 0, sizeof(stm_lo));
	    
	valid_proc_statm_info = get_proc_statm_info (procname, &stm_lo);
    }

    if (get_proc_stat_info (procname, &st) == 0)
    {
	ff->vmsize = st.stat_vsize;
	ff->utime = st.stat_utime;
	ff->stime = st.stat_stime;
	ff->cutime = st.stat_cutime;
	ff->cstime = st.stat_cstime;
	ff->minflt = st.stat_minflt;
	ff->majflt = st.stat_majflt;
	ff->cminflt = st.stat_cminflt;
	ff->cmajflt = st.stat_cmajflt;
	ff->rss = st.stat_rss;
    }
    else
    {
	rc += 1;
    }

    if ((fds = get_proc_fd_count (procname, p_fds)) > 0)
    {
	ff->fds = fds;
    }
    else
    {
	rc += 2;
    }

    /* If overhead checking is enabled, then let's gather the data. */
    if (overhead)
    {
      int ok; /* return value from getrusage() */

	/* Because Linux doesn't properly implement getrusage() ... */
        if ((overhead > 1) && (valid_proc_statm_info == 0))
	{
	    memset ((void *) &stm_hi, 0, sizeof(stm_hi));
	    
	    if (get_proc_statm_info (procname, &stm_hi) == 0)
	    {
		(void) delta_proc_statm_info (&stm_lo, &stm_hi, &(ff->statm));
	    }
	}

	if (valid_rusage == 0)
	{
	    ok = getrusage (RUSAGE_SELF, &ru_hi);
#if defined(DONT_TRUST_GETRUSAGE)
	    if (ok != 0) 
	    {
		ru_lo.ru_utime.tv_sec = 6666;
		ru_lo.ru_utime.tv_usec = 7777;
		ru_lo.ru_stime.tv_sec = 8888;
		ru_lo.ru_stime.tv_usec = 9999;
		
		ok = 0;
	    }
#endif /* defined(DONT_TRUST_GETRUSAGE) */
	    if (ok == 0)
	    {
	        delta_rusage (&ru_lo, &ru_hi, &(ff->overhead));
	    }
	}
    }

    
    return rc;

} /* end of int get_ff_stat (const char *pfx, ff_stat_t *ff, int overhead, int extended) */


void
cleanup_ff_stat(void)
{
    (void) get_proc_stat_info ((char *) NULL, (proc_stat_info_t *) NULL);
    (void) get_proc_fd_count ((char *) NULL, (proc_fd_info_list_t **) NULL);
    (void) get_proc_statm_info ((char *) NULL, (proc_statm_info_t *) NULL);

    return;
}  /* cleanup_ff_stat() */

 

int
move_ff_stat (ff_stat_t *dest, ff_stat_t *src)
{
    int ret;

    if ((src == (ff_stat_t *) NULL) || (dest == (ff_stat_t *) NULL))
       return (-1);

    ret = reset_ff_stat (dest);

    memcpy ((void *) dest, (void *) src, sizeof (ff_stat_t));

    memset ((void *) src, 0, sizeof (ff_stat_t));

    return (ret);

} /* end of move_ff_stat() */



int
copy_ff_stat (ff_stat_t *dest, ff_stat_t *src)
{
    int ret;

    if ((src == (ff_stat_t *) NULL) || (dest == (ff_stat_t *) NULL))
       return (-1);

    ret = reset_ff_stat (dest);

    memcpy ((void *) dest, (void *) src, sizeof (ff_stat_t));

    dest->fds_info = dup_proc_fd_info_list (src->fds_info);

    return (ret);

} /* end of copy_ff_stat() */



unsigned int
reset_ff_stat (ff_stat_t *ff)
{
    __FUNC(reset_ff_stat);
    unsigned int ret = 0;

    if (ff == (ff_stat_t *) NULL)
        return (0);

    if (ff->fds_info)
    {
        ret = free_proc_fd_info_list (ff->fds_info);
	if (ret == 0)
	{
	    log_debug (1, "%s: Nothing free'd despite something there", _func);
	}
    }

    memset ((void *) ff, 0, sizeof(ff_stat_t));

    return (ret);

} /* reset_ff_stat() */


/*
 * Examine changes between 'old' and 'new' ff_stat_t structures.
 *
 * Return values (aka. bitmask)
 *
 *    0 (0x0000) == the same.
 *    1 (0x0001) == vmsize changes.
 *    2 (0x0002) == rss changes.
 *    4 (0x0004) == utime changes
 *    8 (0x0008) == stime changes.
 *   16 (0x0010) == cutime changes.
 *   32 (0x0020) == cstime changes.
 *   64 (0x0040) == minflt changes
 *  128 (0x0080) == majflt changes
 *  256 (0x0100) == cminflt changes
 *  512 (0x0200) == cmajflt changes
 * 1024 (0x0400) == fds (count) changes
 * 2048 (0x0800) == file descriptors in 'fds_info' doesn't match
 *
 * Example:
 * 3139 
 * (0x0c43) == 0x080 (fds_info) | 0x0400 (fds) | 0x00040(minflt) | 0x0002 (rss) | 0x0001 (vmsize) 
 *
 *
 *
 */
int
delta_ff_stat (const ff_stat_t *old, const ff_stat_t *new, ff_stat_t *delta,
	       char *buffer, size_t bufflen)
{
    int rc = 0;

    reset_ff_stat (delta);

#define DELTA_FF_STAT(_field,_code)	_DELTA(_field,_code,old,new,delta,rc)
    
    DELTA_FF_STAT(vmsize, 1);
    DELTA_FF_STAT(rss, 2);
    DELTA_FF_STAT(utime, 4);
    DELTA_FF_STAT(stime, 8);
    DELTA_FF_STAT(cutime, 16);
    DELTA_FF_STAT(cstime, 32);
    DELTA_FF_STAT(minflt, 64);
    DELTA_FF_STAT(majflt, 128);
    DELTA_FF_STAT(cminflt, 256);
    DELTA_FF_STAT(cmajflt, 512);
    DELTA_FF_STAT(fds, 1024);	/* Maybe this can be ignored? */
    DELTA_FF_STAT(tick, 2048);

    if (buffer)
    {
        *buffer = '\0';
	(void) cmp_proc_fd_info_list (old->fds_info, new->fds_info, buffer, bufflen,
				      (char *) NULL, 0);
    }
    
    if (rc == 4095)
      return (-1);	/* All failed. */

    return (rc);

} /* end of delta_ff_stat (const ff_stat_t *old, const ff_stat_t *new, ff_stat_t *delta) */



char *
ff_stat_toa (char *buff, size_t bufflen, const ff_stat_t *ff, const char *timefmt,
	     const char *sep, int verbose)
{
    char tock_buff[128];
    char *tock;
    char *pos = buff;

    if (sep == (char *) NULL)
        sep = ", ";

    if ((buff == (char *)  NULL) || (bufflen < 10) || (ff == (ff_stat_t *) NULL))
    {
        return ((char *) NULL);
    }

    if (verbose | (ff->tick > 0))
    {
        tock = tick_toa (tock_buff, sizeof(tock_buff), ff->tick, (char *) NULL,
			 timefmt, verbose);
    }
    else 
    {
	tock = (char *) NULL;
    }

    *buff = '\0';

#define FF_SEP(_sep)	if (pos != buff) {	\
      strncat (pos, _sep, bufflen);		\
      len = strlen(pos); 			\
      pos += len;				\
      bufflen -= len;				\
    }

#define FF_STAT_TOA(_field,_name,_fmt) {	\
      int len;					\
      if (verbose || (ff->_field > 0)) {	\
	FF_SEP(sep);				\
	snprintf(pos, bufflen, _name ": " _fmt, ff->_field);	\
	len = strlen(pos);			\
	pos += len;				\
	bufflen -= len;				\
      } }
 
#define FF_STAT2_TOA(_field1,_field2,_name,_fmt) {		\
      int len;							\
      if (verbose || (ff->_field1 > 0) || (ff->_field2 > 0)) {	\
	FF_SEP(sep);						\
	snprintf(pos, bufflen, _name ": " _fmt, ff->_field1, ff->_field2);	\
	len = strlen(pos);					\
	pos += len;						\
	bufflen -= len;						\
      } }
 
    FF_STAT_TOA(vmsize, "vmsize", "%lu");
    FF_STAT_TOA(rss, "rss", "%u");
    FF_STAT_TOA(fds, "fds", "%u");
    FF_STAT2_TOA(utime,stime, "[u/s]time", "%lu/%lu");
    FF_STAT2_TOA(cutime,cstime, "c[u/s]time", "%lu/%lu");
    FF_STAT2_TOA(minflt,majflt, "[min/maj]flt", "%lu/%lu");
    FF_STAT2_TOA(cminflt,cmajflt, "c[min/maj]flt", "%lu/%lu");

    if (tock && (*tock != '\0')) {
        int len;

	FF_SEP(sep);
	snprintf (pos, bufflen, "tick: %s", tock);
	len = strlen (pos);
	pos += len;
	bufflen -= len;
    }

#if defined(DONT_DO_THIS)    
    /* Reuse tock and tock_buff */
    tock_buff[0] = '\0';
    tock = proc_statm_info_toa (tock_buff, sizeof(tock_buff) , &(ff->statm), sep, verbose);
    if (tock_buff[0])
    {
        int len;

        FF_SEP(sep);

	strncat (pos, tock_buff, bufflen);
	len = strlen (pos);
	pos += len;
	bufflen -= len;
    }
#endif /* DONT_DO_THIS */
    
    if (verbose && (ff->fds_info != (proc_fd_info_list_t *) NULL))
    {
        iterate_proc_fd_info_list_t iter;
	proc_fd_info_t *pfi;
	int len;
      
	begin_iterate__proc_fd_info_list (&iter, ff->fds_info);
	for (pfi = next_iterate__proc_fd_info_list (&iter);
	     pfi;
	     pfi = next_iterate__proc_fd_info_list (&iter))
	{
	    FF_SEP(sep);

	    (void) proc_fd_info_toa (pos, bufflen, pfi,
				     verbose);
	    len = strlen (pos);
	    pos += len;
	    bufflen -= len;
	}
    }

    return buff;

} /* end of ff_stat_toa (buff, bufflen, ff, timefmt, const char *sep, int verbose) */



char *
ff_threshold_toa (char *buff, size_t bufflen, const ff_threshold_t *thresh,
		  const char *pfx, const char *timefmt, const char *sep, int verbose)
{
    char   tock_buff[128];
    size_t len;
    char *pos = buff;
    unsigned int seplen;

    if ((buff == (char *)  NULL) || (bufflen < 10) || (thresh == (ff_threshold_t *) NULL))
    {
        return ((char *) NULL);
    }

    if (sep == (char *) NULL)
        sep = ", ";

    seplen = strlen (sep);

    *pos = '\0';	/* Same as *buff = '\0' */
   

#define _THRESH_TOA(_thing,_fmt_func) 		\
    if (verbose || (_thing) > 0)		\
    {						\
       if (*buff) {				\
	   strncat (pos, sep, bufflen);		\
	   bufflen -= seplen;			\
	   pos += seplen;			\
       } else if (pfx && *pfx)	{ 		\
	    strncat (pos, pfx, bufflen);	\
	    len = strlen (pos);			\
	    bufflen -= len;			\
	    pos += len;				\
	    strncat (pos, " ", bufflen);	\
	    bufflen --;				\
	    pos ++;				\
	    pfx = (char *) NULL;		\
	}					\
        _fmt_func;				\
	len = strlen (pos);			\
	bufflen -= len;				\
	pos += len;				\
    }


#define UL_THRESH_TOA(_field,_fmt)		\
    _THRESH_TOA(thresh->_field,snprintf(pos,bufflen,_fmt,	\
					(thresh->_field)))

#define U_THRESH_TOA(_field,_fmt)		\
    _THRESH_TOA(thresh->_field,snprintf(pos,bufflen,_fmt,\
					(thresh->_field)))
    
#define T_THRESH_TOA(_field,_fmt)		\
    _THRESH_TOA(thresh->_field,snprintf(pos,bufflen,_fmt,\
	tick_toa(tock_buff, sizeof(tock_buff), thresh->_field,\
		 (char *) NULL, timefmt, verbose)));


    UL_THRESH_TOA(vmsize, "vmsize > %lu");
    U_THRESH_TOA(rss, "rss > %u");
    U_THRESH_TOA(fds, "fds > %u");
    UL_THRESH_TOA(utime, "utime > %lu");
    UL_THRESH_TOA(stime, "stime > %lu");
    UL_THRESH_TOA(cutime, "cutime > %lu");
    UL_THRESH_TOA(cstime, "cstime > %lu");
    UL_THRESH_TOA(minflt, "minflt > %lu");
    UL_THRESH_TOA(majflt, "majflt > %lu");
    UL_THRESH_TOA(cminflt, "cminflt > %lu");
    UL_THRESH_TOA(cmajflt, "cmajflt > %lu");
    T_THRESH_TOA(tick,"tick > %s");

    return buff;

} /* end of ff_threshold_toa() */


int
check_threshold (char *buff, size_t bufflen, const ff_threshold_t *thresh,
		 const ff_stat_t *test, const char *timefmt, int verbose)
{
      int count = 0;
      char tmp[128];  /* Two (longish?) integers, a short string, and some glue. */
      char stat_tock[64];
      char thresh_tock[64];

      if ((buff != (char *) NULL) && (bufflen > 0)) {
	  *buff = '\0';
      }

#define _CHECK(_field,_msg,_fmt_func)				\
      if (thresh->_field > 0) {					\
	int found = 0; int tmplen;				\
	found = (thresh->_field < test->_field);		\
	count += found; /* Record whether check worked */	\
        if (found || verbose) { 				\
	  if ((buff != (char *) NULL) && (bufflen > 2)) {	\
	    _fmt_func;						\
	    tmplen = strlen(tmp);				\
	    if ((tmplen + 2) <  bufflen) {			\
	      if (*buff) {					\
		strcat (buff, "; ");				\
		bufflen -= 2;					\
	      } /* if (*buff) */				\
	      if (found && verbose) { strcat (buff, "*"); tmplen++; }	\
	      strcat (buff, tmp);				\
	      bufflen -= tmplen;				\
	    } /* if (tmplen...)	*/				\
	  } /* if (buff != ...) */				\
        } /* if (thresh->_field < test->_field) */		\
      }	/* if (thresh->+field > 0) */


#define UL_CHECK(_field,_msg) 		\
      _CHECK(_field,_msg,			\
	     snprintf (tmp, sizeof(tmp)-1,	\
		       "%s (%lu > %lu)",_msg,	\
		       test->_field,thresh->_field))


#define U_CHECK(_field,_msg)		\
      _CHECK(_field,_msg,			\
	     snprintf (tmp, sizeof(tmp)-1,	\
		       "%s (%u > %u)", _msg,	\
		       test->_field,thresh->_field))


#define T_CHECK(_field,_msg)				\
      _CHECK(_field,_msg,					\
	     snprintf (tmp, sizeof(tmp)-1,			\
		  "%s (%s > %s)", _msg,				\
		  tick_toa(stat_tock, sizeof(stat_tock),	\
      			   test->_field, (char *) NULL, timefmt, verbose),	\
		  tick_toa(thresh_tock, sizeof(thresh_tock),	\
			   thresh->_field, (char *) NULL, timefmt,verbose)))

      UL_CHECK(vmsize, "vmsize");
      U_CHECK(rss, "rss");
      UL_CHECK(utime, "utime");
      UL_CHECK(stime, "stime");
      UL_CHECK(cutime, "cutime");
      UL_CHECK(cstime, "cstime");
      UL_CHECK(minflt, "minflt");
      UL_CHECK(majflt, "majflt");
      UL_CHECK(cminflt, "cminflt");
      UL_CHECK(cmajflt, "cmajflt");
      U_CHECK(fds, "fds");
      T_CHECK(tick,"tick");

      return count;

} /* end of
   *
   * check_threshold (char *buff, size_t bufflen, const ff_threshold_t *thresh,
   *                  const ff_stat_t *test, const char *timefmt, int verbose)
   */



void
init_threshold (ff_threshold_t *thresh)
{
    /* If we're called stupidly, just stupidly return. */
    if (thresh == (ff_threshold_t *) NULL)
      return;
    
    /* This could be done with
     * 
     * memset ((void *) thresh, 0, sizeof(ff_threshold_t)); 
     *
     * But we're pedantic.  Really, really pedantic.
     */

    thresh->vmsize = FF_UNSET;
    thresh->utime = FF_UNSET;
    thresh->stime = FF_UNSET;
    thresh->cutime = FF_UNSET;
    thresh->cstime = FF_UNSET;
    thresh->minflt = FF_UNSET;
    thresh->majflt = FF_UNSET;
    thresh->cminflt = FF_UNSET;
    thresh->cmajflt = FF_UNSET;
    thresh->rss = FF_UNSET;
    thresh->fds = FF_UNSET;
    thresh->tick = FF_UNSET;

    return;		/* Because we're pedantic. */

} /* end of init_threshold () */

