/*
	Copyright 2012-2013 by the Regents of the University of Michigan
	All Rights Reserved
*/

#if !defined(_PROC_INFO_H)
#  define _PROC_INFO_H "$Id: procinfo.h,v 1.9 2013/01/04 21:04:48 rsc Exp $"

#  if !defined(STAT_COMM_SIZE)
#    define STAT_COMM_SIZE 256
#  endif

#  include <sys/types.h>
#  include <sys/stat.h>

#  include "utility.h"

/* This is a representation of /proc/[pid]/stat.
 *
 * The values laid out here are NOT in the order they are laid out in /proc/[pid]/stat
 *
 * Some values are kernel dependent.
 *
 * See http://www.kernel.org/doc/man-pages/online/pages/man5/proc.5.html
 */

typedef struct {
    unsigned long long stat_starttime;  /* %llu Time in jiffies since boot time of when this process started. */

    unsigned long stat_flags; 	   /* %lu */
    unsigned long stat_minflt;     /* %lu (minor faults, not requiring pagein) */
    unsigned long stat_cminflt;    /* %lu (... of children) */
    unsigned long stat_majflt;     /* %lu (major faults requiring pagein) */
    unsigned long stat_cmajflt;    /* %lu (... of children) */
    unsigned long stat_utime;      /* %lu (user mode jiffies) */
    unsigned long stat_stime;      /* %lu (kernel mode jiffies) */
    unsigned long stat_vsize;	   /* %lu Virtual Memory size in  bytes. */
    unsigned long stat_rsslim;	   /* %lu RSS limit */
    unsigned long stat_startcode;  /* %lu address above which for code */
    unsigned long stat_endcode;    /* %lu address below which code can run. */
    unsigned long stat_startstack; /* %lu address of the start of the stack */
    unsigned long stat_kstkesp;    /* %lu Current value of esp (stack ptr) found in kernel stack page */
    unsigned long stat_kstkeip;    /* %lu Current eip (instruction pointer) */  
    unsigned long stat_signal;	   /* %lu Bitmap of pending signals */
    unsigned long stat_blocked;	   /* %lu Bitmap of blocked signals */
    unsigned long stat_sigignore;  /* %lu Bitmap of ignored signals */
    unsigned long stat_sigcatch;   /* %lu Bitmap of catched(sp!) signals */
    unsigned long stat_wchan;	   /* %lu Channel/Address of a system call */	
    unsigned long stat_nswap;	   /* %lu Number of pages swapped (not maintained) */
    unsigned long stat_cnswap;	   /* %lu Cumulative nswap for child processes */
    
    long stat_cutime;     /* %ld (user mode jiffies for process and children) */
    long stat_cstime;     /* %ld (kernel mode jiffies for process and children) */
    long stat_priority;	  /* %ld Nice value + 15 */
    long stat_nice;       /* %ld Nice values */
    long stat_num_threads;  /* %ld - Number of threads in process */
    long stat_itrealvalue;  /* %ld time in jiffies to next SIGALARM */
    long stat_rss;	  /* %ld Resident Set Size in PAGES */

    int stat_pid;		/* %d */
    int stat_ppid;		/* %d */
    int stat_pgrp;		/* %d */
    int stat_session;		/* %d */
    int stat_tty_nr;		/* %d */
    int stat_tpgid;		/* %d */
    int stat_exit_signal;	/* %d signal to be sent to parent when we die */
    int stat_processor;		/* %d Processor number last executed on */

    char stat_comm[STAT_COMM_SIZE];	/* Name of running program. */
    char stat_state;

} proc_stat_info_t;


/* This is a representation of /proc/[pid]/statm.
 *
 * Some values are kernel dependent.
 *
 * See http://www.kernel.org/doc/man-pages/online/pages/man5/proc.5.html
 */
typedef struct {
    unsigned long statm_size;		/* total program size */
    unsigned long statm_resident;	/* resident set size */
    unsigned long statm_share;		/* shared pages */
    unsigned long statm_trs;		/* text (code) */
    unsigned long statm_drs;		/* data/stack */
    unsigned long statm_lrs;		/* library */
    unsigned long statm_dt;		/* dirty pages */
} proc_statm_info_t;


#  if !defined(PROCINFO_MAX_PATHLEN)
#    if defined(MAX_PATH_LEN)
#      define PROCINFO_MAX_PATHLEN MAX_PATH_LEN
#    else
#      define PROCINFO_MAX_PATHLEN 1024
#    endif
#  endif

#  if !defined(PROCINFO_FD_LIST_SIZE)
#     define PROCINFO_FD_LIST_SIZE 30
#  endif

typedef struct {
    int             fd;         /* File descriptor number */
    int             valid:1;	/* Is this structure counted? */
    int             inuse:1;	/* Is this structure in use? */
    int             stat_ok:1;  /* is value in 'start' OK? */ 
    int             mine:1;     /* Should free_proc_fd_info() free this? */
    int             tmpcmp:1;	/* Temporary bit for cmp operation */
    int             path_ok:1;   /* Could path be determined? */
    struct stat     stat;       /* stat information */
    off_t           pos;        /* Current location??? */
    unsigned short  pathlen;	/* # of bytes in path - excluding trailing '\0' */
    const char     *path;       /* Path */
} proc_fd_info_t;

typedef struct proc_fd_info_list_struct proc_fd_info_list_t;

struct proc_fd_info_list_struct {
    proc_fd_info_list_t	*next;	/* Linked list for more. */
    unsigned short  size; 	/* Number of slots avail in list[] */
    unsigned short  valid;	/* Count of valid (non-empty) in list[] */
    proc_fd_info_t  list[1];
};


typedef struct {
    proc_fd_info_list_t *pos;
    unsigned int         i;
} iterate_proc_fd_info_list_t;


/*
 * postmortem_xxx() routines return a string showing memory usage. 
 *
 * If pedantic == 0, then an empty string is given if allocs == frees,
 * else if pedantic != 0, then a full report is given.
 */

extern char *postmortem_proc_fd_info (char *buffer, size_t bufflen, long long expected_fd, 
				      long long expected_fd_path, int pedantic);

extern char *postmortem_proc_fd_info_list (char *buffer, size_t bufflen, 
				    long long expected_list, long long expected_fd, 
				    long long expected_fd_path, int pedantic);


#define COUNT_PROC_FD_INFO_PROTO_ARGS long long *p_fd_info, long long *p_fd_info__path
#define PASS_PROC_FD_INFO_PARAMETERS(_p_fi,_p_fi_p) _p_fi, _p_fi_p

extern void count_proc_fd_info (const proc_fd_info_t *pfi, COUNT_PROC_FD_INFO_PROTO_ARGS );



#define COUNT_PROC_FD_INFO_LIST_PROTO_ARGS long long *p_fd_info_list, long long *p_fd_info__path
#define PASS_PROC_FD_INFO_LIST_PARAMETERS(_p_fil,_p_fi_p) _p_fil, _p_fi_p

extern void count_proc_fd_info_list (const proc_fd_info_list_t *pfil, COUNT_PROC_FD_INFO_LIST_PROTO_ARGS );


#define COUNT_EXPECTED_FD_INFO_PROTO_ARGS long long *p_fd_info_list, COUNT_PROC_FD_INFO_PROTO_ARGS
#define PASS_EXPECTED_FD_INFO_PARAMETERS(_p_fil,_p_fi,_p_fi_p) _p_fil, 	\
    PASS_PROC_FD_INFO_LIST_PARAMETERS(_p_fi,_p_fi_p)


/*
 * Note: Call with NULL parameters to clear any internal state information
 *  (i.e.: free file descriptors used)
 */

extern int    get_proc_stat_info (const char *procname, proc_stat_info_t *st);

extern char  *proc_stat_info_toa (char *buffer, size_t bufflen, const proc_stat_info_t *st,
				  const char *sep, int verbose);


/*
 * Note: Call with NULL parameters to clear any internal state information
 *  (i.e.: free file descriptors used)
 */

extern int    get_proc_statm_info (const char *procname, proc_statm_info_t *stm);

extern char  *proc_statm_info_toa (char *buffer, size_t bufflen, const proc_statm_info_t *stm,
				  const char *sep, int verbose);

extern int     delta_proc_statm_info (const proc_statm_info_t *old, const proc_statm_info_t *new,
				      proc_statm_info_t *delta);

extern int     get_proc_fd_count (const char *procname, proc_fd_info_list_t **p_list);


extern proc_fd_info_list_t *dup_proc_fd_info_list (proc_fd_info_list_t *list);

/* Returns total number of free'd objects of any kind. */
extern unsigned int free_proc_fd_info_list (proc_fd_info_list_t *list);

extern int     cmp_proc_fd_info (const proc_fd_info_t *a, const proc_fd_info_t *b);

extern int     cmp_proc_fd_info_list (proc_fd_info_list_t *a,
				      proc_fd_info_list_t *b,
				      char *buffer, size_t bufflen, const char *sep,
				      int verbose);

extern char *  proc_fd_info_toa (char *buffer, size_t bufflen, const proc_fd_info_t *pfi, int verbose);

/* pfi is free()'d if return is 2 or 3 */
extern unsigned int  reset_proc_fd_info (proc_fd_info_t *pfi);

extern proc_fd_info_t *get_proc_fd_info (proc_fd_info_t *buff, const char *procfdpath);


extern void begin_iterate__proc_fd_info_list (iterate_proc_fd_info_list_t *it, 
				       proc_fd_info_list_t *list);

extern proc_fd_info_t *next_iterate__proc_fd_info_list (iterate_proc_fd_info_list_t *it);


/* If something wants to log down deep, hook here. */

extern int proc_fd_info_log_debug_hook_register (void *context, vfprintf_like_log_hook_t logfunc, int level);

#endif /* defined(_PROC_INFO_H) */

