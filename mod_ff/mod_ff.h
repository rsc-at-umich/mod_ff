/*
        Apache Module Fat Finder (mod_ff)

	Copyright 2012-2013 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: mod_ff.h,v 1.11 2013/03/07 16:09:31 rsc Exp $
*/

#if !defined(MOD_FF_H)
#  define MOD_FF_H "$Id: mod_ff.h,v 1.11 2013/03/07 16:09:31 rsc Exp $"
/*
 * Include the core server components.
 */

#  include <unistd.h>
#  include <stdarg.h>
#  include <time.h>
#  include <sys/resource.h>
#  include <string.h>

#  include "httpd.h"

/*
 * Get local externals
 */
#  include "timevals.h"
#  include "rusage.h"
#  include "apr_utility.h"
#  include "utility.h"
#  include "ff_stat.h"

#  define SUPPRESS_CHILD_OVERHEAD 20	/* Default number of times to suppress. */

#  define FF_DIRECTIVE_PFX "FF"

extern module AP_MODULE_DECLARE_DATA ff_module;

/*
 * Some switches to show if various flags were EVER turned on.
 *
 * Set by configuration, used by ff_child_cleanup()
 */

extern int ff_any_enabled;
extern int ff_any_verbose;
extern int ff_any_checkoverhead;
extern int ff_any_extended;


#  if !defined(FF_DEBUG_PROCINFO)
#    define FF_DEBUG_PROCINFO 1
#  endif /* defined(FF_DEBUG_PROCINF) */

/* Record our current position. */
typedef struct {
        const char  *tag;	/* A name for this position. */
        server_rec  *s;		/* Current server (local port - http/https -  found here.)  */

        /* connection stuff. */ 
        const char  *conn_remote_ip;	/* Remote IP address as string */
        apr_int32_t  conn_family;
        apr_port_t   conn_remote_port;	/* Remote TCP port */
        const char  *session_cookie_name;
        char        *session_cookie;
  

        /* Our stats and counters. */
        unsigned int request_count;	/* Our version of requests-per-child */
        unsigned int session_count;	/* Times used for same session */
        ff_stat_t    ff; 		/* Current stats. */
        int          ff_valid;		/* Are current stats valid? */
        
        struct rusage overhead;		/* Overhead total for this position */
} modff_position_t;

#define _NULL_HOSTNAME "(none)"
#define NULL_HOSTNAME(_hostname) ((_hostname) == (char *) NULL ? _NULL_HOSTNAME : (_hostname))
#define SERVER_HOSTNAME(_s) (((_s) == (server_rec *) NULL) ? _NULL_HOSTNAME : NULL_HOSTNAME((_s)->server_hostname))
#define MODFF_POS_NONE _NULL_HOSTNAME

#define MODFF_POS(_tag) 			\
  {						\
  	_tag,		/* tag */		\
	(server_rec *) NULL,			\
	MODFF_POS_NONE,	/* conn_remote_ip */	\
	-1,		/* conn_family */	\
	-1,  		/* conn_remote_port */	\
	(char *) NULL,	/* session_cookie_name */ \
	(char *) NULL,	/* session_cookie */	\
	0,		/* request_count */	\
	0,		/* session_count */	\
	(ff_stat_t) {0}, /* ff */		\
	0,		/* ff_valid */		\
        (struct rusage) {0,0} /* overhead */	\
   }


/* Apache module configuration structure */

#define FF_UNSET   0
#define FF_DISABLE 1
#define FF_ENABLE  2
#define FF_FULL    3	/* still two bits. */

#define FF_FLAG(_thing) unsigned int _thing :2
#define ENABLED(_cnf,_flag) (((_cnf)->_flag == FF_ENABLE)||((_cnf)->_flag == FF_FULL))
#define NOT_ENABLED(_cnf,_flag) (((_cnf)->_flag != FF_ENABLE)&&((_cnf)->_flag != FF_FULL))
#define DISABLED(_cnf,_flag) ((_cnf)->_flag == FF_DISABLE)
#define NOT_DISABLED(_cnf,_flag) ((_cnf)->_flag != FF_DISABLE)
#define FLAGVAL(_cnf,_flag) (((_cnf)->_flag == FF_ENABLE) ? 1 : ((_cnf)->_flag == FF_FULL) ? 2 : 0)

typedef struct {
	ff_threshold_t exit_child;	/* Maximum change since child begins */
        ff_threshold_t warn_child;	/* Warning since child begins. */

	ff_threshold_t exit_request;	/* Maximum change since request begins */
        ff_threshold_t warn_request;	/* Warning since request begins */

	ff_threshold_t exit_session;	/* Maximum change since session begins */
        ff_threshold_t warn_session;	/* Warning since session begins */

        ff_threshold_t exit_idle;	/* Maximum idle time between requests */
        ff_threshold_t warn_idle;	/* Warning about idle children. */

        ff_threshold_t exit_internal;	/* Maximums for special internal requests. */
        ff_threshold_t warn_internal;	/* Warning about special internal requests */

        FF_FLAG(enabled);
        FF_FLAG(verbose);	    /* Turn up verbosity */
        FF_FLAG(extended);	    /* Do extended gathering */
        FF_FLAG(cleanup);  	    /* Release /proc/self/.. file descriptors */
  	FF_FLAG(debug_config);	    /* Extra debugging for configuration management */
        FF_FLAG(debug_procinfo);    /* Debug the proc_fd_info_list * stuff. */
        FF_FLAG(verbose_postmortem);/* Verbose messages on "Postmortem" reports */
        FF_FLAG(dump_env);	    /* Dump GET/POST 'env' value pairs for this location to error */
        FF_FLAG(dump_headers);	    /* Dump headers for this location to error */

        FF_FLAG(debug_position);    /* Debug the position management handling */
#define DEBUG_POSITION(_cnf) (ENABLED(_cnf,debug_position))

        FF_FLAG(debug_session);     /* Debug the session management handling */
#define DEBUG_SESSION(_cnf) (ENABLED(_cnf,debug_session)||ENABLED(_cnf,debug_position))

        FF_FLAG(log_main);	    /* Log delta/exit events on main errorlog */
        FF_FLAG(do_loopback);       /* Do stuff on loopback requests. */
        FF_FLAG(do_remote_tcpport); /* Check session sameness based on remote_port */
        FF_FLAG(do_internal);       /* Do stuff on an internal request. */

        FF_FLAG(watchrequest);	    /* Turn on watching for request */
        FF_FLAG(overhead_request);  /* Display overhead of requests */

        FF_FLAG(watchchild);	    /* Turn on watching for child */
        FF_FLAG(overhead_child);    /* Display total overhead of children */

        FF_FLAG(watchsession);	    /* Turn on watching for session */
        FF_FLAG(overhead_session);  /* Display overhead of sessions */

        FF_FLAG(watchidle);	    /* Turn on watching for idle */
        FF_FLAG(overhead_idle);     /* Display overhead of idles */

        FF_FLAG(watchinternal);	    /* Turn on watching for internal */
        FF_FLAG(overhead_internal); /* Display overhead of internals */
  
        FF_FLAG(defined_ignore_status); /* Is "ignore_status" below set? */
        FF_FLAG(defined_remote_ip_sources); /* Is "remote_ip_sources" below set? */

	unsigned int max_requests_per_child;
        unsigned int max_requests_per_session;
        unsigned int suppress_child_overhead; 
        unsigned int id;	/* An ID per. allocated object. */
        const char * pfx;	/* Typically "/proc" for Linux, "/compat/linux/proc" on FreeBSD */
        const char * labelid;	/* Label/ID string for logs. */
        const char * path;	/* To distinguish between server and directory confs */
        const char * timefmt;	/* How to display timestamps. */
        const char * session_cookie_name; /* Session cookie name to check for same session */

        intlist_t  * ignore_status;  /* Ignore status codes wuth these values. */
        strlist_t  * remote_ip_sources; /* How do we fill out the remote_ip field? */
} modff_config_t;


extern int ff_overhead_any (const modff_config_t *conf);  /* Calculate the complicate overhead combination */

#define POSITION_TAG(_pos) ((_pos) == (modff_position_t *) NULL ? "*lost*" : (((_pos)->tag) ? (_pos)->tag : "*?*"))
extern char *position_toa (char *buffer, size_t bufflen, const modff_position_t *pos, int verbose);
		     
extern modff_config_t *ff_find_config (const char *by_func, cmd_parms *params, void *mconfig);
extern modff_config_t *ff_find_rconfig (request_rec *r, server_rec **p_server);
extern modff_config_t *ff_find_sconfig (const char *by_func, server_rec *s);

extern void            ff_child_init (apr_pool_t *p, server_rec *s);
extern int             ff_request_begin (request_rec *r);
extern int             ff_request_end (request_rec *r);

extern void  ff_sreport (const char *file, int lnum, int level, apr_status_t status,
			 const server_rec *s, const ff_stat_t *ff, const char *timefmt,
			 int verbose, int dump, const char *fmt, ...) __attribute__((format(printf,10,11)));

extern void  ff_rreport (const char *file, int lnum, int level, apr_status_t status,
			 const request_rec *r, const ff_stat_t *ff, const char *timefmt,
			 int verbose, int dump, const char *fmt, ...) __attribute__((format(printf,10,11)));

extern void  ff_swatch (const char *file, int lnum, int level, apr_status_t status,
			 const server_rec *s, const ff_stat_t *ff, const char *timefmt,
			int verbose, const char *fmt, ...) __attribute__((format(printf,9,10)));

extern void  ff_rwatch (const char *file, int lnum, int level, apr_status_t status,
			 const request_rec *r, const ff_stat_t *ff, const char *timefmt,
			 int verbose, const char *fmt, ...) __attribute__((format(printf,9,10)));

extern const char *ff_labelid (modff_config_t *conf);

extern int         ff_copy_position (const char *by_func, modff_position_t *dest, modff_position_t *src);

/* If all listening port#s are same, then return port#, otherwise a hash of ports#s */
extern int         ff_ap_server_porthash (const server_rec *s);

/* brief text representation of 'server_rec *' */
extern char       *ff_ap_server_name (char *buffer, size_t bufflen, const server_rec *s);


/* debugging in a context free space. */

extern int ff_log_debug (int level, const char *fmt, ...)  __attribute__((format(printf,2,3)));


#  if !defined(REPORT_BUFFLEN)
#    define REPORT_BUFFLEN 1024
#  endif
#  if !defined(REPORT_BUFFLEN_LONG)
#    define REPORT_BUFFLEN_LONG REPORT_BUFFLEN*4
#  endif /* REPPORT_BUFFLEN_LONG */

#endif /* defined(MOD_FF_H) */
