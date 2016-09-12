/*
        Apache Module Fat Finder (mod_ff)
	Handlers and like action

	Copyright 2012-2013 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: ff_handlers.c,v 1.15 2013/03/12 19:06:16 rsc Exp $

	This file provides the interface between Apache APIs and
	the underlying login APIs.
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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"
#include "mpm_common.h"
#include "apr_strings.h"
#include "apr_env.h"
#include "apr_tables.h"

/* This takes care of resolving between Apache autoconf and this modules autoconf */
#include "unpackage_autoconf.h"


/*
 * Get local externals
 */
#include "timevals.h"
#include "rusage.h"
#include "apr_utility.h"
#include "utility.h"
#include "procinfo.h"
#include "ff_stat.h"
#include "mod_ff.h"

#if !defined(_MAX)
#  define _MAX(a,b)  ((a)>(b) ? (a) : (b) )
#endif /* _MAX */


#if !defined(FD_REPORT_SIZE)
#  if defined(REPORT_BUFFLEN_LONG)
#    define FD_REPORT_SIZE REPORT_BUFFLEN_LONG*2
#  else
#    define FD_REPORT_SIZE 4096*2
#  endif
#endif /* defined(FD_REPORT_SIZE) */

typedef struct {
  int    do_remote_tcpport:1;
} ff_same_session_opts_t;


typedef struct {
  server_rec *s;
  const char *file;
  int line;
} mod_log_debug_context_t;


static const char * ff_get_remote_ip (modff_config_t *conf, request_rec *r);

/*
static vfprintf_like_log_hook_t mod_vprintf_log;
*/
static int mod_vprintf_log (void *context, const char *fmt, va_list ap);
static mod_log_debug_context_t mod_log_debug_context;

static int me;		/* My pid (from getpid()) */
static int this_child_will_die = 0;
static int dirty_child = 0;

/*
 * Some switches to show if various flags were EVER turned on.
 *
 * Set by configuration, used by ff_child_cleanup()
 */

int ff_any_enabled = 0;
int ff_any_verbose = 0;
int ff_any_checkoverhead = 0;
int ff_any_extended = 0;

/* An initializer. Should NEVER be visible in logs, etc. */
static const modff_position_t ZED_position = MODFF_POS("ZED");


static modff_position_t  child_init_position = MODFF_POS("child");
static struct rusage     last_child_overhead;
static int               count_same_child_overhead = 0;

static modff_position_t  request_position  = MODFF_POS("request");
static modff_position_t  session_position  = MODFF_POS("session");
static modff_position_t  idle_position     = MODFF_POS("idle");
static modff_position_t  internal_position = MODFF_POS("internal");
static modff_position_t *last_position     = &internal_position;


#define DEF_TIMEFMT(_tfmt) ((_tfmt) ? (_tfmt) : "%c")

#if defined(__FreeBSD__)
#  define DEF_PROCPFX(_pfx) ((_pfx) ? (_pfx) : "/compat/linux/proc" )
#else
    /* Assume Linux.  How provincial. */
#  define DEF_PROCPFX(_pfx) ((_pfx) ? (_pfx) : "/proc" )
#endif
    


static ff_same_session_opts_t ff_same_session_opts (const modff_config_t *conf);

static int c_is_loopback (const conn_rec *c);
static int  r_is_internal (const request_rec *r);


/* Note: the result from this ff_get_session_cookie() is valid only for this request.
   It must be copied into more permanent storage for position management.
*/
static char *ff_get_session_cookie (request_rec *r, modff_config_t *conf);

static void ff_rdump (const char *file, int lnum, int level, apr_status_t status,
		      const request_rec *r, const ff_stat_t *ff, int verbose);

static void ff_sdump (const char *file, int lnum, int level, apr_status_t status,
		      const server_rec *s, const ff_stat_t *ff, int verbose);

/* Clear everything in 'pos' and reset to defaults (preserve tag) */
static int ff_reset_position (const char *by_func, modff_position_t *pos);

/* Move all data from 'src' to 'dest', then ff_reset_position(dest) */
static int ff_move_position (const char *by_func, modff_position_t *dest, modff_position_t *src);


static int ff_same_virtual_host (const modff_position_t *a, const modff_position_t *b,
			 char *buffer, size_t bufflen);

static int ff_same_session (const modff_position_t *a, modff_position_t *b,
			    char *buffer, size_t bufflen, const ff_same_session_opts_t opts,
			    int verbose);

static int ff_get_position (const char *by_func, modff_config_t *conf, modff_position_t *cur,
			    modff_position_t *last, server_rec *s, request_rec *r,
			    int overhead);

static int ff_regular_actions (modff_config_t *conf, request_rec *r, modff_position_t *cur);

static int ff_action (modff_config_t *conf, request_rec *r, modff_position_t *new_pos,
		      modff_position_t *to_pos, const ff_threshold_t *t_warn, 
		      const ff_threshold_t *t_exit,  int watch);

static void ff_rlog_overhead (const char *file, int lnum, int level, apr_status_t status,
			      const request_rec *r, modff_config_t *conf, 
			      const modff_position_t *pos, const char *fmt, ...) __attribute__((format(printf,8,9)));

static void ff_log_overhead (const char *file, int lnum, int level, apr_status_t status,
			     const server_rec *s, modff_config_t *conf, 
			     const modff_position_t *pos, const char *fmt, ...) __attribute__((format(printf,8,9)));

static char *postmortem_position (char *buffer, size_t bufflen, int pedantic);



/*
 * When we're doing log hooking
 */

static void *log_debug_hook_context = (void *) NULL;
static vfprintf_like_log_hook_t log_debug_hook_func = (vfprintf_like_log_hook_t) NULL;
static int log_debug_hook_level = 0;

static int
mod_log_debug_hook_register (void *context, vfprintf_like_log_hook_t logfunc, int level)
{
    __FUNC(mod_log_hook_register);

    log_debug_hook_context = context;
    log_debug_hook_func = logfunc;
    log_debug_hook_level = level;

    /* Pass it down another level. */
    ff_stat_log_debug_hook_register (context, logfunc, level);

    return (0);

} /* end of mod_log_debug_hook_register() */


int
ff_log_debug(int level, const char *fmt, ...)
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
} /* end of ff_log_debug() */




/* Sanity testing, etc. */
static int
mod_vprintf_log (void *context, const char *fmt, va_list ap)
{
    __FUNC(mod_vprintf_log);
    mod_log_debug_context_t *ctx = (mod_log_debug_context_t *) context;
    char bigbuf[4096];
    int ret = 0;
    
    if (context == (void *) NULL)
        return (0);

    if ((ctx->s == (server_rec *) NULL) || (ctx->file == (char *) NULL))
        return (0);

    bigbuf[0] = '\0';
    ret = vsnprintf (bigbuf, sizeof(bigbuf), fmt, ap);

    if (bigbuf[0])
    {
        ap_log_error (ctx->file, ctx->line, APLOG_DEBUG, 0, ctx->s,
		      "%s: Pid %d %s", ff_module.name, me, bigbuf);
    }

    return ret;
} /* end of mod_vprintf_log()  */



/*
 * Try do do this with minimal new memory overhead.
 */
static const char *
ff_get_remote_ip (modff_config_t *conf, request_rec *r)
{
    __FUNC(ff_get_remote_ip);
    tag_val_pair_t *sources = (tag_val_pair_t *) NULL;
    tag_val_pair_t *each_source;
    char *got;			/* Temp variable for 'apr_env_get()' */
    char *conn_rec_remote_ip = (char *) NULL;
    const char *pristine_table;

    /* Should never happen, but let's not core-dump here. */
    if ((conf == (modff_config_t *) NULL) || (r == (request_rec *) NULL))
        return ((char *) NULL);
    
    /* Easy to find. Make it so. */
    if (r->connection != (conn_rec*) NULL)
        conn_rec_remote_ip = r->connection->remote_ip;
    
    ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, 
		   "%s: %sPid %d %s() - Default conn_rec_remote_ip is [%s]",
		   ff_module.name, ff_labelid(conf), me, _func, 
		   conn_rec_remote_ip ? conn_rec_remote_ip : "(nil)");

    sources = ap_strlist_to_tag_val_pair (r->pool, conf->remote_ip_sources);

    /*
     * Default case of no configuration.
     */
    if (sources == (tag_val_pair_t *) NULL)
    {
        if (conn_rec_remote_ip != (char *) NULL)
	    return (conn_rec_remote_ip);

	return (MODFF_POS_NONE);
    }

    /* Populate our sources. */
    for (each_source = sources; each_source; each_source = each_source->next)
    {
        const char *tag = each_source->tag;

	ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
		       "%s: %sPid %d %s() - Examine source %s", 
		       ff_module.name, ff_labelid(conf), me, _func, tag);

	switch (*tag) {
	case '$':  /* Environment variable. */
	  got = (char *) NULL;
	  (void) apr_env_get (&got, tag+1, r->pool);
	  if (got)
	    each_source->val = got;

	  break;

	case '@':  /* Builtins */
	  if (strcasecmp (tag, "@remote_ip") == 0)
	    each_source->val = conn_rec_remote_ip;

	  break;

	case '+':  /* HTTP headers (like X-Forwarded-For) */
	case '-':
	  pristine_table = apr_table_get (r->headers_in, tag+1);
	  if (pristine_table != (char *) NULL)
	  {
	      const char *found_comma;
	      size_t len;

	      pristine_table = strtrim (pristine_table);

	      /* Prowl through the headers carefully, try not to allocate too much new data. */
	      if (*tag == '+')
	      {
		  /* Get first. */
		  if ((found_comma = strchr (pristine_table, ',')) == (char *) NULL)
		  {
		      /* Get new string buffer and remove trailing whitespace. */
		      each_source->val = strrtrim(apr_pstrdup (r->pool, pristine_table));
		  }
		  else
		  {
		      len = found_comma - pristine_table;
		      each_source->val = strrtrim(apr_pstrndup (r->pool, pristine_table, len-1));
		  }
	      }
	      else
	      {
		  /* Get last. */
		  if ((found_comma = strrchr (pristine_table, ',')) == (char *) NULL)
		  {
		      /* Get new string buffer and remove trailing whitespace. */
		      each_source->val = apr_pstrdup (r->pool, strtrim(pristine_table));
		  }
		  else
		  {
		      each_source->val = strrtrim(apr_pstrdup (r->pool, pristine_table));
		  }
	      }
	  }
	  else if ((r->server->loglevel >= APLOG_DEBUG) && DEBUG_SESSION(conf))
	  {
	      ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
			     "%s: %sPid %d - " FF_DIRECTIVE_PFX 
			     "RemoteIPSource header '%s' not found for %s '%s'",
			     ff_module.name, ff_labelid(conf), me, tag+1, 
			     r->method, r->unparsed_uri);
	  }
	  break;  /* '+' or '-' for HTTP headers. */

	default:
	  ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r,
			 "%s: %sPid %d Invalid " FF_DIRECTIVE_PFX
			 "RemoteIPSource, '%s' (ignored) for %s '%s'",
			 ff_module.name, ff_labelid(conf), me, tag,
			 r->method, r->unparsed_uri);
	  
	} /* switch (*(each_source->tag)) */
    }

    /*
     * And now find the first source with something.
     */
    
    for (each_source = sources; each_source; each_source = each_source->next)
    {
        ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
		       "%s: %sPid %d RemoteIPSource %s found [%s]",
		       ff_module.name, ff_labelid(conf), me, each_source->tag,
		       each_source->val ? each_source->val : "");

        if (each_source->val != (char *) NULL)
	{
	    if (DEBUG_SESSION(conf))
	    {
	        ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r,
			       "%s: %sPid %d - %s returns [%s] for %s '%s'",
			       ff_module.name, ff_labelid(conf), me,
			       each_source->tag, each_source->val,
			       r->method, r->unparsed_uri);
	    }
	    return (each_source->val);
	}
    }

    ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
		   "%s: %sPid %d %s() - Returning default conn_rec_remote_ip [%s]",
		   ff_module.name, ff_labelid(conf), me, _func, 
		   conn_rec_remote_ip ? conn_rec_remote_ip : "(default)");

    /* Return remote IP after all (if we have it.). */
    if (!conn_rec_remote_ip)
      return (MODFF_POS_NONE);

    return (conn_rec_remote_ip);

} /* Return an ip address string. */



/*
 * Return cookie named by the 'SessionCookieName' directive.
 */
static char *
ff_get_session_cookie (request_rec *r, modff_config_t *conf)
{
    __FUNC(ff_get_session_cookie);
    const char *dont_touch_cookies;
    char *cookies;
    char *pair;    /* candidate <cookiename> "=" <value> pair */
    char *this_cookie;
    char *milk;   /* The cookie value returned -- in a metaphor mangling way. */
    char *pos = (char *) NULL;	/* strtok_r() position for scanning cookies string */


    if ((r == (request_rec *) NULL) || (conf == (modff_config_t *) NULL))
        return ((char *) NULL);

    /* If we haven't configured a cookie name - or have unconfigured a cookie name, give up */
    if ((conf->session_cookie_name == FF_UNSET) || ( *(conf->session_cookie_name) == '\0'))
      return ((char *) NULL);

    /* Look for cookies, first in any cookies set by the application (most likely)
       then by any incoming cookies (which are may be a security issue if we're
       killing off sessions) since the cookies are under the control of the end-user.
    */
    if ((dont_touch_cookies = apr_table_get (r->headers_out, "Set-Cookie")) == (char *) NULL)
        dont_touch_cookies = apr_table_get (r->headers_in, "Cookie");

    if (dont_touch_cookies == (char *) NULL)
        return ((char *) NULL);

    /*
     * Make a copy of the cookies, with our fantabulous ditto machine
     *
     * We work on the copy rather than the original so we won't crumble
     * any cookies...
     */
    cookies = apr_pstrdup (r->pool, dont_touch_cookies);

    /* Now use conventional 'strtok_r()' calls to scan our cookies string for what we want. */
    for (pair = strtok_r (cookies, ";", &pos); pair; pair = strtok_r ((char *) NULL, ";", &pos))
    {
        char *kv = (char *) NULL;
	
	this_cookie = strtok_r (pair, "=", &kv);
	if (this_cookie && (strcmp(this_cookie, conf->session_cookie_name) == 0))
	{
	    /*  Return the cookie value (btw: it was allocated from the request pool) */
	    milk = strtok_r ((char *) NULL, "", &kv);  /* "" used to match rest of string */
	    if (milk)
	    {
		ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
			       "%s: %sPid %d Cookie '%s' value found \"%s\" for %s '%s'",
			       ff_module.name, ff_labelid(conf), me, conf->session_cookie_name,
			       milk ? milk : "(nil-cookie)", r->method, r->unparsed_uri);
	    }
	    return (milk);
	}
    }

    /* No cookie. No milk. */
    ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
		   "%s: %sPid %d Cookie '%s' not found for %s '%s'",
		   ff_module.name, ff_labelid(conf), me, conf->session_cookie_name,
		   r->method, r->unparsed_uri);

    return ((char *) NULL);

} /* end of ff_get_session_cookie() */



/*
 * Return a -2 if no server.
 * Return a -1 if no list of addresses (for port#s)
 * report a port#  (less that USHRT_MAX ie. 65535) if all port#s are same
 * returns a hash of port#s (> USHRT_MAX) if port#s change from first.
 */
int
ff_ap_server_porthash (const server_rec *s)
{
    int port = 0;
    int port_hash = 0;
    server_addr_rec *each;

    if (s == (server_rec *) NULL)
    {
        return (-2);
    }

    /* If there's no address list, complain. */
    if (s->addrs == (server_addr_rec *) NULL)
    {
        return (-1);
    }

    for (each = s->addrs; each != (server_addr_rec *) NULL; each = each->next)
    {
        if (port == 0)
	{
	    port = each->host_port;
	}
	else if (port != each->host_port)
	{
	    if (port_hash == 0)
	    {
	        port_hash = port;
	    }
	    port_hash = (port_hash * each->host_port) % (USHRT_MAX + 1);
	}
    }

    if (port_hash != 0)
    {
        return (port_hash + USHRT_MAX + 1);
    }
    
    return (port);

} /* end of ff_ap_server_porthash(s) */


static ff_same_session_opts_t
ff_same_session_opts (const modff_config_t *conf)
{
    ff_same_session_opts_t res = {0};

    if (conf != (modff_config_t *) NULL)
    {
        res.do_remote_tcpport = ENABLED(conf,do_remote_tcpport);
    }

    return res;
} /* end of ff_same_session_opts() */



char *
ff_ap_server_name (char *buffer, size_t bufflen, const server_rec *s)
{
    if (!buffer || (bufflen < 10))
    {
        return "*unknown*";
    }

    *buffer = '\0';

    if (s == (server_rec *) NULL)
    {
        snprintf (buffer, bufflen, "(nil)");
    }
    else
    {
        int port = ff_ap_server_porthash (s);

	if (port == 0)
	{
	    snprintf (buffer, bufflen, "'%s':?", SERVER_HOSTNAME(s));
	}
	else
	{
	    snprintf (buffer, bufflen, "'%s':%d", SERVER_HOSTNAME(s), port);
	}
    }

    return (buffer);

} /* end of ff_ap_server_name() */


static char *ap_family_name (char *buffer, size_t bufflen, int family);
static char *
ap_family_name(char *buffer, size_t bufflen, int family)
{
    switch (family) {
    case APR_UNSPEC:
        return "none";

    case APR_INET:
        return "IPv4";

    case APR_INET6:
        return "IPv6";

    case -1:
        return "unknown";

    default:
        if (buffer)
	{
	    *buffer = '\0';
	    snprintf (buffer, bufflen, "encaps(%d)", family);

	    return buffer;
	}
    }
    
    /* Fall through. */
    return "?";

} /* end of ap_family_name() /*/



char *
position_toa (char *buffer, size_t bufflen, const modff_position_t *pos, int verbose)
{
    char *str;	/* 'cause our usual use of 'pos' is subsumed by the parameter. */
    char fn[32];
    int  len;

    if (buffer)
        *buffer = '\0';

    if (! buffer || (bufflen < 10))
        return buffer;

    str = buffer;
    if (pos == (modff_position_t *) NULL)
    {
        strncpy (buffer, "*lost*", bufflen);

	return (buffer);
    }

    snprintf (str, bufflen, "<%s>", POSITION_TAG(pos));

    if (verbose)
    {
        len = strlen (str);
	str += len;
	bufflen -= len;
	
	(void) ff_ap_server_name (str, bufflen, pos->s);

	len = strlen (str);
	str += len;
	bufflen -= len;

	if ((pos->conn_remote_ip != (char *) NULL) && ( *(pos->conn_remote_ip) != '\0') &&
	    (strcmp(pos->conn_remote_ip, _NULL_HOSTNAME) != 0))
	{
	    snprintf (str, bufflen, "#%s#[%s]:%d", ap_family_name (fn, sizeof(fn), pos->conn_family),
		      pos->conn_remote_ip,  pos->conn_remote_port);
	}
    }

    return (buffer);

}  /* end of position_toa() */



static modff_position_t *next_expected_position (void *p_context);
static modff_position_t *
next_expected_position (void *p_context)
{
    modff_position_t  *pos;
    modff_position_t **p_pos_context = (modff_position_t **) p_context;

    static modff_position_t *positions[] =
      {
	&child_init_position,
	&request_position,
	&idle_position,
	&internal_position,
	&session_position,

	/* END of LIST */

	(modff_position_t *) NULL
      };

    if (p_pos_context == (modff_position_t **) NULL)
        return ((modff_position_t *) NULL);

    if (*p_pos_context == (modff_position_t *) NULL)
    {
        p_pos_context = &(positions[0]);
    }
    pos = *p_pos_context;

    p_pos_context++;

    return (pos);
    
} /* end of next_expected_position() */



static ff_stat_t * position_next_expected_ff_stat (void *p_context);
static ff_stat_t *
position_next_expected_ff_stat (void *p_context)
{
    modff_position_t *pos;

    pos = next_expected_position (p_context);

    if (pos)
      return ( &(pos->ff) );

    return ((ff_stat_t *) NULL);

} /* end of position_next_expected_ff_stat() */



static char *
postmortem_position (char *buffer, size_t bufflen, int pedantic)
{
    return postmortem_ff_stat (buffer, bufflen, position_next_expected_ff_stat,
			       count_ff_stat, pedantic);
} /* end of postmortem_position() */



/*
 * Return a label string.
 *
 * Not thread safe.
 */

const char *
ff_labelid (modff_config_t *conf)
{
#define LABELID_BUFF_SIZE 64
#define LABELID_BUFF_COUNT 6

    static unsigned short n = 0;
    static char temp_buffers[LABELID_BUFF_COUNT][LABELID_BUFF_SIZE];
    char *temp = temp_buffers[n];

    if (conf == (modff_config_t *) NULL)
        return "brainless";

    if ((conf->labelid == (char *) NULL) || (*(conf->labelid) == '\0'))
        return "";

    n = (n + 1) % LABELID_BUFF_COUNT;
    if (ENABLED(conf,debug_config))
    {
        snprintf (temp, LABELID_BUFF_SIZE, "#%d#%s.", conf->id, conf->labelid);
    }
    else
    {
        snprintf (temp, LABELID_BUFF_SIZE, "%s.", conf->labelid);
    }
    
    return temp;
} /* end of ff_labelid() */


/*
 * Determine the composite 'overhead' value (0, 1, or 2) 
 */
int
ff_overhead_any (const modff_config_t *conf)
{
    int overhead = 0;

#define DO_OVERHEAD(_field) { int tmp = FLAGVAL(conf,_field); overhead = _MAX(overhead,tmp); }

    DO_OVERHEAD(overhead_request);
    DO_OVERHEAD(overhead_child);
    DO_OVERHEAD(overhead_session);
    DO_OVERHEAD(overhead_idle);
    DO_OVERHEAD(overhead_internal);

    return overhead;

} /* end of int ff_overhead_any() */



/*
 * Determine whether we're being used by a loopback interface.
 * (The loopback interface is used for 'internal' requests.)
 */
static int
c_is_loopback (const conn_rec *c)
{
    char *rem_ip;

    if (c == (conn_rec *) NULL)
    {
        return (0); /* false */
    }

    if (c->remote_ip == (char *) NULL)
    {
        return (0); /* false */
    }

    rem_ip = c->remote_ip;

    if ((strcasecmp (rem_ip, "localhost") == 0) || (strcmp (rem_ip, "127.0.0.1") == 0) ||
	(strcmp (rem_ip, "::1") == 0) )
    {
        return (1);  /* Generic loopback address. */
    }

    return (0); /* Not loopback. */

} /* end of c_is_loopback (conn_rec *c) */


/*
 * Determine if it is an internal request or not.
 *
 * Returns: 
 *   -1 : Not a request
 *   -2 : Unable to determine
 *   -3 : No connection
 *   -4 : No remote address
 *    1 : Is internal 
 *    0 : An actual external request.
 */
static int
r_is_internal (const request_rec *r)
{
    __FUNC(r_is_internal);
    const conn_rec *c;
    const apr_sockaddr_t *ra;
    int port;

    if (r == (request_rec *) NULL)
        return (-1);

    if (r->server == (server_rec *) NULL)
        return (-2);
      
    port = ff_ap_server_porthash (r->server);
    if (port < 0)
        return (-5);

    /* Sneaky - internal requests depend on virtual servers without address lists. */
    if (port == 0)
        return (1);

    if ((c = r->connection) == (conn_rec *) NULL)
        return (-3);
    
    if ((ra = c->remote_addr) == (apr_sockaddr_t *) NULL)
        return (-4);

    /* No real address family! */
    if (ra->family == APR_UNSPEC)
        return (1);

    /* Assume it's a regular request. */

    return (0);

} /* end of r_is_internal (request_rec *r) */



void
ff_sreport (const char *file, int lnum, int level, apr_status_t status,
	    const server_rec *s, const ff_stat_t *ff, const char *timefmt,
	    int verbose, int dump, const char *fmt, ...)
{
    char v_buffer[REPORT_BUFFLEN_LONG];
    char ff_buffer[REPORT_BUFFLEN];
    va_list ap;

    v_buffer[0] = '\0';
    
    va_start(ap, fmt);
    if ((fmt != (char *) NULL) && (*fmt && (fmt[0] != '*') && fmt[1] != '\0'))
    {
        vsnprintf (v_buffer, sizeof(v_buffer), fmt, ap);
    }
    va_end(ap);

    ff_buffer[0] = '\0';
    if (ff != (ff_stat_t *) NULL)
    {
        (void) ff_stat_toa (ff_buffer, sizeof(ff_buffer), ff, timefmt, ", ", verbose);
    }

    ap_log_error (file, lnum, level, status, s, "%s %s", v_buffer, ff_buffer);

    if (dump)
        ff_sdump (file, lnum, level, status, s, ff, verbose);

    return;

} /* end of ff_sreport() */


static void 
ff_rdump (const char *file, int lnum, int level, apr_status_t status,
	  const request_rec *r, const ff_stat_t *ff,
	  int verbose)
{
    iterate_proc_fd_info_list_t iter;	/* Debugging */
    proc_fd_info_t *pfi;		/* Debugging */
    unsigned int count = 0;
    char buffer[4096];
    char *str;

    if (ff == (ff_stat_t *) NULL)
        return;

    begin_iterate__proc_fd_info_list (&iter, ff->fds_info);
    for (pfi = next_iterate__proc_fd_info_list (&iter);
	 pfi;
	 pfi = next_iterate__proc_fd_info_list (&iter))
    {
        count ++;
	
	buffer[0]= '\0';
	str = proc_fd_info_toa (buffer, sizeof(buffer), pfi,
				verbose);

	ap_log_rerror (file, lnum, level, status, r, "%u: %s",
		       count, str ? str : "(nothing)");
    }

    return;

} /* end of ff_rdump() */


static void 
ff_sdump (const char *file, int lnum, int level, apr_status_t status,
	  const server_rec *s, const ff_stat_t *ff,
	  int verbose)
{
    iterate_proc_fd_info_list_t iter;	/* Debugging */
    proc_fd_info_t *pfi;		/* Debugging */
    unsigned int count = 0;
    char buffer[4096];
    char *str;

    if (ff == (ff_stat_t *) NULL)
        return;

    begin_iterate__proc_fd_info_list (&iter, ff->fds_info);
    for (pfi = next_iterate__proc_fd_info_list (&iter);
	 pfi;
	 pfi = next_iterate__proc_fd_info_list (&iter))
    {
        count ++;
	
	buffer[0]= '\0';
	str = proc_fd_info_toa (buffer, sizeof(buffer), pfi,
				verbose);

	ap_log_error (file, lnum, level, status, s, "%u: %s",
		      count, str ? str : "(nothing)");
    }

    return;

} /* end of ff_sdump() */


void
ff_rlog_overhead (const char *file, int lnum, int level, apr_status_t status,
		  const request_rec *r, modff_config_t *conf, const modff_position_t *pos,
		  const char *fmt, ...)
{
    char v_buffer[REPORT_BUFFLEN_LONG];
    char overhead_msg[REPORT_BUFFLEN];
    char pos_buff[1024];
    char *t_pos;
    size_t t_len;
    va_list ap;

    va_start(ap, fmt);

    v_buffer[0] = '\0';
    overhead_msg[0] = '\0';

    if ((fmt != (char *) NULL) && (*fmt && (fmt[0] != '*') && fmt[1] != '\0'))
    {
        vsnprintf (v_buffer, sizeof(v_buffer), fmt, ap);
    }
    va_end(ap);

    rusage_toa (overhead_msg, sizeof(overhead_msg), &(pos->overhead), ", ",
		ENABLED(conf,verbose));

    t_len = strlen (overhead_msg);
    t_pos = overhead_msg + t_len;

    if (overhead_msg[0])
    {
        strcat (t_pos, ", ");
	t_len += 2;
	t_pos += 2;
    }

    (void) proc_statm_info_toa (t_pos, sizeof(overhead_msg) - t_len, &(pos->ff.statm), ", ", ENABLED(conf,verbose));

    if (overhead_msg[0])
    {
        ap_log_rerror (file, lnum, level, status, r, "%s: %sPid %d Overhead %s %s %s by %s '%s'",
		       ff_module.name, ff_labelid(conf), me, 
		       position_toa(pos_buff, sizeof(pos_buff), pos, DEBUG_POSITION(conf)),
		       overhead_msg, v_buffer, r->method, r->unparsed_uri);
    }

    return; /* out of the kindness of our professional coding hearts */

} /* end of ff_rlog_overhead()  */    


void
ff_log_overhead (const char *file, int lnum, int level, apr_status_t status,
		 const server_rec *s, modff_config_t *conf, const modff_position_t *pos,
		 const char *fmt, ...)
{
    char v_buffer[REPORT_BUFFLEN_LONG];
    char overhead_msg[REPORT_BUFFLEN];
    char pos_buff[1024];
    char *t_pos;
    size_t t_len;
    va_list ap;

    va_start(ap, fmt);

    v_buffer[0] = '\0';
    overhead_msg[0] = '\0';

    if ((fmt != (char *) NULL) && (*fmt && (fmt[0] != '*') && fmt[1] != '\0'))
    {
        vsnprintf (v_buffer, sizeof(v_buffer), fmt, ap);
    }
    va_end(ap);

    rusage_toa (overhead_msg, sizeof(overhead_msg), &(pos->overhead), ", ",
		ENABLED(conf,verbose));

    t_len = strlen (overhead_msg);
    t_pos = overhead_msg + t_len;

    if (overhead_msg[0])
    {
        strcat (t_pos, ", ");
	t_len += 2;
	t_pos += 2;
    }

    (void) proc_statm_info_toa (t_pos, sizeof(overhead_msg) - t_len, &(pos->ff.statm), ", ", ENABLED(conf,verbose));

    if (overhead_msg[0])
    {
        ap_log_error (file, lnum, level, status, s, "%s: %sPid %d Overhead %s %s %s",
		      ff_module.name, ff_labelid(conf), me, 
		      position_toa(pos_buff, sizeof(pos_buff), pos, DEBUG_POSITION(conf)),
		      overhead_msg, v_buffer);
    }

    return; /* out of the kindness of our professional coding hearts */

} /* end of ff_log_overhead()  */    



void
ff_rreport (const char *file, int lnum, int level, apr_status_t status,
	    const request_rec *r, const ff_stat_t *ff, const char *timefmt,
	    int verbose, int dump, const char *fmt, ...)
{
    char v_buffer[REPORT_BUFFLEN_LONG];
    char ff_buffer[REPORT_BUFFLEN];
    va_list ap;

    v_buffer[0] = '\0';
    
    va_start(ap, fmt);
    if ((fmt != (char *) NULL) && (*fmt && (fmt[0] != '*') && fmt[1] != '\0'))
    {
        vsnprintf (v_buffer, sizeof(v_buffer), fmt, ap);
    }
    va_end(ap);

    ff_buffer[0] = '\0';
    if (ff != (ff_stat_t *) NULL)
    {
        (void) ff_stat_toa(ff_buffer, sizeof(ff_buffer), ff, timefmt, ", ", verbose);
    }

    ap_log_rerror (file, lnum, level, status, r, "%s %s", v_buffer, ff_buffer);

    if (dump)
        ff_rdump (file, lnum, level, status, r, ff, verbose);

    return;

} /* end of ff_rreport() */



void
ff_swatch (const char *file, int lnum, int level, apr_status_t status,
	    const server_rec *s, const ff_stat_t *ff, const char *timefmt,
	    int verbose, const char *fmt, ...)
{
    char v_buffer[REPORT_BUFFLEN_LONG];
    char ff_buffer[REPORT_BUFFLEN];
    va_list ap;

    v_buffer[0] = '\0';
    
    va_start(ap, fmt);
    if ((fmt != (char *) NULL) && (*fmt && (fmt[0] != '*') && fmt[1] != '\0'))
    {
        vsnprintf (v_buffer, sizeof(v_buffer), fmt, ap);
    }
    va_end(ap);

    ff_buffer[0] = '\0';
    if (ff != (ff_stat_t *) NULL)
    {
        (void) ff_stat_toa(ff_buffer, sizeof(ff_buffer), ff, timefmt, ", ", verbose);
    }

    if ( ff_buffer[0] != '\0' )
    {
	ap_log_error (file, lnum, level, status, s, "%s %s", v_buffer, ff_buffer);
    }
    ff_sdump (file, lnum, level, status, s, ff, verbose);

    return;

} /* end of ff_swatch() */


void
ff_rwatch (const char *file, int lnum, int level, apr_status_t status,
	    const request_rec *r, const ff_stat_t *ff, const char *timefmt,
	    int verbose, const char *fmt, ...)
{
    char v_buffer[REPORT_BUFFLEN_LONG];
    char ff_buffer[REPORT_BUFFLEN];
    va_list ap;

    v_buffer[0] = '\0';
    
    va_start(ap, fmt);
    if ((fmt != (char *) NULL) && (*fmt && (fmt[0] != '*') && fmt[1] != '\0'))
    {
        vsnprintf (v_buffer, sizeof(v_buffer), fmt, ap);
    }
    va_end(ap);

    ff_buffer[0] = '\0';
    if (ff != (ff_stat_t *) NULL)
    {
        (void) ff_stat_toa(ff_buffer, sizeof(ff_buffer), ff, timefmt, ", ", verbose);
    }

    if (ff_buffer[0] != '\0' )
    {
        ap_log_rerror (file, lnum, level, status, r, "%s %s", v_buffer, ff_buffer);
    }
    ff_rdump (file, lnum, level, status, r, ff, verbose);

    return;

} /* end of ff_rwatch() */


static int
ff_reset_position (const char *by_func, modff_position_t *pos)
{
    __FUNC(ff_reset_position);
    const char *old_tag;
    char pos_buff[1024];

    if (pos == (modff_position_t *) NULL)
        return (-1);

    ff_log_debug (1, "Resetting %s by %s()",
	       position_toa(pos_buff, sizeof(pos_buff), pos, 1),
	       by_func);

    old_tag = pos->tag;
    reset_ff_stat (&(pos->ff));
    
    if (pos->session_cookie)
        free (pos->session_cookie);

    memcpy ((void *) pos, (void *) &ZED_position, sizeof(modff_position_t));
    pos->tag = old_tag;

    pos->conn_remote_ip = MODFF_POS_NONE;

    return (0);

} /* end of ff_reset_position() */




static int
ff_move_position (const char *by_func, modff_position_t *dest, modff_position_t *src)
{
    const char *src_tag;
    const char *dest_tag;
    char pos_src[1024];
    char pos_dest[1024];

    if ((dest == (modff_position_t *) NULL) || (src == (modff_position_t *) NULL))
        return (-1);

    if (dest == src)
        return (1);

    src_tag = src->tag;
    dest_tag = dest->tag;
    pos_src[0] = '\0';
    pos_dest[0] = '\0';
    ff_log_debug(1, "Move %s to %s by %s()", position_toa (pos_src, sizeof(pos_src), src, 1),
	      position_toa (pos_dest, sizeof(pos_dest), dest, 1), by_func);
						

    /* Clear destination before move. */
    ff_reset_position (by_func, dest);

    memcpy ((void *)dest, (void *)src, sizeof (modff_position_t));
    memcpy ((void *)src, (void *) &ZED_position, sizeof(modff_position_t));
    dest->tag = dest_tag;
    src->tag = src_tag;

    ff_reset_position (by_func, src);

    ff_log_debug (1, "Move to %s done by %s()",
	       position_toa (pos_dest, sizeof(pos_dest), dest, 1),
	       by_func);

    return (0);

} /* ff_move_position() */



int
ff_copy_position (const char *by_func, modff_position_t *dest, modff_position_t *src)
{
    const char *tag;
    char pos_dest[1024];
    char pos_src[1024];


    if ((dest == (modff_position_t *) NULL) || (src == (modff_position_t *) NULL))
        return (-1);

    if (dest == src)
        return (1);

    pos_src[0] = '\0';
    pos_dest[0] = '\0';
    ff_log_debug(1, "Copy %s to %s by %s()", position_toa (pos_src, sizeof(pos_src), src, 1),
	      position_toa (pos_dest, sizeof(pos_dest), dest, 1), by_func);
						

    /* Preserve destination tag name */
    tag = dest->tag;

    /* Clear destination before move. */
    ff_reset_position (by_func, dest);

    memcpy ((void *) dest, (void *) src, sizeof(modff_position_t));

    memset ((void *) &(dest->ff), 0, sizeof (ff_stat_t));
    copy_ff_stat (&(dest->ff), &(src->ff));

    /* Copy the session cookie too. */
    if (src->session_cookie)
      dest->session_cookie = strdup (src->session_cookie);

    dest->tag = tag;

    ff_log_debug (1, "Copy to %s done by %s()",
	       position_toa (pos_dest, sizeof(pos_dest), dest, 1), by_func);

    return (0);
} /* ff_copy_position() */

/*
 * Check to see if the two positions represent the same virtual host
 */

static int
ff_same_virtual_host (const modff_position_t *a, const modff_position_t *b,
	      char *buffer, size_t bufflen)
{
    __FUNC(ff_same_virtual_host);
    char pos_a_buff[256];
    char pos_b_buff[256];


    if ((a == (modff_position_t *) NULL) || (b == (modff_position_t *) NULL))
    {
        if (buffer && (bufflen > 0))
	{
	    snprintf(buffer, bufflen, "%s: NULL a=%p, b=%p", _func, a, b);
	}
        return (-1);
    }

    /* degenerate case. */
    if (a == b)
        return (0);

    /* Different server (virtual host?) */
    if ((a->s == (server_rec *) NULL) || (b->s == (server_rec *) NULL))
    {
        if (buffer && (bufflen > 0))
	{				
	    snprintf (buffer, bufflen, "%s: (server_rec *) NULL %s or %s",
		      _func, 
		      position_toa(pos_a_buff, sizeof(pos_a_buff), a, /* verbose=false */ 0),
		      position_toa(pos_b_buff, sizeof(pos_b_buff), b, /* verbose=false */ 0));
	}
        return (-1);
    }

    /* If the virtual servers are identical, then we're cool */
    if (a->s == b->s)
    {
        return (0);
    }

    if ((a->s->server_hostname == (char *) NULL) ||
	(b->s->server_hostname == (char *) NULL))
    {
        if (buffer && (bufflen > 0))
	{				
	    snprintf (buffer, bufflen, "%s: server_hostname(s) NULL %s or %s",
		      _func, 
		      position_toa(pos_a_buff, sizeof(pos_a_buff), a, /* verbose=false */ 0),
		      position_toa(pos_b_buff, sizeof(pos_b_buff), b, /* verbose=false */ 0));
	}

        return (-1);
    }

    /* If the server NAMES are identical, then we're OK too. 
       (ignoring network transport issues like IPv4 vs. IPv4 & TCP port #)
    */

    if (a->s->server_hostname == b->s->server_hostname)
    {
        return (0);
    }


    if (strcasecmp(a->s->server_hostname, b->s->server_hostname) == 0)
    {
	return (0);
    }


    return (1);
    
} /* end of ff_same_virtual_host () */

/*
 * Check to see if the two positions represent the same session.
 *
 * Like 'cmp' functions, 0 is the same, non-zero is not the same. 
 * (incidentally, a -1 return value indicates a missing value.)
 */
static int
ff_same_session (const modff_position_t *a, modff_position_t *b, char *buffer,
		 size_t bufflen, ff_same_session_opts_t opts, int verbose)
{
    __FUNC(ff_same_session);
    char pos_a_buff[256];
    char pos_b_buff[256];


    if ((a == (modff_position_t *) NULL) || (b == (modff_position_t *) NULL))
    {
        if (buffer && (bufflen > 0))
	{
	    snprintf(buffer, bufflen, "%s: NULL a=%p, b=%p", _func, a, b);
	}
        return (-1);
    }

    /* degenerate case. */
    if (a == b)
        return (0);

    /* Different server (virtual host?) */
    if ((a->s == (server_rec *) NULL) || (b->s == (server_rec *) NULL))
    {
        if (buffer && (bufflen > 0))
	{				
	    snprintf (buffer, bufflen, "%s: (server_rec *) NULL %s or %s",
		      _func, 
		      position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
		      position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));
	}
        return (-1);
    }

    /* This should take care of local port (http/https) too. */
    if (a->s != b->s)
    {
        if (buffer && (bufflen > 0))
	{
	    snprintf(buffer, bufflen, "%s: server_hostname %s != %s",
		     _func,
		     position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
		     position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));
	}
        return (1);
    }

    if (a->conn_family != b->conn_family)
    {
        if (buffer && (bufflen > 0))
	{
	    snprintf (buffer, bufflen, "%s: conn_family (%s != %s) for %s and %s",
		      _func, ap_family_name((char *) NULL, 0, a->conn_family),
		      ap_family_name((char *) NULL, 0, b->conn_family),
		      position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
		      position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));
	}
        return (1);
    }

    if (opts.do_remote_tcpport)
    {
        if (a->conn_remote_port != b->conn_remote_port)
	{
	    if (buffer && (bufflen > 0))
	    {
	        snprintf (buffer, bufflen,
			  "%s: conn_remote_port (%d != %d) for %s and %s",
			  _func,  a->conn_remote_port, b->conn_remote_port,
			  position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
			  position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));
	    }
	    return (1);
	}
    }
 
    if ((a->conn_remote_ip == (char *) NULL) || (b->conn_remote_ip == (char *) NULL))
    {
        if (buffer && (bufflen > 0))
	{
	    snprintf (buffer, bufflen,
		      "%s: NULL conn_remote_ip %p, %p for %s and %s", _func,
		      a->conn_remote_ip, b->conn_remote_ip,
		      position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
		      position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));
	}
        return (-1);
    }

    /*
     * Even if we want to decide by session cookies, we can't if there are
     * no session cookies, so do this test first.
     */
    if ((a->session_cookie != (char *) NULL) || (b->session_cookie != (char *) NULL))
    {
	/* Only check if we have a session cookie names to inform us. */
	if (a->session_cookie_name && ( *(a->session_cookie_name) != '\0') &&
	    b->session_cookie_name && ( *(b->session_cookie_name) != '\0') &&
	    strcmp (a->session_cookie_name, b->session_cookie_name) == 0)
	{
	    /* Now check the session cookie VALUES */
	    if (strcmp (a->session_cookie, b->session_cookie) != 0)
	    {
		if (buffer && (bufflen > 0))
		{
		    snprintf (buffer, bufflen, 
			      "%s: cookie('%s') (\"%s\" != \"%s\") for %s and %s",
			      _func, a->session_cookie_name, a->session_cookie,
			      b->session_cookie, 
			      position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
			      position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));
		}

		return (1);
	    }
	}
    }

    if (strcmp (a->conn_remote_ip, b->conn_remote_ip) == 0)
    {
        return (0);
    }

    /* They're different after all. */
    if (buffer && (bufflen > 0))
    {
        snprintf (buffer, bufflen, "%s: conn_remote_ip ([%s] !=  [%s]), for %s and %s",
		  _func, NULL_HOSTNAME(a->conn_remote_ip), NULL_HOSTNAME(b->conn_remote_ip),
		  position_toa(pos_a_buff, sizeof(pos_a_buff), a, verbose),
		  position_toa(pos_b_buff, sizeof(pos_b_buff), b, verbose));

    }

    return (1);

} /* end of ff_same_session(modff_position_t *a, modff_position_t *b, char *buffer, size_t bufflen, int verbose) */


static int
ff_get_position (const char *by_func, modff_config_t  *conf, modff_position_t *cur,
		 modff_position_t *last, server_rec *s, request_rec *r, int overhead)
{
    __FUNC(ff_get_position);
    conn_rec *c = (conn_rec *) NULL;
    char     *tmp;  /* For session cookie allocation */
    int       rc;


    if (s == (server_rec *) NULL)
    {
        if (r != (request_rec *) NULL)
	{
	    s = r->server;
	}
    }
    cur->s = s;		/* Update the current position. */

    /* Harvest the server from the request if the server is missing. */
    if (r != (request_rec *) NULL)
    {
        c = r->connection;
    }

    /* If there's a connection associated with this, record it. Otherwise, disconnect... */
    if (c != (conn_rec *) NULL)
    {
        cur->conn_remote_ip = ff_get_remote_ip(conf, r);
	if (c->remote_addr != (apr_sockaddr_t *) NULL)
	{
	    cur->conn_family = c->remote_addr->family;
	    cur->conn_remote_port = c->remote_addr->port;
	}
	else
	{
	    ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r,
			   "%s: %sPid %d %s() from %s() - connection without remote_addr!",
			   ff_module.name, ff_labelid (conf), me, _func, by_func);

	    cur->conn_family = -1;
	    cur->conn_remote_port = -1;
	}
    }
    else
    {
        cur->conn_remote_ip = MODFF_POS_NONE;
	cur->conn_family = -1;
	cur->conn_remote_port = -1;
    }

    /*
     * Do session cookie stuff.
     */
    cur->session_cookie_name = conf->session_cookie_name;
    tmp = ff_get_session_cookie (r, conf);
    if (tmp)
        cur->session_cookie = strdup(tmp);


    rc = get_ff_stat (DEF_PROCPFX(conf->pfx), &(cur->ff), overhead, ENABLED(conf,extended));
    if (rc != 0)
    {
        ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r,
		       "%s: %sPid %d %s() from %s() - get_ff_stat('%s') failed for <%s>", 
		       ff_module.name, ff_labelid(conf), me, _func, by_func, DEF_PROCPFX(conf->pfx),
		       POSITION_TAG(cur));

        conf->enabled = FF_DISABLE;
	cleanup_ff_stat();

	cur->ff_valid = 0;		/* Force ff to be marked invalid. */

	return (-1);			/* Error return */
    }

    if (last != (modff_position_t *) NULL)
    {
        char msg[1024];
	char *p_msg = (char *) NULL;

	if (DEBUG_SESSION(conf))
	{
	    p_msg = msg;
	}
	msg[0] = '\0';

        if (ff_same_session (cur, last, p_msg, sizeof(msg), 
			     ff_same_session_opts(conf), DEBUG_SESSION(conf)) == 0)
	{
	    cur->session_count = last->session_count;
	}
	else
	{
	    if (msg[0] != '\0')
	    {
		ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r,
	       "%s: %sPid %d %s() from %s() - <%s> session changed after %d hits because %s",
			       ff_module.name, ff_labelid(conf), me, _func, by_func,
			       POSITION_TAG(last), last->session_count, msg);
	    }

	    cur->session_count = 0;
	}
    }

    cur->ff_valid = 1;
    cur->session_count ++;

    /* Check for failure to collect fd information */
    if (ENABLED(conf,extended) && (cur->ff.fds_info == (proc_fd_info_list_t *) NULL))
    {
        ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r,
	      "%s: %sPid %d %s() from %s() - extended file descriptor information requested, but not available for <%s>",
		       ff_module.name, ff_labelid (conf), me, _func, by_func, 
		       POSITION_TAG(cur));
    }

    /* Be clean. Be neat. */
    if (ENABLED(conf,cleanup))
    {
        cleanup_ff_stat ();
    }

    return (0);  /* Success */

} /* end of ff_get_position() */


/*
 * Function to call when a child terminates.
 */
static apr_status_t ff_child_cleanup (void *data);
static apr_status_t
ff_child_cleanup (void *data)
{
    __FUNC(ff_child_cleanup);
    int overhead = 0;
    int enabled = 0;
    int extended = 0;
    int verbose = 0;
    int verbose_postmortem = 0;
    server_rec *s = (server_rec *) data;
    int count;
    char *msg;
    ff_stat_t diff;

    modff_config_t *child_conf = (modff_config_t *) NULL;
    int overhead_child = 0;
    int watchchild = 0;

    modff_config_t *idle_conf = (modff_config_t *) NULL;
    int overhead_idle = 0;
    int watchidle = 0;

    modff_config_t *internal_conf = (modff_config_t *) NULL;
    int overhead_internal = 0;
    int watchinternal = 0;

    modff_config_t *session_conf = (modff_config_t *) NULL;
    int overhead_session = 0;
    int watchsession = 0;


    char report[REPORT_BUFFLEN_LONG];
    char _fd_report[FD_REPORT_SIZE];   /* Big, fixed sized temp buffer. */
    char *fd_report;

    strcpy (_fd_report, "begining");
    strcpy (report, "starting");

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, s, "%s: Pid %d - %s() dirty_child=%d",
		  ff_module.name, me, _func, dirty_child);

    if (dirty_child == 0)
    {
        return (APR_SUCCESS);
    }

    dirty_child = 0;

    /* 
     * Gather configuration information.
     */
#define _CONF_FLAG_ENABLED(_cnf,_flag)	_flag = _flag || ENABLED(_cnf,_flag)

#define _GET_CONF_IDLE(_cnf)	\
    _CONF_FLAG_ENABLED(_cnf,overhead_idle);	\
    _CONF_FLAG_ENABLED(_cnf,watchidle)

#  define _GET_CONF_SESSION(_cnf)	\
    _CONF_FLAG_ENABLED(_cnf,overhead_session);	\
    _CONF_FLAG_ENABLED(_cnf,watchsession)

#  define _GET_CONF_INTERNAL(_cnf)	\
    _CONF_FLAG_ENABLED(_cnf,overhead_internal);	\
    _CONF_FLAG_ENABLED(_cnf,watchinternal)

#define GET_CONF(_pos,_cnf)				\
    if (_pos.s != (server_rec *) NULL) {		\
      if (s == (server_rec *) NULL) { s = _pos.s; }	\
      _cnf = (modff_config_t *) ap_get_module_config (_pos.s->module_config, &ff_module); \
      overhead = _MAX(overhead,ff_overhead_any(_cnf));	\
      _CONF_FLAG_ENABLED(_cnf,enabled);			\
      _CONF_FLAG_ENABLED(_cnf,verbose);			\
      _CONF_FLAG_ENABLED(_cnf,verbose_postmortem);	\
      _CONF_FLAG_ENABLED(_cnf,extended);		\
      _CONF_FLAG_ENABLED(_cnf,overhead_child);		\
      _CONF_FLAG_ENABLED(_cnf,watchchild);		\
      _CONF_FLAG_ENABLED(_cnf,enabled);			\
      _GET_CONF_SESSION(_cnf);				\
      _GET_CONF_IDLE(_cnf);				\
      _GET_CONF_INTERNAL(_cnf);				\
    }

    GET_CONF(child_init_position,child_conf);
    GET_CONF(idle_position,idle_conf);
    GET_CONF(internal_position,internal_conf);
    GET_CONF(session_position,session_conf);


    /* If we're not enabled, don't bother. */
    if (! (enabled || ff_any_enabled))
    {
        return (APR_SUCCESS);
    }


    /*
     * XXXXXXX The security model needs to be thought through here!!!
     */

    /* Heavy lifting begins. */
    if (watchchild)
    {
        /* Initialize stuff on the stack. */
        memset ((void *) &diff, 0, sizeof(diff));

	_fd_report[0] = '\0';  /* Start with empty message buffer */
	fd_report = (char *)  NULL;
	if (extended)
	  fd_report = _fd_report;
	
	count = delta_ff_stat (&(child_init_position.ff), &(request_position.ff),
			       &diff, fd_report, sizeof(_fd_report));
	if (count != -1)	/* All OK?? */
	{
	    ff_swatch (APLOG_MARK, APLOG_INFO, 0, s, &diff,
		       DEF_TIMEFMT(child_conf->timefmt), verbose,
		       "%s: %sPid %d Final watch <%s> %s",
		       ff_module.name, ff_labelid(child_conf), me,
		       POSITION_TAG(&child_init_position), _fd_report);
	}
	reset_ff_stat (&diff);
    }


    if (watchsession)
    {
        /* Initialize stuff on the stack. */
        memset ((void *) &diff, 0, sizeof(diff));

	_fd_report[0] = '\0';  /* Start with empty message buffer */
	fd_report = (char *) NULL;
	if (extended)
	  fd_report = _fd_report;

	count = delta_ff_stat (&(session_position.ff), &(request_position.ff),
			       &diff, fd_report, sizeof(_fd_report));
	if (count != -1)	/* All OK?? */
	{
           ff_swatch (APLOG_MARK, APLOG_INFO, 0, s, &diff,
		      DEF_TIMEFMT(session_conf->timefmt), verbose,
		      "%s: %sPid %d Final watch <%s> %s",
		      ff_module.name, ff_labelid(session_conf), me,
		      POSITION_TAG(&session_position), _fd_report);
	}
	reset_ff_stat (&diff);
    }

    
    if (watchidle)
    {
        /* Initialize stuff on the stack. */
        memset ((void *) &diff, 0, sizeof(diff));
	_fd_report[0] = '\0';  /* Start with empty message buffer */
	if (extended)
	  fd_report = _fd_report;
	
	count = delta_ff_stat (&(idle_position.ff), &(request_position.ff),
			       &diff, fd_report, sizeof(_fd_report));
	if (count != -1)	/* All OK?? */
	{
           ff_swatch (APLOG_MARK, APLOG_INFO, 0, s, &diff,
		      DEF_TIMEFMT(idle_conf->timefmt), verbose,
		      "%s: %sPid %d Final watch <%s> %s",
		      ff_module.name, ff_labelid(idle_conf), me,
		      POSITION_TAG(&idle_position), _fd_report);
	}
	reset_ff_stat (&diff);
    }

    
    if (watchinternal)
    {
        /* Initialize stuff on the stack. */
        memset ((void *) &diff, 0, sizeof(diff));

	_fd_report[0] = '\0';  /* Start with empty message buffer */
	fd_report = (char *) NULL;
	if (extended)
	  fd_report = _fd_report;

	count = delta_ff_stat (&(internal_position.ff), &(request_position.ff),
			       &diff, fd_report, sizeof(_fd_report));
	if (count != -1)	/* All OK?? */
	{
           ff_swatch (APLOG_MARK, APLOG_INFO, 0, s, &diff,
		      DEF_TIMEFMT(internal_conf->timefmt), verbose,
		      "%s: %sPid %d Final watch <%s> %s",
		      ff_module.name, ff_labelid(session_conf), me,
		      POSITION_TAG(&internal_position), _fd_report);
	}
	reset_ff_stat (&diff);
    }

    
    if (overhead_child)
    {
        ff_log_overhead (APLOG_MARK, APLOG_INFO, 0, s, 
			 child_conf, &child_init_position, "*");
    }

    if (overhead_idle)
    {
        ff_log_overhead (APLOG_MARK, APLOG_INFO, 0, s, 
			 idle_conf, &idle_position, "*");
    }


    if (overhead_internal)
    {
        ff_log_overhead (APLOG_MARK, APLOG_INFO, 0, s, 
			 internal_conf, &internal_position, "*");
    }


    if (overhead_session)
    {
        ff_log_overhead (APLOG_MARK, APLOG_INFO, 0, s, 
			 session_conf, &session_position, "*");
    }



    /* Final cleanup */
    
    ff_reset_position (_func, &child_init_position);
    ff_reset_position (_func, &request_position);
    ff_reset_position (_func, &idle_position);
    ff_reset_position (_func, &internal_position);
    ff_reset_position (_func, &session_position);


    /* Final report */
    _fd_report[0] = '\0';
    fd_report = (char *) NULL;
    if (extended)
      fd_report = _fd_report;

    msg = postmortem_position (fd_report, sizeof(_fd_report),
			       ff_any_verbose || ff_any_extended || ff_any_checkoverhead ||
			       verbose_postmortem || overhead);
    
    if (msg)
    {
        ap_log_error (APLOG_MARK, APLOG_INFO, 0, s, "%s: Pid %d Postmortem %s",
		      ff_module.name, me, msg);
    }

    /* And we're done. */
    return (APR_SUCCESS);

} /* end of ff_child_cleanup (void *data) */



/*
 * Initialize thing.  Hang an object on the pool 'p' that
 * will have an function executed when the child terminates.
 */
void   
ff_child_init (apr_pool_t *p, server_rec *s)
{
    __FUNC(ff_child_init);
    modff_config_t *conf = ff_find_sconfig (_func, s);


    dirty_child = 1;

    me = getpid();		/* Only needed here. */
    
    /*
     * This is ugly and can make threading nearly impossible...
     *
     * Engage hooks in lower layers to enable debug logging.
     */
    if (s->loglevel >= APLOG_DEBUG)
    {
        if (ENABLED(conf,verbose_postmortem))  /* Maybe this should be a new switch. */
	{
	    mod_log_debug_context.s = s;
	    mod_log_debug_context.file = __FILE__;
	    mod_log_debug_context.line = __LINE__;
	    
	    mod_log_debug_hook_register ( &mod_log_debug_context,  mod_vprintf_log, 7);
	}
    }

    child_init_position.s = s;	/* Initialize to where we are. */

    (void) ff_get_position (_func, conf, &child_init_position, (modff_position_t *) NULL,
			    s, (request_rec *) NULL, ff_overhead_any(conf));

    /* Copy initial state to other counters */
    (void) ff_copy_position (_func, &request_position, &child_init_position);
    (void) ff_copy_position (_func, &session_position, &child_init_position);
    (void) ff_copy_position (_func, &idle_position, &child_init_position);
    (void) ff_copy_position (_func, &internal_position, &child_init_position);

    
    ff_sreport (APLOG_MARK, APLOG_DEBUG, 0, s, &(child_init_position.ff), DEF_TIMEFMT(conf->timefmt),
		ENABLED(conf,verbose), /* dump */ ENABLED(conf,debug_procinfo),
		"%s: %sPid %d config #%d, enabled=%s, initial state",
		ff_module.name, ff_labelid(conf), me, conf->id, ENABLED(conf,enabled) ? "ON" : "OFF");
   
    /* Hook in a routine to run when this child exits. */
    apr_pool_cleanup_register (p, s, &ff_child_cleanup, apr_pool_cleanup_null);

    return;

} /* end of ff_child_init (p, s) */



static int
ff_regular_actions (modff_config_t *conf, request_rec *r, modff_position_t *cur)
{
    __FUNC(ff_regular_actions);
    int new_session = 0;
    char overhead_msg[1024];
    char *tmp;		/* Temporary */

    /* Child processing */
    ff_action (conf, r, cur, &child_init_position,
	       &(conf->warn_child), &(conf->exit_child),
	       /* watch=false */ 0);

    /* 
     * Session Processing
     *
     * If a new session came up, then report stuff.
     */

    /* Reusing 'overhead_msg' for a non-overhead message */
    tmp = (char *) NULL;
    if (DEBUG_SESSION(conf))
    {
	tmp = overhead_msg;
    }
    overhead_msg[0] = '\0';

    if (ff_same_session (&session_position, cur, tmp, sizeof(overhead_msg),
			 ff_same_session_opts(conf), DEBUG_SESSION(conf)) != 0)
    {
        if (overhead_msg[0] != '\0')
	{
	    ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r,
			   "%s: %sPid %d New session because %s",
			   ff_module.name, ff_labelid(conf),
			   me, overhead_msg);
	}

	/*
	 * Security model: The 'watch' option on ff_action() can reveal
	 * the path names of older file descriptors.  Don't show them
	 * unless the same virtual host was involved.
	 */
        ff_action (conf, r, cur, &session_position,
		   &(conf->warn_session), &(conf->exit_session),
		   ENABLED(conf,watchsession) &&
		   (ff_same_virtual_host (cur, &session_position,
					  (char *) NULL, 0) == 0));
	new_session = 1;
    }
    else
    {
        sum_rusage (&(cur->ff.overhead), &(session_position.overhead),
		    &(session_position.overhead));

	if (conf->max_requests_per_session != FF_UNSET)
	{
	    if (session_position.session_count >= conf->max_requests_per_session)
	    {
	        this_child_will_die ++;
		ap_log_rerror (APLOG_MARK, APLOG_NOTICE, 0, r,
			       "%s: %sPid %d <%s> max_requests_per_session reached %u by %s '%s'",
			       ff_module.name, ff_labelid(conf), me,
			       POSITION_TAG(&session_position), session_position.session_count,
			       r->method, r->unparsed_uri);
	    }
	}
    }


    child_init_position.request_count ++;
    if (conf->max_requests_per_child != FF_UNSET)
    {
        if (child_init_position.request_count >= conf->max_requests_per_child)
	{
	    this_child_will_die ++;
	    ap_log_rerror (APLOG_MARK, APLOG_NOTICE, 0, r,
			   "%s: %sPid %d <%s> max_requests_per_child reached %u by %s '%s'",
			   ff_module.name, ff_labelid(conf), me,
			   POSITION_TAG(&child_init_position), child_init_position.request_count,
			   r->method, r->unparsed_uri);
	}
    }

    
    /*
     * Show overhead usage
     */

    if (ENABLED(conf,overhead_idle))
    {
        ff_rlog_overhead (APLOG_MARK, APLOG_INFO, 0, r, 
			   conf, &idle_position, "*");
    }

    if (ENABLED(conf,overhead_request))
    {
        ff_rlog_overhead (APLOG_MARK, APLOG_INFO, 0, r,
			  conf, &request_position, "*");
    }


    if (new_session)
    {
	if (ENABLED(conf,overhead_session))
	{
	    ff_rlog_overhead (APLOG_MARK, APLOG_INFO, 0, r,
			      conf, &session_position, "*");
	}

	/* Clear session information and reset */
	ff_copy_position (_func, &(session_position), cur);
    }


    if (ENABLED(conf,overhead_child))
    {
        if (cmp_rusage (&(child_init_position.ff.overhead), &last_child_overhead) != 0)
	{
	    ff_rlog_overhead (APLOG_MARK, APLOG_INFO, 0, r,
			      conf, &child_init_position, "*");
	    count_same_child_overhead = 0;
	}
	else 
	{
	    count_same_child_overhead ++;
	}

	/* Limit the number of times we suppress the changes. */
	if ((conf->suppress_child_overhead != 0) &&
	    (conf->suppress_child_overhead < count_same_child_overhead))
	{
	    memset ((void *) &last_child_overhead, 0, sizeof(last_child_overhead));
	}
	else
	{
	    memcpy ((void *) &last_child_overhead, (void *) &(child_init_position.ff.overhead),
		    sizeof (last_child_overhead));
	}
    }

    return (0);

} /* end of ff_regular_actions() */


static int 
ff_action (modff_config_t *conf, request_rec *r, modff_position_t *new_pos,
	   modff_position_t *to_pos, const ff_threshold_t *t_warn, const ff_threshold_t *t_exit,
	   int watch)
{
    __FUNC(ff_action);
    int count;
    ff_stat_t diff;
    char report[REPORT_BUFFLEN_LONG];
    char _fd_report[FD_REPORT_SIZE];   /* Big, fixed sized temp buffer. */
    char *fd_report = (char *) NULL;
    
    /* Initialize stuff on the stack. */
    memset ((void *) &diff, 0, sizeof(diff));

        /* Total up overhead for class of position */
    sum_rusage (&(new_pos->ff.overhead), &(to_pos->overhead), 
		&(to_pos->overhead));

    _fd_report[0] = '\0';  /* Start with empty message buffer */
    if (watch)
      fd_report = _fd_report;

    count = delta_ff_stat (&(to_pos->ff), &(new_pos->ff), &diff,
			   fd_report, sizeof(_fd_report));
    if (count == -1)	/* Fatal error. All blew up. */
    {
	ap_log_cerror (APLOG_MARK, APLOG_DEBUG, 0, r->connection,
		"%s: %sPid %d - delta_ff_stat('%s'.ff, '%s'.ff, &diff) returned %d by %s '%s'",
		       ff_module.name, ff_labelid(conf), me, to_pos->tag, new_pos->tag,
		       count, r->method, r->unparsed_uri);
	
	ff_rreport (APLOG_MARK, APLOG_DEBUG, 0, r, &(new_pos->ff), DEF_TIMEFMT(conf->timefmt),
		    /* verbose */ 1, /* dump */ ENABLED(conf,debug_procinfo),
		    "%s: %sPid %d '%s'.ff ", ff_module.name, ff_labelid(conf), me,
		    new_pos->tag);
	
	ff_rreport (APLOG_MARK, APLOG_DEBUG, 0, r, &(to_pos->ff), DEF_TIMEFMT(conf->timefmt),
		    /* verbose */ 1, /* dump */ ENABLED(conf,debug_procinfo),
		    "%s: %sPid %d '%s'.ff ", ff_module.name, ff_labelid(conf), me,
		    to_pos->tag);
    }
    else
    {
        /* Implement watch */
        if (watch)
	{
	    ff_rwatch (APLOG_MARK, APLOG_INFO, 0, r, &diff,
		       DEF_TIMEFMT(conf->timefmt), ENABLED(conf,verbose),
		       "%s: %sPid %d Watch <%s> %s '%s' %s",
		       ff_module.name, ff_labelid(conf), me,
		       POSITION_TAG(to_pos), r->method, r->unparsed_uri, fd_report);
	}
	else if ((r->server->loglevel >= APLOG_DEBUG))
	{
	    ff_rreport (APLOG_MARK, APLOG_DEBUG, 0, r, &diff, DEF_TIMEFMT(conf->timefmt),
			ENABLED(conf,verbose), /* dump */ ENABLED(conf,debug_procinfo),
			"%s: %sPid %d delta_ff_stat('%s'.ff, '%s'.ff) returns %d, %s '%s' %s",
			ff_module.name, ff_labelid(conf), me, POSITION_TAG(to_pos), 
			POSITION_TAG(new_pos), count, r->method, r->unparsed_uri, fd_report);
	}

	/* Implement warn */
	if (t_warn != (ff_threshold_t *) NULL)
	{
	    report[0] = '\0';
	    if (check_threshold (report, sizeof(report), t_warn, &diff,
				 DEF_TIMEFMT(conf->timefmt), ENABLED(conf,verbose)) > 0)
	    {
	        ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r,
			       "%s: %sPid %d <%s> warning for %s by %s '%s'",
			       ff_module.name, ff_labelid(conf), me,
			       POSITION_TAG(to_pos), report, r->method, r->unparsed_uri);
	    }
	}
	
	/* Implement exit */
	if (t_exit != (ff_threshold_t *) NULL)
	{
	    report[0] = '\0';
	    if (check_threshold (report, sizeof(report), t_exit, &diff,
				 DEF_TIMEFMT(conf->timefmt), ENABLED(conf,verbose)) > 0)
	    {
	        this_child_will_die++;		/* This child should die... */
	        ap_log_rerror (APLOG_MARK, APLOG_NOTICE, 0, r,
			       "%s: %sPid %d <%s> maximum reached for %s by %s '%s'",
			       ff_module.name, ff_labelid(conf), me,
			       POSITION_TAG(to_pos), report, r->method, r->unparsed_uri);
	    }
	}
    }

    reset_ff_stat (&diff);

    return (0);

} /* end of ff_action() */


modff_config_t *
ff_find_rconfig (request_rec *r, server_rec **p_server)
{
    __FUNC(ff_find_rconfig);
    request_rec    *eff_r = r;	/* The effective request, assume the one we're passed. */
    server_rec     *s;
    modff_config_t *conf = (modff_config_t *) NULL;

    /*
     * If there's no request, we're hosed.
     */
    if (eff_r == (request_rec *) NULL)
        return ((modff_config_t *) NULL);

    if (eff_r->main != (request_rec *) NULL)
    {
        /* This is a sub-request. Use the main request instead. */
        eff_r = eff_r->main;
    }

    conf = (modff_config_t *) ap_get_module_config (eff_r->per_dir_config,
						    &ff_module);
    /* Mark the server for this thing. */
    s = eff_r->server;

    if (conf == (modff_config_t *) NULL)
    {
        conf = ff_find_sconfig (_func, r->server);
	s = r->server;
    }

    if ((conf != (modff_config_t *) NULL) && (p_server != (server_rec **) NULL))
        *p_server = s;

    return (conf);

}  /* end of ff_find_rconfig() */



modff_config_t *
ff_find_sconfig (const char *by_func, server_rec *s)
{
    __FUNC(ff_find_sconfig);
    modff_config_t *conf = (modff_config_t *) NULL;

    if (me == 0)
        me = getpid();

    /*
     * If there's no server, we're hosed.
     */
    if (s == (server_rec *) NULL)
        return ((modff_config_t *) NULL);

    conf = (modff_config_t *) ap_get_module_config (s->module_config,
						    &ff_module);
    
    if (conf)
    {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
		      "%s: %sPid %d - Found configuration #%d for %s()",
		      ff_module.name, ff_labelid(conf), me, conf->id, by_func);
    }
    else
    {
        ap_log_error (APLOG_MARK, APLOG_INFO, 0, s,
		      "%s: Pid %d - Unable to find configuration for %s()", 
		      ff_module.name, me, by_func);
    }

    return (conf);

}  /* end of ff_find_sconfig() */



/*
 * Called at the begining of every request.
 *
 * This gives us a chance to measure the fat generated by the application.
 */
int
ff_request_begin (request_rec *r)
{
    __FUNC(ff_request_begin);
    modff_config_t *conf = ff_find_rconfig (r, (server_rec **) NULL);
    modff_position_t BEGIN_REQUEST;
    const apr_table_entry_t *each_header;
    long guard_word_1 = 123456;
    apr_table_entry_t *cur_header;
    long guard_word_2 = 65432;
    const apr_array_header_t *tar;	/* Temporary array pointer */
    char *errmsg = "Nobody here but us cats";
    
    /* Initialize stuff on stack. */
    memset ((void *) &BEGIN_REQUEST, 0, sizeof(BEGIN_REQUEST));
    BEGIN_REQUEST.tag = "begin-request";

    if (r_is_internal (r)) 
    {
        if (NOT_ENABLED(conf,do_internal))
	{
	    if (DEBUG_SESSION(conf))
	    {
	        ap_log_rerror (APLOG_MARK, APLOG_NOTICE, 0, r,
			       "%s: %sPid %d - Ignoring internal request %s '%s'",
			       ff_module.name, ff_labelid(conf), me,
			       r->method, r->unparsed_uri);
	    }
	    
	    return (DECLINED);
	}
    }

    /*
     * Allow mod_ff to be used in simple minded fashion to log headers.
     */
    if (ENABLED(conf,dump_headers)) 
    {
      cur_header = (apr_table_entry_t *) NULL;
      each_header = ff_apr_table_entry_next (r->headers_in, &cur_header, &errmsg);

      if (each_header)
	{
	  me = getpid ();
	  tar = apr_table_elts (r->headers_in);

	  ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r, 
			 "%s: %sPid %d header table %d of %d elements of size %d",
			 ff_module.name, ff_labelid (conf), me, tar->nelts, 
			 tar->nalloc, tar->elt_size);

	  for ( ;
		(apr_table_entry_t *) NULL != each_header ; 
		each_header = ff_apr_table_entry_next (r->headers_in, &cur_header, &errmsg)) 
	    {
	      if ((char *) NULL != each_header->key)
		{
		  if ((char *) NULL != each_header->val)
		    {
		      ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r, "%s: %sPid %d header '%s': value '%s'",
				     ff_module.name, ff_labelid (conf), me, each_header->key, each_header->val);
		    }
		  else
		    {
		      ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r, "%s: %sPid %d header '%s'",
				     ff_module.name, ff_labelid (conf), me, each_header->key);
		    }
		}
	    }
	}
    }

    if (ENABLED(conf,dump_env)) 
    {
      cur_header = (apr_table_entry_t *) NULL;

      each_header = ff_apr_table_entry_next (r->subprocess_env, &cur_header, &errmsg);
      if (each_header)
	{
	  me = getpid ();
	  tar = apr_table_elts (r->subprocess_env);

	  ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r, 
			 "%s: %sPid %d env table %d of %d elements of size %d",
			 ff_module.name, ff_labelid (conf), me, tar->nelts, 
			 tar->nalloc, tar->elt_size);

	  for ( ;
		(apr_table_entry_t *) NULL != each_header ; 
		each_header = ff_apr_table_entry_next (r->subprocess_env, &cur_header, &errmsg)) 
	    {
	      if ((char *) NULL != each_header->key)
		{
		  if ((char *) NULL != each_header->val)
		    {
		      ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r,
				     "%s: %sPid %d env '%s': value '%s'",
				     ff_module.name, ff_labelid (conf), me, each_header->key,
				     each_header->val);
		    }
		  else
		    {
		      ap_log_rerror (APLOG_MARK, APLOG_INFO, 0, r, "%s: %sPid %d env '%s'",
				     ff_module.name, ff_labelid (conf), me, each_header->key);
		    }
		}
	    }
	}
    }

    /* Initialize 'BEGIN_REQUEST' with all the stats and stuff from 'idle_position' */
    ff_copy_position (_func, &BEGIN_REQUEST, &idle_position);

    if (ff_get_position (_func, conf, &BEGIN_REQUEST, last_position, 
			 (server_rec *) NULL, r, FLAGVAL(conf,overhead_idle)))
    {
        /* we blew up. Depend on ff_get_position() to log things. */
        return (DECLINED);
    }

    /*
     * treat the period between the end of the previous request and the
     * begining of this request as 'idle' and process it. 
     *
     *
     * Security model: The 'watch' option on ff_action() can reveal
     * the path names of older file descriptors.  Don't show them
     * unless the same virtual host was involved.
     */

    ff_action (conf, r, &BEGIN_REQUEST, last_position, 
	       &(conf->warn_idle), &(conf->exit_idle),
	       ENABLED(conf,watchidle) &&
	       (ff_same_virtual_host (&BEGIN_REQUEST, last_position,
				      (char *) NULL, 0) == 0));
	       
    ff_move_position (_func, &idle_position, &BEGIN_REQUEST);

    return (DECLINED);

} /* end of ff_request_begin() */



/*
 * Called at the end of every request.
 *
 * This gives us a chance to measure the fat generated by the application.
 */
int
ff_request_end (request_rec *r)
{
    __FUNC(ff_request_end);
    int internal;
    modff_config_t *conf = ff_find_rconfig (r, (server_rec **) NULL);
    modff_position_t END_REQUEST;
    
    /* Initialize stuff on stack. */
    memset ((void *) &END_REQUEST, 0, sizeof(END_REQUEST));
    END_REQUEST.tag = "end-request";

    /* Treat internal requests specially... */
    internal = r_is_internal (r);
    if (internal)
    {
        if (NOT_ENABLED(conf,do_internal))
	{
	    if (DEBUG_SESSION(conf))
	    {
	        ap_log_rerror (APLOG_MARK, APLOG_NOTICE, 0, r,
			       "%s: %sPid %d - Ignoring internal request %s '%s'",
			       ff_module.name, ff_labelid(conf), me,
			       r->method, r->unparsed_uri);
	    }
	    
	    return (DECLINED);
	}
    }

    /* Initialize 'END_REQUEST' with all the stats and stuff from 'last_position' */
    ff_copy_position (_func, &END_REQUEST, last_position);

    if (ff_get_position (_func, conf, &END_REQUEST, last_position, 
			 (server_rec *) NULL, r, FLAGVAL(conf,overhead_request)))
    {
        /* we blew up. Depend on ff_get_position() to log things. */
        return (DECLINED);
    }


    if (! internal)
    {
        /*
	 * Processing the current request is special
	 *
	 * Security model: The 'watch' option on ff_action() can reveal
	 * the path names of older file descriptors.  Don't show them
	 * unless the same virtual host was involved.
	 */

        END_REQUEST.request_count ++;
        ff_action (conf, r, &END_REQUEST, last_position, 
		   &(conf->warn_request), &(conf->exit_request),
		   ENABLED(conf,watchrequest) &&
		   (ff_same_virtual_host (&END_REQUEST, last_position,
					  (char *) NULL, 0) == 0));

        /* Regular other processing */
        ff_regular_actions (conf, r, &END_REQUEST);

	last_position = &request_position;
    }
    else
    {
        /*
	 * Processing an internal request is abbreviated.
	 *
	 * Security model: The 'watch' option on ff_action() can reveal
	 * the path names of older file descriptors.  Don't show them
	 * unless the same virtual host was involved.
	 */

        ff_action (conf, r, &END_REQUEST, last_position, 
		   &(conf->warn_internal), &(conf->exit_internal),
		   ENABLED(conf,watchinternal) &&
		   (ff_same_virtual_host (&END_REQUEST, last_position,
					  (char *) NULL, 0) == 0));
        last_position = &internal_position;
    }

    ff_move_position (_func, last_position, &END_REQUEST);

    if (this_child_will_die > 0)
    {
	if (me > 1) 
	{
   	    ap_log_rerror (APLOG_MARK, APLOG_NOTICE, 0, r,
			   "%s: %sPid %d %d reasons to quit after %u requests", ff_module.name,
			   ff_labelid(conf), me, this_child_will_die, 
			   child_init_position.request_count);

	    kill (me, AP_SIG_GRACEFUL_STOP);
	}
	else
	{
	    ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r,
			   "%s: %sPid %d Can't kill pid %d, even with %d reasons",
			   ff_module.name, ff_labelid(conf), me, me, this_child_will_die);
	}
    }


    /* Pass this request on to the next hook. */
    return (DECLINED);


} /* end of ff_request_end (r) */
