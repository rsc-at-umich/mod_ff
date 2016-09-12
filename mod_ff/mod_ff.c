/*
        Apache Module Fat Finder (mod_ff)

	Copyright 2012-2013 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: mod_ff.c,v 1.21 2013/03/07 16:09:31 rsc Exp $

	This file contains purely Apache API code, except for
	the few interface handlers in ff_handlers.c
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

#define SUPPRESS_CHILD_OVERHEAD 20	/* Default number of times to suppress. */


#define _THRESHOLDS "vmsize|rss|fds|utime|stime|cutime|cstime|minflt|majflt|cminflt|cmajflt|tick"

#define _IDLE_COMMA "Idle, "
#define _IDLE_OR "Idle|"
#define _SESSION_COMMA "Session, "
#define _SESSION_OR "Session|"
#define _INTERNAL_COMMA "Internal, "
#define _INTERNAL_OR "Internal|"



static char rcsid[] = "$Id: mod_ff.c,v 1.21 2013/03/07 16:09:31 rsc Exp $";

module AP_MODULE_DECLARE_DATA ff_module;

static modff_config_t *ff_new_config (apr_pool_t *p);
static modff_config_t *ff_merge_config (apr_pool_t *p, modff_config_t *parent_conf, 
					modff_config_t *newlocn_conf);
static void * ff_merge_dir_config (apr_pool_t *p, void *parent_conf, void *newlocn_conf);
static void * ff_merge_server_config (apr_pool_t *p, void *parent_conf, void *newlocn_conf);
static void * ff_create_server_config (apr_pool_t *p, server_rec *s);
static void * ff_create_dir_config (apr_pool_t *p, char *dir);
static const char * set_modff_threshold (char *buff, size_t bufflen, cmd_parms *params,
					 modff_config_t *conf, ff_threshold_t *thresh,
					 const char *th, const char *item, const char *num);

static int  ff_getflag(const char *str);


/*
 * Convert strings like 'ON', 'OFF', etc. to numberic FF_ENABLE, FF_DISABLE, FF_FULL
 */

static int
ff_getflag (const char *str)
{
    if ((str == (char *) NULL) || (*str == '\0'))
        return (FF_UNSET);

    if ((strcasecmp (str, "ON") == 0) || (strcasecmp (str, "YES") == 0) ||
	(strcasecmp (str, "OK") == 0) || (strcasecmp (str, "TRUE") == 0) ||
	(strcasecmp (str, "ENABLE") == 0) || (strcmp (str, "1") == 0))
      return (FF_ENABLE);

    if ((strcasecmp (str, "OFF") == 0) || (strcasecmp (str, "NO") == 0) ||
	(strcasecmp (str, "FALSE") == 0) || (strcasecmp (str, "DISABLE") == 0) ||
	(strcmp (str, "0") == 0))
      return (FF_DISABLE);

    if ((strcasecmp (str, "FULL") == 0) || (strcasecmp (str, "ALL") == 0) ||
	(strcasecmp (str, "LONG") == 0) || (strcmp (str, "2") == 0))
      return (FF_FULL);

    if ((strcasecmp (str, "UNSET") == 0) || (strcasecmp (str, "CLEAR") == 0) ||
	(strcasecmp (str, "CLEAR") == 0))
      return (FF_UNSET);

    return -1;

} /* end of ff_getflag() */


static const char *
set_modff_threshold (char *buff, size_t bufflen, cmd_parms *params, modff_config_t *conf,
		     ff_threshold_t *thresh, const char *th, const char *item, const char *num)
{
    unsigned long siz;
    char errbuff[64];
    char *errmsg = (char *) NULL;
    int  me = getpid();

    /*
     * My apologies for abusing the readability of the code
     * by IDEs - but this helps reduce the potential for error
     * in the code, and your IDE should be emacs & make anyway.
     *
     * --- Richard (rsc)
     */

#define if_SET_THRESHOLD(_field,_name,_fmt,_max)			\
    if (strcasecmp (item, _name) == 0) {				\
      siz = str_to_ul (num, errbuff, sizeof(errbuff), _max, &errmsg);	\
      if (errmsg == (char *) NULL) {					\
	thresh->_field = siz;						\
	ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,	\
		      "%s: %sPid %d - Config id #%d - '%s %s' set to "	\
		      _fmt " ('%s')",					\
		      ff_module.name, ff_labelid(conf), me, conf->id,	\
		      th, item, siz, num);				\
	return ((char *) NULL);	/* Success */				\
      } }
	
#define if_SET_THRESHOLD_UL(_field,_name) if_SET_THRESHOLD(_field,_name,"%lu",ULONG_MAX)

#define if_SET_THRESHOLD_L(_field,_name) if_SET_THRESHOLD(_field,_name,"%ld",LONG_MAX)

#define if_SET_THRESHOLD_S(_field,_name) if_SET_THRESHOLD(_field,_name,"%d",SHRT_MAX)

    if_SET_THRESHOLD_UL(vmsize, "vmsize")
    else
      if_SET_THRESHOLD_UL(utime, "utime")
    else
      if_SET_THRESHOLD_L(stime, "stime")
    else 
      if_SET_THRESHOLD_UL(cutime, "cutime")
    else 
      if_SET_THRESHOLD_L(cstime, "cstime")
    else
      if_SET_THRESHOLD_L(minflt, "minflt")
    else
      if_SET_THRESHOLD_L(majflt, "majflt")
    else
      if_SET_THRESHOLD_L(cminflt, "cminflt")
    else
      if_SET_THRESHOLD_L(cmajflt, "cmajflt")
    else
      if_SET_THRESHOLD_L(fds, "fds")
    else
      if_SET_THRESHOLD_UL(rss, "rss")
    else
      if_SET_THRESHOLD(tick, "tick", "%lu", 365*24*3600)
    else 
    {
        snprintf (errbuff, sizeof(errbuff), "Unknown item ('%s') to set in '%s'", item, th);
	errmsg = errbuff;
    }
    
    /* Collect the error message and return an error condition. */

    ap_log_error (APLOG_MARK, APLOG_ERR, 0, params->server, "Syntax error: %s", errmsg);

    strncat (buff, errmsg, bufflen);
    return buff;

} /* end of set_modff_threshold() */




static modff_config_t *
ff_new_config (apr_pool_t *p)
{
    modff_config_t *new;
    static int idnum = 0;

    idnum ++;
 
    new = (modff_config_t *) apr_pcalloc (p, sizeof (modff_config_t));
    
    memset (new, 0, sizeof(modff_config_t));	/* 0 is the same as FF_UNSET */

    new->pfx = FF_UNSET;
    new->enabled = FF_UNSET;	/* It's 0 - so no-op. */
    new->extended = FF_UNSET;
    new->verbose = FF_UNSET;
    new->verbose_postmortem = FF_UNSET;
    new->cleanup = FF_UNSET;

    new->session_cookie_name = FF_UNSET;

    new->debug_procinfo = FF_UNSET;
    new->debug_config = FF_UNSET;
    new->debug_session = FF_UNSET;
    new->debug_position = FF_UNSET;
    new->dump_env = FF_UNSET;
    new->dump_headers = FF_UNSET;
    new->log_main = FF_UNSET;
    new->do_loopback = FF_UNSET;
    new->do_remote_tcpport = FF_UNSET;
    new->do_internal = FF_UNSET;

    new->watchchild = FF_UNSET;
    new->overhead_child = FF_UNSET; 
    new->suppress_child_overhead = SUPPRESS_CHILD_OVERHEAD;
    new->max_requests_per_child = FF_UNSET;
    new->max_requests_per_session = FF_UNSET;

    new->watchrequest = FF_UNSET;
    new->overhead_request = FF_UNSET; 

    new->watchidle = FF_UNSET;
    new->overhead_idle = FF_UNSET; 

    new->watchsession = FF_UNSET;
    new->overhead_session = FF_UNSET; 

    new->watchinternal = FF_UNSET;
    new->overhead_internal = FF_UNSET; 

    new->defined_remote_ip_sources = FF_UNSET;
    new->defined_ignore_status = FF_UNSET;

    new->id = idnum;
    new->timefmt = FF_UNSET;	/* See man strftime for '%c' - this is local time representation */

    return new;
} /* end of ff_new_config() */


modff_config_t *
ff_find_config (const char *by_func, cmd_parms *params, void *mconfig)
{
    modff_config_t *conf;
 
    if (mconfig != (void *) NULL)
    {
        conf = (modff_config_t *) mconfig;

	if (ENABLED(conf,debug_config))
	{
	    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
			  "%s: %s Using existing configuration #%d ("
			  FF_DIRECTIVE_PFX "Enable %s) for %s()", 
			  ff_module.name, ff_labelid (conf), conf->id,
			  ENABLED(conf,enabled) ? "ON" : "OFF", by_func);
	}
    }
    else
    {
        char buff [128];

        /* Get the configuration from the server. */
        conf = ff_find_sconfig (by_func, params->server);

	if (ENABLED(conf,debug_config))
	{
	    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
			  "%s: %s Got configuration #%d ("
			  FF_DIRECTIVE_PFX "Enable %s) from server '%s' for %s()",
			  ff_module.name, ff_labelid (conf), conf->id,
			  ENABLED(conf,enabled) ? "ON" : "OFF",
			  ff_ap_server_name (buff, sizeof(buff), 
					     params->server), by_func);
	}
    }

    return (conf);

} /* end of ff_find_config(params, mconfig) */



    
/* Tedious examination of each thing. */
#define F_MERGE(_dst,_alt,_src,_field)	\
    if ((_src)->_field != FF_UNSET) {		\
      (_dst)->_field = (_src)->_field;		\
    } else {					\
      (_dst)->_field = (_alt)->_field;		\
    }

#define F_STR_MERGE(_dst,_alt,_src,_field)		\
    if ((_src)->_field != FF_UNSET) {			\
      (_dst)->_field = apr_pstrdup(p,(_src)->_field);	\
    } else if ((_alt)->_field != FF_UNSET) {		\
      (_dst)->_field = apr_pstrdup(p,(_alt)->_field);	\
    } else {						\
      (_dst)->_field = FF_UNSET;			\
    }

#define S_MERGE(_dst,_alt,_src,_field)	\
    if (_src._field != FF_UNSET) {		\
      _dst._field = _src._field;		\
    } else {					\
	_dst._field = _alt._field;		\
    }

#define THRESH_MERGE(_dst,_alt,_src,_field)	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,vmsize);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,rss);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,utime);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,stime);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,minflt);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,majflt);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,cminflt);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,cmajflt);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,fds);	\
    S_MERGE((_dst)->_field,(_alt)->_field,(_src)->_field,tick);

static modff_config_t *
ff_merge_config (apr_pool_t *p, modff_config_t *parent_conf, modff_config_t *newlocn_conf)
{
    __FUNC(ff_merge_config);
    modff_config_t *new = ff_new_config (p);
    unsigned int    save_id;


    save_id = new->id;
    if (newlocn_conf == (modff_config_t *) NULL)
    {
        if (parent_conf != (modff_config_t *) NULL)
	{
  	    memcpy ((void *) new, (void *) parent_conf, sizeof(modff_config_t));
	    new->id = save_id;
	} 
	return (new);
    }

    if (parent_conf == (modff_config_t *) NULL)
    {
        memcpy ((void *) new, (void *) newlocn_conf, sizeof(modff_config_t));
	new->id = save_id;
	return (new);
    }


    F_MERGE(new,parent_conf,newlocn_conf,enabled);
    F_MERGE(new,parent_conf,newlocn_conf,extended);
    F_MERGE(new,parent_conf,newlocn_conf,verbose);
    F_MERGE(new,parent_conf,newlocn_conf,verbose_postmortem);
    F_MERGE(new,parent_conf,newlocn_conf,cleanup);

    F_MERGE(new,parent_conf,newlocn_conf,watchchild);
    F_MERGE(new,parent_conf,newlocn_conf,overhead_child);
    THRESH_MERGE(new,parent_conf,newlocn_conf,exit_child);
    THRESH_MERGE(new,parent_conf,newlocn_conf,warn_child);
    F_MERGE(new,parent_conf,newlocn_conf,suppress_child_overhead);
    F_MERGE(new,parent_conf,newlocn_conf,max_requests_per_child);
    F_MERGE(new,parent_conf,newlocn_conf,max_requests_per_session);

    F_MERGE(new,parent_conf,newlocn_conf,watchrequest);
    F_MERGE(new,parent_conf,newlocn_conf,overhead_request);
    THRESH_MERGE(new,parent_conf,newlocn_conf,exit_request);
    THRESH_MERGE(new,parent_conf,newlocn_conf,warn_request);

    F_MERGE(new,parent_conf,newlocn_conf,watchidle);
    F_MERGE(new,parent_conf,newlocn_conf,overhead_idle);
    THRESH_MERGE(new,parent_conf,newlocn_conf,exit_idle);
    THRESH_MERGE(new,parent_conf,newlocn_conf,warn_idle);

    F_MERGE(new,parent_conf,newlocn_conf,watchsession);
    F_MERGE(new,parent_conf,newlocn_conf,overhead_session);
    THRESH_MERGE(new,parent_conf,newlocn_conf,exit_session);
    THRESH_MERGE(new,parent_conf,newlocn_conf,warn_session);

    F_MERGE(new,parent_conf,newlocn_conf,watchinternal);
    F_MERGE(new,parent_conf,newlocn_conf,overhead_internal);
    THRESH_MERGE(new,parent_conf,newlocn_conf,exit_internal);
    THRESH_MERGE(new,parent_conf,newlocn_conf,warn_internal);

    F_MERGE(new,parent_conf,newlocn_conf,log_main);
    F_MERGE(new,parent_conf,newlocn_conf,do_loopback);
    F_MERGE(new,parent_conf,newlocn_conf,do_remote_tcpport);
    F_MERGE(new,parent_conf,newlocn_conf,do_internal);
    F_MERGE(new,parent_conf,newlocn_conf,debug_procinfo);
    F_MERGE(new,parent_conf,newlocn_conf,debug_config);
    F_MERGE(new,parent_conf,newlocn_conf,debug_session);
    F_MERGE(new,parent_conf,newlocn_conf,debug_position);
    F_MERGE(new,parent_conf,newlocn_conf,dump_env);
    F_MERGE(new,parent_conf,newlocn_conf,dump_headers);

    F_STR_MERGE(new,parent_conf,newlocn_conf,labelid);
    F_STR_MERGE(new,parent_conf,newlocn_conf,pfx);
    F_STR_MERGE(new,parent_conf,newlocn_conf,session_cookie_name);
    F_STR_MERGE(new,parent_conf,newlocn_conf,timefmt);


    if (newlocn_conf->defined_ignore_status != FF_UNSET)
    {
        new->ignore_status = intlist_dup (p, 1, newlocn_conf->ignore_status);
	new->defined_ignore_status = newlocn_conf->defined_ignore_status;
    }
    else if (parent_conf->defined_ignore_status != FF_UNSET)
    {
        new->ignore_status = intlist_dup (p, 1, parent_conf->ignore_status);
	new->defined_ignore_status = parent_conf->defined_ignore_status;
    }

    if (newlocn_conf->defined_remote_ip_sources != FF_UNSET)
    {
        new->remote_ip_sources = strlist_dup (p, 1, newlocn_conf->remote_ip_sources);
	new->defined_remote_ip_sources = newlocn_conf->defined_remote_ip_sources;
    }
    else if (parent_conf->defined_remote_ip_sources != FF_UNSET)
    {
        new->remote_ip_sources = strlist_dup (p, 1, parent_conf->remote_ip_sources);
	new->defined_remote_ip_sources = parent_conf->defined_remote_ip_sources;
    }


    if (ENABLED(new,debug_config))
    {
    	ff_log_debug (1, "Merging '%s' and '%s' into '%s'",
		      ff_labelid (newlocn_conf), ff_labelid (parent_conf), ff_labelid (new));
    }

    return (new);

} /* end of void *ff_merge_config() */



static void *
ff_merge_server_config (apr_pool_t *p, void *parent_conf, void *newlocn_conf)
{
    __FUNC(ff_merge_server_config);
    modff_config_t * new = ff_merge_config (p, parent_conf, newlocn_conf);

    /* Treatment of 'path'??? */

    return new;
} /* end of ff_merge_server_config() */



static void *
ff_merge_dir_config (apr_pool_t *p, void *parent_conf, void *newlocn_conf)
{
    __FUNC(ff_merge_dir_config);
    modff_config_t * pc = (modff_config_t *) parent_conf;
    modff_config_t * nc = (modff_config_t *) newlocn_conf;
    modff_config_t * new = ff_merge_config (p, parent_conf, newlocn_conf);
    
    F_STR_MERGE(new,pc,nc,path);

    return new;

} /* end of ff_merge_dir_config() */



static void *
ff_create_server_config(apr_pool_t *p, server_rec *s)
{
    modff_config_t *new = ff_new_config (p);
    int me = getpid();

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
		  "%s: Pid %d - Creating server config id #%d for '%s'",
		  ff_module.name, me, new->id, SERVER_HOSTNAME(s));

    return new;

} /* end of ff_create_server_config() */

static void *
ff_create_dir_config (apr_pool_t *p, char *dir)
{
    modff_config_t *new = ff_new_config (p);
   
    new->path = apr_pstrdup (p, dir);

    return new;

} /* end of ff_create_dir_config() */


static int
ff_init (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    __FUNC(ff_init);
    modff_config_t *conf = ff_find_sconfig (_func, s);
    static int count = 0;

    /* Ignore subsequent go-rounds */
    if (count == 0)
    {
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, s,
		      "%s (Fat Finder) started, version %s, RCSID: %s", ff_module.name,
		      PACKAGE_VERSION, rcsid);

	ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
		      "%s Server config id #%d, enabled %s", ff_module.name, conf->id, 
		      ENABLED(conf,enabled) ? "ON" : "OFF" );
    }
    count++;

    return (OK);

} /* end of ff_init */

/*
 * This function is a callback and it declares what other functions
 * should be called for request processing and configuration requests.
 * This callback function declares the Handlers for other events.
 */
static void mod_ff_register_hooks (apr_pool_t *p);

static void 
mod_ff_register_hooks (apr_pool_t *p)
{
  /* See: http://httpd.apache.org/docs/2.2/developer/request.html
   * See also: http://www.apachetutor.org/dev/request 
   *      and  http://www.apachetutor.org/dev/request 
   */

  /*
    ap_hook_quick_handler (GENERIC_quick_handler, NULL, NULL, APR_HOOK_FIRST)
  */

  /* The Request Processing Phase (metadata processing)
   *  1: translate_name
   *  *: map_to_storage      -- Where <File> and <Directory> processing occurs
   *  2: header_parser
   */
  ap_hook_map_to_storage (ff_request_begin, NULL, NULL, APR_HOOK_FIRST);

  /*  ap_hook_translate_name (GENERIC_translate_name, NULL, NULL, APR_HOOK_FIRST);
      ap_hook_header_parser (GENERIC_header_parser, NULL, NULL, APR_HOOK_FIRST); 
   */
  
    /* The Security Phase  (metadata processing)
     * SATISFY_ALL, SATISFY_NOSPEC:
     *    1: access_checker
     *
     * SATISFY_ANY:
     *    1: access_checker
     */
    /*
      ap_hook_access_checker (GENERIC_access_checker, NULL, NULL, APR_HOOK_FIRST);
    */

    /* The Preparation Phase (metadata processing)
     * 1: type_checker	 -- Test URI/filename against target resource
     * 2: fixups         -- When "trounced" (DECLINED by above)
     */
    /*
      ap_hook_type_checker (GENERIC_type_checker, NULL, NULL, APR_HOOK_FIRST);
      ap_hook_fixups (GENERIC_fixups, NULL, NULL, APR_HOOK_FIRST);
    */
    /* The Handler Phase (content processing - we let underlying systems take care of that.)
     *  *: insert_filter   -- Where normal pre-processing occurs.
     *  *: handler         -- Where content generation from file/php/cgi occurs.
     */

    /*
     * logging gives us a chance to do something at the end
     */
 
    ap_hook_log_transaction (ff_request_end, NULL, NULL, APR_HOOK_LAST);
    
    /* Configuration Processing??? */
    ap_hook_child_init (ff_child_init, NULL, NULL, APR_HOOK_LAST);

    /*
     * Called through "ap_run_post_read_request()" by "ap_read_request()" in 
     * "server/protocol.c"
     */
    /*
      ap_hook_post_read_request (GENERIC_read_request, NULL, NULL, APR_HOOK_FIRST);
    */


    /* 
     * Called through "ap_run_pre_connection()" by "ap_process_connection()" in
     * "server/connection.c"
     */
    /*
       ap_hook_pre_connection (GENERIC_new_connection, NULL, NULL, APR_HOOK_FIRST); 
    */

    
    /* Called through "ap_run_post_config()" by "main()" in "server/main.c"  (2 places.) */

    ap_hook_post_config (ff_init, NULL, NULL, APR_HOOK_FIRST);
    
    return;
} /* end of mod_ff_register_hooks() */


static const char * set_modff_enable (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_enable (cmd_parms *params, void *vconf, const char *str)
{
    __FUNC(set_modff_enable);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int me = getpid();
    int flag = ff_getflag (str);

    if (flag >= 0) {
        conf->enabled = flag;
	ff_any_enabled = 1;
    } else {
        return "Invalid flag - should be ON (yes, true, ok), or OFF (no, false)";
    }

    if (ENABLED(conf,debug_config))
    {
	ap_log_error (APLOG_MARK, APLOG_INFO, 0, params->server,
		      "%s: %sPid %d Config id #%d enabled is: %s for '%s'", 
		      ff_module.name, ff_labelid(conf), me, conf->id, 
		      ENABLED(conf,enabled) ? "ON" : "OFF", SERVER_HOSTNAME(params->server));
    }

    return ((char *) NULL);

} /* end of static char * set_modff_enable () */



static const char * set_modff_extended (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_extended (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_extended);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->extended = FF_ENABLE;
	ff_any_extended = 1;
    } else {
	conf->extended = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_extended () */



static const char * set_modff_cleanup (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_cleanup (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_cleanup);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->cleanup = FF_ENABLE;
    } else {
	conf->cleanup = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_cleanup () */


static const char * set_modff_verbose (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_verbose (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_verbose);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->verbose = FF_ENABLE;
	ff_any_verbose = 1;
    } else {
	conf->verbose = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_verbose () */



static const char * set_modff_verbose_postmortem (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_verbose_postmortem (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_verbose_postmortem);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->verbose_postmortem = FF_ENABLE;
    } else {
	conf->verbose_postmortem = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_verbose_postmortem () */




static const char * set_modff_resetexit (cmd_parms *params, void *vconf, const char *what);
static const char * 
set_modff_resetexit (cmd_parms *params, void *vconf, const char *what)
{
    __FUNC(set_modff_resetexit);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (strcasecmp (what, "all") == 0)
    {
        init_threshold (&(conf->exit_request));
        init_threshold (&(conf->exit_child));
        init_threshold (&(conf->exit_idle));
        init_threshold (&(conf->exit_session));
        init_threshold (&(conf->exit_internal));
        
	return ((char *) NULL);
    }

    if ((strcasecmp(what, "request") == 0)  || (strcasecmp (what, "delta") == 0))
    {
        init_threshold (&(conf->exit_request));

	return ((char *) NULL);
    }

    if (strcasecmp (what, "idle") == 0)
    {
        init_threshold (&(conf->exit_idle));

	return ((char *) NULL);
    }

    if (strcasecmp (what, "session") == 0)
    {
        init_threshold (&(conf->exit_session));

	return ((char *) NULL);
    }

    if (strcasecmp (what, "internal") == 0)
    {
        init_threshold (&(conf->exit_internal));

	return ((char *) NULL);
    }

    if ((strcasecmp(what, "child") == 0) || (strcasecmp (what, "max") == 0))
    {
        init_threshold (&(conf->exit_child));

	return ((char *) NULL);
    }

    return "Invalid reset exit parameter";

} /* end of set_modff_resetexit () */


static const char * set_modff_resetwarn (cmd_parms *params, void *vconf, const char *what);
static const char * 
set_modff_resetwarn (cmd_parms *params, void *vconf, const char *what)
{
    __FUNC(set_modff_resetwarn);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (strcasecmp (what, "all") == 0)
    {
        init_threshold (&(conf->warn_request));
        init_threshold (&(conf->warn_child));
        init_threshold (&(conf->warn_idle));
        init_threshold (&(conf->warn_session));
        init_threshold (&(conf->warn_internal));
        
	return ((char *) NULL);
    }

    if ((strcasecmp (what, "request") == 0) || (strcasecmp (what, "delta") == 0))
    {
        init_threshold (&(conf->warn_request));

	return ((char *) NULL);
    }

    if (strcasecmp (what, "idle") == 0)
    {
        init_threshold (&(conf->warn_idle));

	return ((char *) NULL);
    }

    if (strcasecmp (what, "internal") == 0)
    {
        init_threshold (&(conf->warn_internal));

	return ((char *) NULL);
    }

    if (strcasecmp (what, "session") == 0)
    {
        init_threshold (&(conf->warn_session));

	return ((char *) NULL);
    }

    if ((strcasecmp (what, "child") == 0) || (strcasecmp (what, "max") == 0))
    {
        init_threshold (&(conf->warn_child));

	return ((char *) NULL);
    }

    return "Invalid reset warn parameter";

} /* end of set_modff_resetwarn () */



static const char * set_modff_watch (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_watch (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_watch);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->watchrequest = FF_ENABLE;
        conf->watchchild = FF_ENABLE;
        conf->watchsession = FF_ENABLE;
	/*
	 * Don't do these unless we can verify that this is at the Apache host config level.
	 *
	 conf->watchidle = FF_ENABLE;
	 conf->watchinternal = FF_ENABLE;
	*/

    } else {
	conf->watchrequest = FF_DISABLE;
	conf->watchchild = FF_DISABLE;
        conf->watchsession = FF_ENABLE;
	/*
	 * Don't do these unless we can verify that this is at the Apache host config level
	 *
	 conf->watchidle = FF_DISABLE;
	 conf->watchinternal = FF_DISABLE;
	*/
    }

    return ((char *) NULL);

} /* end of static char * set_modff_watch () */


static const char * set_modff_watchrequest (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_watchrequest (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_watchrequest);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->watchrequest = FF_ENABLE;
    } else {
	conf->watchrequest = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_watchrequest () */


static const char * set_modff_watchidle (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_watchidle (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_watchidle);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->watchidle = FF_ENABLE;
    } else {
	conf->watchidle = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_watchidle () */


static const char * set_modff_check_overhead_idle (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_check_overhead_idle (cmd_parms *params, void *vconf, const char *str)
{
    __FUNC(set_modff_check_overhead_idle);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int flag = ff_getflag (str);

    if (flag >= 0) {
        conf->overhead_idle = flag;
	if (ENABLED(conf,overhead_idle))
	  ff_any_checkoverhead = 1;

    } else {
        return "Must be ON (yes, ok, true), OFF (no, false), or FULL (long, all)";
    }

    return ((char *) NULL);

} /* end of static char * set_modff_check_overhead_idle () */


static const char * set_modff_exitidle (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_exitidle (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_exiidle);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->exit_idle), 
				FF_DIRECTIVE_PFX "ExitIdle", item, siz);

} /* end of set_modff_exitidle() */


static const char * set_modff_warnidle (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_warnidle (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_warnidle);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->warn_idle),
				FF_DIRECTIVE_PFX "WarnIdle", item, siz);

} /* end of set_modff_warnidle() */


static const char * set_modff_watchinternal (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_watchinternal (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_watchinternal);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->watchinternal = FF_ENABLE;
    } else {
	conf->watchinternal = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_watchinternal () */


static const char * set_modff_check_overhead_internal (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_check_overhead_internal (cmd_parms *params, void *vconf, const char *str)
{
    __FUNC(set_modff_check_overhead_internal);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int flag = ff_getflag (str);

    if (flag >= 0) {
        conf->overhead_internal = flag;
	if (ENABLED(conf,overhead_internal))
	  ff_any_checkoverhead = 1;

    } else {
        return "Must be ON (yes, ok, true), OFF (no, false), or FULL (long, all)";
    }

    return ((char *) NULL);

} /* end of static char * set_modff_check_overhead_internal () */


static const char * set_modff_exitinternal (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_exitinternal (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_exitinternal);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->exit_internal), 
				FF_DIRECTIVE_PFX "ExitInternal", item, siz);

} /* end of set_modff_exitinternal() */


static const char * set_modff_warninternal (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_warninternal (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_warnnternal);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->warn_internal),
				FF_DIRECTIVE_PFX "WarnInternal", item, siz);

} /* end of set_modff_warninternal() */


static const char * set_modff_watchsession (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_watchsession (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_watchsession);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->watchsession = FF_ENABLE;
    } else {
	conf->watchsession = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_watchsession () */



static const char * set_modff_check_overhead_session (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_check_overhead_session (cmd_parms *params, void *vconf, const char *str)
{
    __FUNC(set_modff_check_overhead_session);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int flag = ff_getflag (str);

    if (flag >= 0) {
        conf->overhead_session = flag;
	if (ENABLED(conf,overhead_session))
	  ff_any_checkoverhead = 1;

    } else {
        return "Must be ON (yes, ok, true), OFF (no, false), or FULL (long, all)";
    }

    return ((char *) NULL);

} /* end of static char * set_modff_check_overhead_session () */


static const char * set_modff_exitsession (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_exitsession (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_exitsession);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->exit_session), 
				FF_DIRECTIVE_PFX "ExitSession", item, siz);

} /* end of set_modff_exitsession() */



static const char * set_modff_warnsession (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_warnsession (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_warnsession);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->warn_session),
				FF_DIRECTIVE_PFX "WarnSession", item, siz);

} /* end of set_modff_warnsession() */



static const char * set_modff_watchchild (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_watchchild (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_watchchild);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
        conf->watchchild = FF_ENABLE;
    } else {
	conf->watchchild = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_watchchild () */


static const char * set_modff_log_main (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_log_main (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_log_main);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->log_main = FF_ENABLE;
    } else {
	conf->log_main = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_log_main () */



static const char * set_modff_do_loopback (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_do_loopback (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_do_loopback);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->do_loopback = FF_ENABLE;
    } else {
	conf->do_loopback = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_do_loopback () */



static const char * set_modff_do_remote_tcpport (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_do_remote_tcpport (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_do_remote_tcpport);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->do_remote_tcpport = FF_ENABLE;
    } else {
	conf->do_remote_tcpport = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_do_remote_tcpport () */



static const char * set_modff_do_internal (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_do_internal (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_do_internal);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->do_internal = FF_ENABLE;
    } else {
	conf->do_internal = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_do_internal () */



static const char * set_modff_debug_procinfo (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_debug_procinfo (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_debug_procinfo);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->debug_procinfo = FF_ENABLE;
    } else {
	conf->debug_procinfo = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_debug_procinfo () */



static const char * set_modff_debug_config (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_debug_config (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_debug_config);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->debug_config = FF_ENABLE;
    } else {
	conf->debug_config = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_debug_config () */



static const char * set_modff_debug_position (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_debug_position (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_debug_position);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->debug_position = FF_ENABLE;
    } else {
	conf->debug_position = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_debug_position () */




static const char * set_modff_dump_env (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_dump_env (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_dump_env);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->dump_env = FF_ENABLE;
    } else {
	conf->dump_env = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_dump_env () */





static const char * set_modff_dump_headers (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_dump_headers (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_dump_headers);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->dump_headers = FF_ENABLE;
    } else {
	conf->dump_headers = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_dump_headers () */




static const char * set_modff_debug_session (cmd_parms *params, void *vconf, int flag);
static const char *
set_modff_debug_session (cmd_parms *params, void *vconf, int flag)
{
    __FUNC(set_modff_debug_session);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (flag) {
	conf->debug_session = FF_ENABLE;
    } else {
	conf->debug_session = FF_DISABLE;
    }

    return ((char *) NULL);

} /* end of static char * set_modff_debug_session () */




static const char * set_modff_check_overhead (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_check_overhead (cmd_parms *params, void *vconf, const char *str)
{
  __FUNC(set_modff_check_overhead);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int flag = ff_getflag (str);

    if (flag >= 0) {
	conf->overhead_request = flag;
	conf->overhead_child = flag;
	conf->overhead_session = flag;
	conf->overhead_idle = flag;
	conf->overhead_internal = flag;

	ff_any_checkoverhead = 1;

    } else {
        return "Must be ON (yes, ok, true), OFF (no, false), or FULL (long, all)";
    }

    return ((char *) NULL);

} /* end of static char * set_modff_check_overhead () */




static const char * set_modff_check_overhead_request (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_check_overhead_request (cmd_parms *params, void *vconf, const char *str)
{
    __FUNC(set_modff_overhead_request);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int flag = ff_getflag (str);

    if (flag > 0) {
        conf->overhead_request = flag;
	if (ENABLED(conf,overhead_request)) 
	  ff_any_checkoverhead = 1;

    } else {
        return "Must be ON (yes, ok, true), OFF (no, false), or FULL (long, all)";
    }

    return ((char *) NULL);

} /* end of static char * set_modff_check_overhead_request () */



static const char * set_modff_check_overhead_child (cmd_parms *params, void *vconf, const char *str);
static const char *
set_modff_check_overhead_child (cmd_parms *params, void *vconf, const char *str)
{
    __FUNC(set_modff_overhead_child);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int flag = ff_getflag (str);


    if (flag >= 0) {
        conf->overhead_child = flag;
	if (ENABLED(conf,overhead_child))
	  ff_any_checkoverhead = 1;

    } else {
        return "Must be ON (yes, ok, true), OFF (no, false), or FULL (long, all)";
    }

    return ((char *) NULL);

} /* end of static char * set_modff_check_overhead_child () */







static const char * set_modff_suppress_child_overhead (cmd_parms *params, void *vconf, const char *val);
static const char *
set_modff_suppress_child_overhead (cmd_parms *params, void *vconf, const char *val)
{
    __FUNC(set_modff_suppress_child_overhead);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    long num;
    char *errmsg = (char *) NULL;

    num = strtol (val, &errmsg, 0);

    if (errmsg && (*errmsg == '\0') && (num >= 0))
    {
        conf->suppress_child_overhead = num;
	return ((char *) NULL);
    }

    return FF_DIRECTIVE_PFX "SuppressChildOverhead - not a number";

} /* end of static char * set_modff_suppress_child_overhead () */





static const char * set_modff_max_requests_per_child (cmd_parms *params, void *vconf, const char *val);
static const char *
set_modff_max_requests_per_child (cmd_parms *params, void *vconf, const char *val)
{
    __FUNC(set_modff_max_requests_per_child);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    long num;
    char *errmsg = (char *) NULL;

    num = strtol (val, &errmsg, 0);

    if (errmsg && (*errmsg == '\0') && (num >= 0))
    {
        conf->max_requests_per_child = num;
	return ((char *) NULL);
    }

    return FF_DIRECTIVE_PFX "MaxRequestsPerChild - not a number";

} /* end of static char * set_modff_max_requests_per_child () */





static const char * set_modff_max_requests_per_session (cmd_parms *params, void *vconf, const char *val);
static const char *
set_modff_max_requests_per_session (cmd_parms *params, void *vconf, const char *val)
{
    __FUNC(set_modff_max_requests_per_session);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    long num;
    char *errmsg = (char *) NULL;

    num = strtol (val, &errmsg, 0);

    if (errmsg && (*errmsg == '\0') && (num >= 0))
    {
        conf->max_requests_per_session = num;
	return ((char *) NULL);
    }

    return FF_DIRECTIVE_PFX "MaxRequestsPerSession - not a number";

} /* end of static char * set_modff_max_requests_per_session () */




static const char * set_modff_procfs (cmd_parms *params, void *vconf, const char *procfs);
static const char *
set_modff_procfs (cmd_parms *params, void *vconf, const char *procfs)
{
    __FUNC(set_modff_procfs);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    struct stat procstat;

    if (stat(procfs, &procstat) != 0)
    {
        return "Does not exist";
    }

    if (! S_ISDIR(procstat.st_mode))
    {
        return "Not a directory";
    }

    conf->pfx = apr_pstrdup (params->pool, procfs);

    return ((char *) NULL);

} /* end of set_modff_procfs() */



static const char * set_modff_ignore_status (cmd_parms *params, void *vconf, const char *ignore_status);
static const char *
set_modff_ignore_status (cmd_parms *params, void *vconf, const char *ignore_status)
{
    __FUNC(set_modff_ignore_status);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    int i;		/* 'i' is ALWAYS a loop index!  FORTRAN lives!  */ 
    long num;
    char *errmsg = (char *) NULL;
    static int drops_con[] =
      {
	HTTP_BAD_REQUEST,
	HTTP_REQUEST_TIME_OUT, 
	HTTP_LENGTH_REQUIRED,
	HTTP_REQUEST_ENTITY_TOO_LARGE,
	HTTP_REQUEST_URI_TOO_LARGE,
	HTTP_INTERNAL_SERVER_ERROR,
	HTTP_SERVICE_UNAVAILABLE,
	HTTP_NOT_IMPLEMENTED,

	/* END OF LIST */
	-1
      };

    if (strcasecmp (ignore_status, "none") == 0)
    {
	conf->ignore_status = (intlist_t *) NULL;	/* Let Apache APR clean up any messes. */
	conf->defined_ignore_status = FF_DISABLE;
    }

    else if (strcasecmp (ignore_status, "connection-drops") == 0)
    {
	conf->defined_ignore_status = FF_ENABLE;
	/* See macro 'ap_status_drops_connection()' in 'httpd.h' */
	for (i=0; drops_con[i] != -1; i++)
	{
	    (void) intlist_insert (params->pool, &(conf->ignore_status), 1, drops_con[i]);
	}
    }

    else 
    {
	/* Deal with as a number. */
	num = strtol (ignore_status, &errmsg, 0);
	if (errmsg && (*errmsg == '\0')) 
	{
	    if (ap_is_HTTP_VALID_RESPONSE(num) |  ap_is_HTTP_VALID_RESPONSE(-num))
	    {
	        if (num < 0)
		{
		    (void) intlist_delete (&(conf->ignore_status), 1, -num);
		}
		else
		{
		    (void) intlist_insert (params->pool, &(conf->ignore_status), 1, num);
		}
		conf->defined_ignore_status = FF_ENABLE;
	    }
	    else
	    {
		return FF_DIRECTIVE_PFX "IgnoreStatus - Number not in valid range 100..599";
	    }
	}

	else
	{
	    return FF_DIRECTIVE_PFX "IgnoreStatus - not NONE, CONNECTION-DROPS, or a number";
	}
    }

    return ((char *) NULL);

} /* end of set_modff_ignore_status() */



static const char * set_modff_remote_ip_sources (cmd_parms *params, void *vconf,
						 const char *remote_ip_sources);
static const char *
set_modff_remote_ip_sources (cmd_parms *params, void *vconf, const char *remote_ip_sources)
{
    __FUNC(set_modff_remote_ip_sources);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (strcasecmp (remote_ip_sources, "none") == 0)
    {
	conf->remote_ip_sources = (strlist_t *) NULL;	/* Let Apache APR clean up any messes. */
	conf->defined_remote_ip_sources = FF_DISABLE;
	
	return ((char *) NULL);
    }


    /* Simple minded sanity checking. */
    switch (*remote_ip_sources) {
    case '@':
      /* ABSOLUTE values in 'conn_rec', etc. */
      if (strcasecmp (remote_ip_sources, "@remote_ip") != 0)
	  return ("Not a valid (conn_rec) source");

      break;

       
    case '+':  /* First header value */
    case '-':  /* Last header value */
      if (*(remote_ip_sources+1) == '\0')
	  return ("HTTP Header values must be named");

      break;


    case '$':  /* Environment variable */
      if (*(remote_ip_sources+1) == '\0')
	  return ("Environment variables must be named");
	  
      break;
	

    default:
        return ("Not a valid source");

    } /* switch (*remote_ip_sources) */

    conf->defined_remote_ip_sources = FF_ENABLE;
    (void) strlist_insert (params->pool, &(conf->remote_ip_sources), 0, remote_ip_sources);

    return ((char *) NULL);

} /* end of set_modff_remote_ip_sources() */


static const char * set_modff_label (cmd_parms *params, void *vconf, const char *label);
static const char *
set_modff_label (cmd_parms *params, void *vconf, const char *label)
{
    __FUNC(set_modff_label);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (conf->labelid)
    {
	ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
		      "%s: Changing label from '%s' to '#%d<%s>'",
		      ff_module.name, ff_labelid (conf), 
		      conf->id, label);
    }
    else
    {
	ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
		      "%s: Setting label to '#%d<%s>'",
		      ff_module.name, conf->id, label);
    }

    conf->labelid = apr_pstrdup (params->pool, label);

    return ((char *) NULL);

} /* end of set_modff_label() */




static const char * set_modff_timefmt (cmd_parms *params, void *vconf, const char *timefmt);
static const char *
set_modff_timefmt (cmd_parms *params, void *vconf, const char *timefmt)
{
    __FUNC(set_modff_timefmt);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    conf->timefmt = apr_pstrdup (params->pool, timefmt);

    return ((char *) NULL);

} /* end of set_modff_timefmt() */



static const char * set_modff_session_cookie_name (cmd_parms *params, void *vconf, const char *session_cookie_name);
static const char *
set_modff_session_cookie_name (cmd_parms *params, void *vconf, const char *session_cookie_name)
{
    __FUNC(set_modff_session_cookie_name);
    modff_config_t *conf = ff_find_config (_func, params, vconf);

    if (strcasecmp(session_cookie_name, "none") == 0)
    {
        session_cookie_name = ""; /* Not the same as FF_UNSET */
    }

    conf->session_cookie_name = apr_pstrdup (params->pool,session_cookie_name);

    return ((char *) NULL);

} /* end of set_modff_session_cookie_name() */


  
static const char * set_modff_exitchild (cmd_parms *params, void *vconf, const char *item, const char *siz);

static const char *
set_modff_exitchild (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_exitchild);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->exit_child),
				FF_DIRECTIVE_PFX "ExitChild", item, siz);

} /* end of set_modff_exitchild() */


static const char * set_modff_warnchild (cmd_parms *params, void *vconf, const char *item, const char *siz);

static const char *
set_modff_warnchild (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_warnchild);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->warn_child),
				FF_DIRECTIVE_PFX "WarnChild", item, siz);

} /* end of set_modff_warnchild() */



static const char * set_modff_exitrequest (cmd_parms *params, void *vconf, const char *item, const char *siz);
static const char *
set_modff_exitrequest (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_exitrequest);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->exit_request),
				FF_DIRECTIVE_PFX "ExitRequest", item, siz);

} /* end of set_modff_exitrequest() */


static const char * set_modff_warnrequest (cmd_parms *params, void *vconf, const char *item, const char *siz);

static const char *
set_modff_warnrequest (cmd_parms *params, void *vconf, const char *item, const char *siz)
{
    __FUNC(set_modff_warnrequest);
    modff_config_t *conf = ff_find_config (_func, params, vconf);
    static char errmsg[1024];

    return set_modff_threshold (errmsg, sizeof(errmsg), params, conf, &(conf->warn_request),
				FF_DIRECTIVE_PFX "WarnRequest", item, siz);

} /* end of set_modff_warnrequest() */



static const command_rec mod_ff_cmds[] =
{
        AP_INIT_TAKE1(    /* [0] */
		FF_DIRECTIVE_PFX "CheckOverhead",
		set_modff_check_overhead,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "CheckOverhead [on|OFF|full] --  Log how much time we spend checking Child, " _IDLE_COMMA _SESSION_COMMA _INTERNAL_COMMA" & Request"    
	),

        AP_INIT_TAKE1(    /* [1] */
		FF_DIRECTIVE_PFX "CheckOverheadRequest",
		set_modff_check_overhead_request,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "CheckOverheadRequest [on|OFF|full] -- Log how much time we spend checking Request"    
	 ),

        AP_INIT_TAKE1(    /* [2] */
		FF_DIRECTIVE_PFX "CheckOverheadIdle",
		set_modff_check_overhead_idle,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "CheckOverheadIdle [on|OFF|full] -- Log how much time we spend checking Idle"    
	),

        AP_INIT_TAKE1(    /* [3] */
		FF_DIRECTIVE_PFX "CheckOverheadInternal",
		set_modff_check_overhead_internal,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "CheckOverheadInternal [on|OFF|full] -- Log how much time we spend checking Internal"    
	),

        AP_INIT_TAKE1(    /* [4] */
		FF_DIRECTIVE_PFX "CheckOverheadSession",
		set_modff_check_overhead_session,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "CheckOverheadSession [on|OFF|full] -- Log how much time we spend checking Session"    
	),

        AP_INIT_TAKE1(    /* [5] */
		FF_DIRECTIVE_PFX "CheckOverheadChild",
		set_modff_check_overhead_child,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "CheckOverheadChild [on|OFF|full] -- Log how much time we spend checking Child"    
	),

	AP_INIT_FLAG( /* [6] */
		FF_DIRECTIVE_PFX "Cleanup",
		set_modff_cleanup,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "Cleanup [on|OFF] --  Release /proc/self/.. file descriptors after each sample"
	),

	AP_INIT_TAKE1( /* [7] */
		FF_DIRECTIVE_PFX "Enable",
		set_modff_enable,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "Enable [on|OFF] --  Enable or disable FF (Weight Watchers) checking (exclusive of DUMPHEADERS)."
	),

	AP_INIT_FLAG( /* [8] */
		FF_DIRECTIVE_PFX "Extended",
		set_modff_extended,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "Extended [on|OFF] --  Enable or disable heavier weight checking about file descriptors."
	),

	AP_INIT_TAKE1( /* [9] */
		FF_DIRECTIVE_PFX "IgnoreStatus",
		set_modff_ignore_status,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "IgnoreStatus [NONE|Connection-Drops|<number>] -- Ignore requests with these status codes"
	),


	AP_INIT_TAKE1( /* [10] */
		FF_DIRECTIVE_PFX "RemoteIpSource",
		set_modff_remote_ip_sources,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "RemoteIpSource [NONE|@remote_ip|{+|-}<header>|$<env_variable>] -- Look here for 'soure ip address' when for matching"
	),

	AP_INIT_TAKE1( /* [11] */
		FF_DIRECTIVE_PFX "Label",
		set_modff_label,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "Label <word> -- Word to label this definition with (not implemented)"
	),

	AP_INIT_FLAG( /* [12] */
		FF_DIRECTIVE_PFX "LogMain",
		set_modff_log_main,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "LogMain [on|Off] --  Enable or disable FF (Weight Watchers) logging to default vhost"
	),

	AP_INIT_FLAG( /* [13] */
		FF_DIRECTIVE_PFX "LoopBack",
		set_modff_do_loopback,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "LoopBack [ON|off] --  Enable or disable FF (Weight Watchers) checking on loopback ([127.0.0.1] or [::1]) requests."
	),


	AP_INIT_FLAG( /* [14] */
		FF_DIRECTIVE_PFX "RemoteTcpPort",
		set_modff_do_remote_tcpport,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "RemoteTcpPort [Off|on] --  Enable or disable FF (Weight Watchers) checking on remote_tcpport when checking for sameness of requests."
	),


	AP_INIT_FLAG( /* [15] */
		FF_DIRECTIVE_PFX "Internal",
		set_modff_do_internal,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "Internal [on|Off] --  Enable or disable FF (Weight Watchers) checking on internal requests."
	),


	AP_INIT_FLAG( /* [16] */
		FF_DIRECTIVE_PFX "DebugProcinfo",
		set_modff_debug_procinfo,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "DebugProcinfo [ON|OFF] --  Enable or disable debugging of extended fd lists."
	),


	AP_INIT_FLAG( /* [17] */
		FF_DIRECTIVE_PFX "DebugConfig",
		set_modff_debug_config,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "DebugConfig [ON|OFF] --  Enable or disable debugging of configuration management."
	),


	AP_INIT_FLAG( /* [18] */
		FF_DIRECTIVE_PFX "DebugPosition",
		set_modff_debug_position,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "DebugPosition [ON|OFF] --  Enable or disable debugging of position management"
	),



	AP_INIT_FLAG( /* [19] */
		FF_DIRECTIVE_PFX "DumpEnv",
		set_modff_dump_env,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "DumpEnv [ON|OFF] --  Enable or disable dumping of GET/POST values to error log (independent of ENABLE)"
	),



	AP_INIT_FLAG( /* [20] */
		FF_DIRECTIVE_PFX "DumpHeaders",
		set_modff_dump_headers,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "DumpHeaders [ON|OFF] --  Enable or disable dumping of headers to error log (independent of ENABLE)"
	),



	AP_INIT_FLAG( /* [21] */
		FF_DIRECTIVE_PFX "DebugSession",
		set_modff_debug_session,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "DebugSession [ON|OFF] --  Enable or disable debugging of session management"
	),


	AP_INIT_TAKE1( /* [22] */
		FF_DIRECTIVE_PFX "ProcFS",
		set_modff_procfs,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ProcFS <pathname> -- '/proc' or '/compat/linux/proc' equivalent"
	),

	AP_INIT_TAKE1( /* [23] */
		FF_DIRECTIVE_PFX "SuppressChildOverhead",
		set_modff_suppress_child_overhead,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "SuppressChildOverhead [<number>] -- Ignore this many messages when child overhead doesn't change"
	),


	AP_INIT_TAKE1( /* [24] */
		FF_DIRECTIVE_PFX "MaxRequestsPerChild",
		set_modff_max_requests_per_child,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "MaxRequestsPerChild <number> -- Exit after this many requests for this child"
	),


	AP_INIT_TAKE1( /* [25] */
		FF_DIRECTIVE_PFX "MaxRequestsPerSession",
		set_modff_max_requests_per_session,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "MaxRequestsPerSession <number> -- Exit after this many requests per. session"
	),


	AP_INIT_TAKE1( /* [26] */
		FF_DIRECTIVE_PFX "TimeFmt",
		set_modff_timefmt,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "TimeFmt <word> --strftime format for time/date conversions"
	),


	AP_INIT_TAKE1( /* [27] */
		FF_DIRECTIVE_PFX "SessionCookieName",
		set_modff_session_cookie_name,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "SessionCookieName <word> -- web cookie name to use to match session sameness"
	),

	AP_INIT_FLAG( /* [28] */
		FF_DIRECTIVE_PFX "Verbose",
		set_modff_verbose,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "Verbose [on|OFF] --  Show zero values too"
	),

	AP_INIT_FLAG( /* [29] */
		FF_DIRECTIVE_PFX "VerbosePostmortem",
		set_modff_verbose_postmortem,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "VerbosePostmortem [on|OFF] --  Show zero values on 'Postmortem' reports"
	),

	AP_INIT_FLAG( /* [305] */
		FF_DIRECTIVE_PFX "Watch",
		set_modff_watch,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "Watch [on|OFF] --  Show stat info for all of Child, " _IDLE_COMMA _SESSION_COMMA _INTERNAL_COMMA " and Request" 
	),


	AP_INIT_FLAG( /* [31] */
		FF_DIRECTIVE_PFX "WatchRequest",
		set_modff_watchrequest,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "WatchRequest [on|Off] --  Show Request stat info" 
	),

	AP_INIT_FLAG( /* [32] */
		FF_DIRECTIVE_PFX "WatchIdle",
		set_modff_watchidle,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "WatchIdle [on|Off] --  Show idle stat info" 
	),

	AP_INIT_FLAG( /* [33] */
		FF_DIRECTIVE_PFX "WatchInternal",
		set_modff_watchinternal,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "WatchInternal [on|Off] --  Show internal stat info" 
	),

	AP_INIT_FLAG( /* [34] */
		FF_DIRECTIVE_PFX "WatchSession",
		set_modff_watchsession,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "WatchSession [on|Off] --  Show session stat info" 
	),

	AP_INIT_FLAG( /* [35] */
		FF_DIRECTIVE_PFX "WatchChild",
		set_modff_watchchild,
		NULL,
		RSRC_CONF, 
		FF_DIRECTIVE_PFX "WatchChild [on|Off] --  Show Child stat info" 
	),


	AP_INIT_TAKE1( /* [36] */
		FF_DIRECTIVE_PFX "ResetWarn",
		set_modff_resetwarn,
		NULL,
		RSRC_CONF | ACCESS_CONF,
		FF_DIRECTIVE_PFX "ResetWarn [All|Child|" _IDLE_OR _SESSION_OR _INTERNAL_OR "Request] - Reset these thresholds to defaults"
	),

	AP_INIT_TAKE1( /* [37] */
		FF_DIRECTIVE_PFX "ResetExit",
		set_modff_resetexit,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ResetExit [All|Child|" _IDLE_OR _SESSION_OR _INTERNAL_OR "Request] - Reset these thresholds to defaults"
	),

	AP_INIT_TAKE2( /* [38] */
		FF_DIRECTIVE_PFX "ExitRequest",
		set_modff_exitrequest,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ExitRequest [" _THRESHOLDS "] <value> -- Set the trigger to exit on delta."
	),
	
	AP_INIT_TAKE2( /* [38] */
		FF_DIRECTIVE_PFX "WarnRequest",
		set_modff_warnrequest,
		NULL,
		RSRC_CONF | ACCESS_CONF /* |  OR_OPTIONS */ ,
		FF_DIRECTIVE_PFX "Warnrequest [" _THRESHOLDS "] <value> -- Set the trigger to warn on delta."
	),


	AP_INIT_TAKE2( /* [40] */
		FF_DIRECTIVE_PFX "ExitChild",
		set_modff_exitchild,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ExitChild [" _THRESHOLDS "] <value> -- Set the trigger to exit on max."
	),
	
	AP_INIT_TAKE2( /* [41] */
		FF_DIRECTIVE_PFX "WarnChild",
		set_modff_warnchild,
		NULL,
		RSRC_CONF | ACCESS_CONF /* | OR_OPTIONS */,
		FF_DIRECTIVE_PFX "WarnChild [" _THRESHOLDS "] <value> -- Set the trigger to warn on max."
	),
	
	AP_INIT_TAKE2( /* [42] */
		FF_DIRECTIVE_PFX "ExitIdle",
		set_modff_exitidle,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ExitIdle [" _THRESHOLDS "] <value> -- Set the trigger to exit on idle."
	),
	
	AP_INIT_TAKE2( /* [43] */
		FF_DIRECTIVE_PFX "WarnIdle",
		set_modff_warnidle,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "WarnIdle [" _THRESHOLDS "] <value> -- Set the trigger to warn on idle."
	),


	AP_INIT_TAKE2( /* [44] */
		FF_DIRECTIVE_PFX "ExitInternal",
		set_modff_exitinternal,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ExitInternal [" _THRESHOLDS "] <value> -- Set the trigger to exit on internal."
	),
	
	AP_INIT_TAKE2( /* [45] */
		FF_DIRECTIVE_PFX "WarnInternal",
		set_modff_warninternal,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "WarnInternal [" _THRESHOLDS "] <value> -- Set the trigger to warn on internal."
	),


	AP_INIT_TAKE2( /* [46] */
		FF_DIRECTIVE_PFX "ExitSession",
		set_modff_exitsession,
		NULL,
		RSRC_CONF,
		FF_DIRECTIVE_PFX "ExitSession [" _THRESHOLDS "] <value> -- Set the trigger to exit on session."
	),
	
	AP_INIT_TAKE2( /* [47] */
		FF_DIRECTIVE_PFX "WarnSession",
		set_modff_warnsession,
		NULL,
		RSRC_CONF | ACCESS_CONF /* | OR_OPTIONS */ ,
		FF_DIRECTIVE_PFX "WarnSession [" _THRESHOLDS "] <value> -- Set the trigger to warn on session."
	),

	
	/* end of list */
	{NULL}

}; /* end of static const command_rec mod_ff_cmds[] */


/*
 * Declare and populate the module's data structure.  The
 * name of this structure ('ff_module') is important - it
 * must match the name of the module.  This structure is the
 * only "glue" between the httpd core and the module.
 */
module AP_MODULE_DECLARE_DATA ff_module =
{
	STANDARD20_MODULE_STUFF,/* standard stuff; no need to mess with this. */
	ff_create_dir_config,	/* create per-directory configuration structures */
	ff_merge_dir_config,	/* merge per-directory */
	ff_create_server_config,/* create per-server configuration structures. */
	ff_merge_server_config,	/* merge per-server */
	mod_ff_cmds,		/* configuration directive handlers */
	mod_ff_register_hooks,  /* request handlers */
};
