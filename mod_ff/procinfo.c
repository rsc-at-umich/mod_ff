/*
	Copyright 2012-2013 by the Regents of the University of Michigan

	All Rights Reserved
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>

#include "utility.h"
#include "procinfo.h"


/* Internal function prototypes */

static proc_fd_info_list_t *new_list (proc_fd_info_list_t **p_list,
				      unsigned short size);

static proc_fd_info_t * new_in_list (proc_fd_info_list_t **p_list,
				     proc_fd_info_t *src,
				     unsigned short list_size,
				     int copy_or_move);

static proc_fd_info_t *copy_fd_info (proc_fd_info_t *dest,
				     proc_fd_info_t *src,
				     int copy_or_move);

static proc_fd_info_t * proc_fd_info__in__proc_fd_info_list (const proc_fd_info_t *pfi,
							     proc_fd_info_list_t *list);

static int log_debug (int level, const char *fmt, ...);

/*
 * Counters for the portmortem_xxx() structures.
 */

alloc_free_count_t counter_proc_fd_info;
alloc_free_count_t counter_proc_fd_info__pathstr;
alloc_free_count_t counter_proc_fd_info_list;

/*
 * When we're doing log hooking
 */

static void *log_debug_hook_context = (void *) NULL;
static vfprintf_like_log_hook_t log_debug_hook_func = (vfprintf_like_log_hook_t) NULL;
static int log_debug_hook_level = 0;

/*
 * #define DEBUG(args) printf args
 */
#define DEBUG(args)


/* Procedure definitions */

int
proc_fd_info_log_debug_hook_register (void *context, vfprintf_like_log_hook_t logfunc, int level)
{
    __FUNC(proc_fd_info_log_hook_register);

    log_debug_hook_context = context;
    log_debug_hook_func = logfunc;
    log_debug_hook_level = level;

    return (0);

} /* end of proc_fd_info_log_hook_register() */

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



char *
postmortem_proc_fd_info (char *buffer, size_t bufflen, long long expected_fd, 
			 long long expected_fd_path, int pedantic)
{
    int len;
    char *pos;
    char *tmp;
    char tmp_buff[64];


    if (!buffer || (bufflen < 10))
    {
        return (buffer);
    }
    
    *buffer = '\0';

    pos = postmortem_alloc_free (buffer, bufflen, &counter_proc_fd_info, expected_fd,
				 "proc_fd_info", pedantic);
    
    tmp_buff[0] = '\0';
    tmp = postmortem_alloc_free (tmp_buff, sizeof(tmp_buff), &counter_proc_fd_info__pathstr,
				 expected_fd_path, "proc_fd_info.path", pedantic);
    
    if (*tmp)
    {
    	len = strlen (pos);
	pos += len;
	bufflen -= len;

	snprintf (pos, bufflen, "%s%s", (len > 0 ? ", " : ""), tmp);
    }

    /* Don't need to reposition at end. */

    return (buffer);

} /* end of postmortem_proc_fd_info() */


char *
postmortem_proc_fd_info_list (char *buffer, size_t bufflen, long long expected_list,
			      long long expected_fd, long long expected_fd_path, int pedantic)
{
    char *pos;
    int len;
    char *tmp;
    char tmp_buff[128];

    if (!buffer || (bufflen < 10))
    {
        return (buffer);
    }
    
    *buffer = '\0';

    pos = postmortem_alloc_free (buffer, bufflen, &counter_proc_fd_info_list, expected_list,
				 "proc_fd_info_list",  pedantic);
    
    tmp_buff[0] = '\0';
    tmp = postmortem_proc_fd_info (tmp_buff, sizeof(tmp_buff), expected_fd, expected_fd_path,
				   pedantic);

    if (*tmp)
    {
    	len = strlen (pos);
	pos += len;
	bufflen -= len;

	snprintf (pos, bufflen, "%s%s", (len > 0 ? ", " : ""), tmp);
    }

    /* Don't need to reposition at end. */

    return (buffer);
    
} /* end of postmortem_proc_fd_info_list() */

#define P_COUNT(_p_ctr) 			\
  if ((_p_ctr) != (long long *) NULL) {		\
    if (*(_p_ctr) == -1) { *(_p_ctr) = 0; }	\
    *(_p_ctr) += 1;				\
    }

void 
count_proc_fd_info (const proc_fd_info_t *pfi, COUNT_PROC_FD_INFO_PROTO_ARGS)
{
    if (pfi == (proc_fd_info_t *) NULL)
        return;

    if (pfi->mine)
    {
        P_COUNT(p_fd_info);
    }

    if (pfi->path)
    {
        P_COUNT(p_fd_info__path);
    }

    return;

} /* end of count_proc_fd_info() */


void
count_proc_fd_info_list (const proc_fd_info_list_t *pfil, COUNT_PROC_FD_INFO_LIST_PROTO_ARGS)
{
    /* Don't bother countin' if we've no place to count */
    if ((p_fd_info__path == (long long *) NULL) &&
	(p_fd_info_list == (long long *) NULL))
        return;
    /* For loop won't count if we got nothin' to count. */
    for (; pfil != (proc_fd_info_list_t *) NULL; pfil = pfil->next)
    {
        int i;		/* Loop index.  FORTRAN forever and for always */
	
	P_COUNT(p_fd_info_list);

	for (i = 0; i < pfil->size; i++ )
	{
	    const proc_fd_info_t *pfi = &(pfil->list[i]);

	    if (pfi->valid)
	    {
	        count_proc_fd_info (pfi, (long long *) NULL, p_fd_info__path);
	    }
	}
    }

    return;

} /* end of count_proc_fd_info_list() */



void
begin_iterate__proc_fd_info_list (iterate_proc_fd_info_list_t *it,
				  proc_fd_info_list_t *list)
{
    it->pos = list;
    it->i = 0;
} /* end of begin_iterate__proc_fd_info_list () */


proc_fd_info_t *
next_iterate__proc_fd_info_list (iterate_proc_fd_info_list_t *it)
{
    if (it == (iterate_proc_fd_info_list_t *) NULL)
        return ((proc_fd_info_t *) NULL);

    for (; it->pos != (proc_fd_info_list_t *) NULL;
	 it->pos = it->pos->next)
    {
	while (it->i < it->pos->size)
	{
	    proc_fd_info_t *ret = &(it->pos->list[it->i]);

	    if ((ret->valid) && (ret->inuse))
	    {
	        it->i ++;	/* Point past */
		return (ret);
	    }

	    it->i ++;
	}

	it->i = 0;
    }

    return ((proc_fd_info_t *) NULL);

} /* next_iterate__proc_fd_info_list() */



static proc_fd_info_list_t *
new_list (proc_fd_info_list_t **p_list, unsigned short size)
{
    proc_fd_info_list_t *new = (proc_fd_info_list_t *) NULL;
    size_t offset;

    if ((p_list == (proc_fd_info_list_t **) NULL) || (size < 2))
        return ((proc_fd_info_list_t *) NULL);

    /* Play games with pointers to get the byte size */
    offset = (size_t) &(new->list[size]);

    new = (proc_fd_info_list_t *) malloc (offset);
    if (new == (proc_fd_info_list_t *) NULL)
        return ((proc_fd_info_list_t *) NULL);  /* Error return */
    
    count_alloc (&counter_proc_fd_info_list);

    /* fill with zeros - always safe. */
    memset ((void *) new, 0, offset);

    new->size = size;

    /* Find the end of the list to insert into. */
    for ( ; *p_list != (proc_fd_info_list_t *) NULL;
	  p_list = &((*p_list)->next) ) {
        continue;	/* Some compilers require a statement here. */
    }

    *p_list = new;

    return new;
} /* end of new_list() */


static proc_fd_info_t *
copy_fd_info (proc_fd_info_t *dest, proc_fd_info_t *src, int copy_or_move)
{
    int valid;
    int mine;

    if ((dest == (proc_fd_info_t *) NULL) || (src == (proc_fd_info_t *) NULL))
        return ((proc_fd_info_t *) NULL);

    /* Preserve the 'valid' and 'mine' bits */
    valid = dest->valid;
    mine = dest->mine;

    memcpy ((void *) dest, (void *) src, sizeof (proc_fd_info_t ));
    dest->valid = valid;
    dest->mine = mine;

    if (copy_or_move)
    {
        char *str;
	
	str = (char *) malloc (src->pathlen + 1);
	if (str)
	{
	    memcpy ((void *) str, (void *) (src->path), src->pathlen);
	    str[src->pathlen] = '\0';
	    dest->path = str;

	    count_alloc (&counter_proc_fd_info__pathstr);
	}
	else
	{
	    dest->path = (char *) NULL;
	}
    }
    else
    {
        /* The string for 'path' belongs to 'dest' now, so clobber 'src'. */
        src->path = (char *) NULL;
	src->pathlen = 0;
	src->inuse = 0;
    }

    return dest;
} /* end of copy_fd_info() */


static proc_fd_info_t *
new_in_list (proc_fd_info_list_t **p_list, proc_fd_info_t *src, 
	     unsigned short list_size, int copy_or_move)
{
    int fd;
    proc_fd_info_t *test;
    proc_fd_info_list_t *each;
    unsigned short i;     /* I is always a loop or array index. Long Live FORTRAN */
    
    if ((p_list == (proc_fd_info_list_t **) NULL) ||
	(list_size < 2) || (src == (proc_fd_info_t *) NULL))
        return ((proc_fd_info_t *) NULL);
    
    fd = src->fd;

    /* Search once to see if 'fd' is already present. */
    for (each = *p_list; each != (proc_fd_info_list_t *) NULL;
	 each = each->next)
    {
        for (i = 0; i < each->size; i++)
	{
	    /*
	     * Re-use for existing FD 
	     *
	     * -- let's hope that the fd itself didn't get reused. 
	     */
	    test = &(each->list[i]);
	    if ((fd == test->fd) && (test->inuse))
	    {
	      return (copy_fd_info(test, src, copy_or_move));
	    }
	}
    }

    /* Nothing to re-use. Now try to find an available slot. */
    for (each = *p_list; each != (proc_fd_info_list_t *) NULL; 
	 each = each->next)
    {
      for (i = 0; i < each->size; i++)
	{
	    /*
	     * Re-use for existing FD 
	     *
	     * -- let's hope that the fd itself didn't get reused. 
	     */
	    test = &(each->list[i]);
	    if (test->inuse == 0)
	    {
	        if (test->valid == 0)
		{
		    each->valid ++;
		    test->valid = 1;
		}

	        return (copy_fd_info(test, src, copy_or_move));
	    }
	}
    }
    
    /* Ran off the end. Now create a new thingy and take the first one */
    each = new_list (p_list, list_size);
    if (each == (proc_fd_info_list_t *) NULL)
    {
        return ((proc_fd_info_t *) NULL);
    }
    
    test = &(each->list[0]);
    test->valid = 1;
    each->valid++;

    return (copy_fd_info(test, src, copy_or_move));

} /* new_in_list () */


int
cmp_proc_fd_info (const proc_fd_info_t *a, const proc_fd_info_t *b)
{
    if (a == b)
        return (0);

    if ((!a->inuse) || (a->inuse != b->inuse))
        return (1);

    if (a->fd != b->fd)
        return (1);

    if (a->path_ok != b->path_ok)
        return (1);

    if ((a->path == (char *) NULL) || (b->path == (char *) NULL))
        return (1);

    if (a->pathlen != b->pathlen)
        return (1);

    if (memcmp (a->path, b->path, a->pathlen) != 0)
        return (1);

    /* Should we check 'stat' now??? */

    return (0);
} /* end of cmp_proc_fd_info() */


static proc_fd_info_t *
proc_fd_info__in__proc_fd_info_list (const proc_fd_info_t *pfi, proc_fd_info_list_t *list)
{
    iterate_proc_fd_info_list_t iter;
    proc_fd_info_t *pfi_iter;

    begin_iterate__proc_fd_info_list (&iter, list);
    for (pfi_iter = next_iterate__proc_fd_info_list (&iter);
	 pfi_iter;
	 pfi_iter = next_iterate__proc_fd_info_list (&iter))
    {
        if ((pfi_iter->tmpcmp == 0) && (cmp_proc_fd_info (pfi, pfi_iter) == 0))
	{
	    return pfi_iter;
	}
    }

    return ((proc_fd_info_t *) NULL);

} /* end of proc_fd_info__in__proc_fd_info_list () */



int
cmp_proc_fd_info_list (proc_fd_info_list_t *a,
		       proc_fd_info_list_t *b,
		       char *buffer, size_t bufflen, const char *sep,
		       int verbose)
{
    char *pos = buffer;
    unsigned int len;
    unsigned int diff_count = 0;
    unsigned int num_a = 0;	/* Number of valid 'a' entries. */
    unsigned int count = 0;   /* Count of 'a' entries that match 'b' entries */
    unsigned int num_b = 0;	/* Number of valid 'b' entries. */

    if (buffer)
    {
	if (sep == (char *) NULL)
	    sep = ", ";

        *buffer = '\0';
    }

    /* If they're the same, they're the same. */
    if (a == b)
        return (0);

#define ITERATE(_list,_var,_action) { 					\
          iterate_proc_fd_info_list_t iter_list;			\
	  proc_fd_info_t * _var;					\
	  begin_iterate__proc_fd_info_list (&iter_list, _list);		\
	  for (_var = next_iterate__proc_fd_info_list (&iter_list);	\
	       _var != (proc_fd_info_t *) NULL;				\
	       _var = next_iterate__proc_fd_info_list (&iter_list)) {	\
	    _action;							\
	  } }

	  
    /* Clear the tmpcmp bits. */
    ITERATE(a, pfi, 
	    {
	      pfi->tmpcmp = 0;
	      num_a ++;
	    } );


    ITERATE(b, pfi, 
	    {
	      pfi->tmpcmp = 0;
	      num_b ++;
	    } );

    if ((num_a == 0) && (num_b != 0))
    {
	if (buffer && (bufflen > 0))
	{
	    snprintf (pos, bufflen, "! (#a is 0, #b is %u)", num_b);
	    len = strlen (pos);
	    bufflen -= len;
	    pos += len;
	}

	
	if (!verbose)
	    return (num_b);
    }

    if ((num_a != 0) && (num_b == 0)) 
    {
	if (buffer && (bufflen > 0))
	{
	    snprintf (pos, bufflen, "! (#a is %d, #b is 0)", num_a);
	    len = strlen (pos);
	    bufflen -= len;
	    pos += len;
	}

	if (!verbose)
	    return (num_a);
    }

    /* Order N^2 ... sigh */
    /* If a pair is "==", them mark the pair with tmpcmp */
    ITERATE(a, pfi_a, 
	    {
	        proc_fd_info_t *pfi_b;

		if ((pfi_b = proc_fd_info__in__proc_fd_info_list (pfi_a, b)) != (proc_fd_info_t *) NULL)
		{
		    pfi_a->tmpcmp = 1;
		    pfi_b->tmpcmp = 1;
		    count ++;
		}
	    } );
	      
    if (count > 0 && buffer && (bufflen > 0))
    {
        snprintf (pos, bufflen, "=%u=", count);
	len = strlen (pos);
	pos += len;
	bufflen -= len;
    }

    if ((num_a == num_b) && (count == num_a))
    {
        return (0);
    }


    /* Now, look for entries that don't have tmpcmp set. */
    ITERATE(a, pfi, 
	    {
	        if (pfi->tmpcmp == 0)
		{
		    /* Never matched. */
		    diff_count ++;
		    if (buffer && (bufflen > 0))
		    {
		        char tmp_buffer[PROCINFO_MAX_PATHLEN * 2];
			char *t;
		      
			tmp_buffer[0] = '\0';
			t = proc_fd_info_toa (tmp_buffer, sizeof(tmp_buffer),
					      pfi, verbose);
		      
			snprintf (pos, bufflen, "-%s%s", t, sep);
			len = strlen (pos);
			bufflen -= len;
			pos += len;
		    }
		}
	    } );


    ITERATE(b, pfi, 
	    {
	        if (pfi->tmpcmp == 0)
		{
		    /* Never matched. */
		    diff_count ++;
		    if (buffer && (bufflen > 0))
		    {
		        char tmp_buffer[PROCINFO_MAX_PATHLEN * 2];
			char *t;
		      
			tmp_buffer[0] = '\0';
			t = proc_fd_info_toa (tmp_buffer, sizeof(tmp_buffer),
					      pfi, verbose);
		      
			snprintf (pos, bufflen, "+%s%s", t, sep);
			len = strlen (pos);
			bufflen -= len;
			pos += len;
		    }
		}
	    } );

    return (diff_count);

} /* end of cmp_proc_fd_info_list() */



proc_fd_info_t *
get_proc_fd_info (proc_fd_info_t *buff, const char *procfdpath)
{
    char *pos;
    const char *basename;
    const char *cpos;
    int fd;
    int res;
    long num;
    char linkpath[PROCINFO_MAX_PATHLEN];

    /* parameter error */
    if (procfdpath == (char *) NULL)
      return ((proc_fd_info_t *) NULL);
    
    for (basename = procfdpath, cpos = procfdpath; *cpos; cpos++)
    {
        if (*cpos == '/')
	    basename = cpos + 1;
    }

    /* Check to see of the basename is a decimal, positive fd # */
    pos = (char *) NULL;
    num = strtol (basename, &pos, 10);
    if (!pos || (*pos != '\0' ) | (num < 0)) 
    {
        DEBUG(("DEBUG: procfdpath '%s' - '%s' not an integer at '%s'\n", 
	       procfdpath, basename, pos ? pos : "(null)" ));
        return ((proc_fd_info_t *) NULL);
    }

    fd = num;
    
    if (buff == (proc_fd_info_t *) NULL)
    {
        buff = (proc_fd_info_t *) calloc (1, sizeof (proc_fd_info_t));

	/* calloc failure return. */
	if (buff == (proc_fd_info_t *) NULL)
	    return (buff);

	count_alloc (&counter_proc_fd_info);

	buff->mine = 1;
	buff->fd = fd;
    }
    else 
    {
        /* Clear the provided buffer. */
        memset ((void *) buff, 0, sizeof(proc_fd_info_t)); 

	buff->fd = fd;
    }

    if (fstat (fd, &(buff->stat)) == 0)
    {
	buff->stat_ok = 1;
    }


    /* Get information from the symlink */
    linkpath[sizeof(linkpath)-1] = '\0';
    res = readlink (procfdpath, linkpath, sizeof(linkpath)-1) ;
    if (res < 0) 
    {
        snprintf (linkpath, sizeof(linkpath), 
		  "*err: readlink() failed error %d: %s",
		  errno, strerror (errno));
	
	buff->path = strdup (linkpath);
	if (buff->path)
	{
	    buff->pathlen = strlen (buff->path);
	    count_alloc (&counter_proc_fd_info__pathstr);
	}
    }
    else if (res >= sizeof(linkpath))
    {
        char *str;

	str = (char *) malloc (64 + sizeof(linkpath) + 1);
	if (str)
	{
	    snprintf (str, 64 + sizeof(linkpath),
		     "*err: truncated at %d '%s'...",
		     sizeof(linkpath)-1, linkpath);
	    str[64 + sizeof(linkpath)] = '\0';
	    count_alloc (&counter_proc_fd_info__pathstr);
	}

	buff->path = str;
	buff->pathlen = 64 + sizeof(linkpath);
    }
    else
    {
        char *str;

	str = (char *) malloc (res+1);
	if (str)
	{
	    memcpy ((void *) str, &linkpath, res+1);
	    str[res] = '\0';
	    buff->path_ok = 1;
	    count_alloc (&counter_proc_fd_info__pathstr);
	}
	buff->path = str;
	buff->pathlen = res;
	
    }

    buff->inuse = 1;

    return buff;

} /* end of get_proc_fd_info() */


unsigned int
reset_proc_fd_info (proc_fd_info_t *pfi)
{
    int do_free;
    int valid;
    unsigned int ret = 0;

    if (pfi == (proc_fd_info_t *) NULL)
        return (0);
    
    valid = pfi->valid;
    do_free = pfi->mine;

    if (pfi->path)
    {
        free ((void *) pfi->path);
	ret += 1;
	count_free (&counter_proc_fd_info__pathstr);
    }

    memset ((void *) pfi, 0, sizeof (proc_fd_info_t));

    if (do_free)
    {
        count_free (&counter_proc_fd_info);
        free ((void *)pfi);
	
	ret += 2;
    }

    pfi->valid = valid;

    return (ret);

} /* end of reset_proc_fd_info () */



proc_fd_info_list_t *
dup_proc_fd_info_list (proc_fd_info_list_t *list)
{
    proc_fd_info_list_t  *new = (proc_fd_info_list_t *) NULL;
    proc_fd_info_t *each;
    unsigned int list_size;
    iterate_proc_fd_info_list_t it;
    
    if (! list)
        return ((proc_fd_info_list_t *) NULL);

    list_size = list->size;
    begin_iterate__proc_fd_info_list (&it, list);
    
    /* Re-build the new list, eliminating empty stuff. */

    for (each = next_iterate__proc_fd_info_list (&it);
	 each;
	 each = next_iterate__proc_fd_info_list(&it))
    {
        (void) new_in_list (&new, each, list_size, 1);
    }

    return (new);

} /* end of dup_proc_fd_info_list(src) */



unsigned int
free_proc_fd_info_list (proc_fd_info_list_t *list)
{
    __FUNC(free_proc_fd_info_list);
    proc_fd_info_list_t *next;
    static proc_fd_info_list_t *zed = (proc_fd_info_list_t *) NULL;
    size_t byte_size;
    int i;
    unsigned int ret = 0;

    for (next = list; list != (proc_fd_info_list_t *) NULL; list = next)
    {
        int loop_freed = 0;

	log_debug (1, "%s: list@%p {size=%u,valid=%u,next=%p}", _func,
		   list, list->size, list->valid, list->next);

        next = list->next;
        for (i = 0; i < list->size; i++)
	{
	    int tmp = 0;
	    int rc;

	    rc  = reset_proc_fd_info ( &(list->list[i]));
	    if ((rc & 1) == 1)
	        tmp ++;
	    if ((rc & 2) == 2)
	        tmp ++;

	    loop_freed += tmp;
	}

	/* Attempt to do some debugging very indirectly. */
	log_debug (2, "%s: %d objects freed in list@%p", _func, loop_freed, list);

	byte_size = (size_t) &(zed->list[list->size]);
	
	memset ((void *) list, 0, byte_size);
	count_free (&counter_proc_fd_info_list);
	free (list);

	ret += loop_freed;
    }

    if (ret == 0)
    {
        log_debug (1, "%s: Final - no objects freed", _func);
    }
    return (ret);

} /* free_proc_fd_info_list() */


char *
proc_fd_info_toa (char *buffer, size_t bufflen, const proc_fd_info_t *pfi, int verbose)
{
    int   len;
    char *pos = buffer;

    if ((buffer == (char *) NULL) || (bufflen < 10) ||
	(pfi == (proc_fd_info_t *) NULL))
        return ((char *) NULL);

    *buffer = '\0';

    if (pfi->inuse)
    {
        snprintf (pos, bufflen, "{fd=%d;", pfi->fd);

	len = strlen(pos);
	pos += len;
	bufflen -= len;
	
	if (verbose)
	{
	    snprintf(pos, bufflen, "%s%s%s",
		     pfi->valid ? "valid;" : "",
		     pfi->mine ? "alloc;" : "",
		     pfi->stat_ok ? "stat;" : "");
	    
	    len = strlen(pos);
	    pos += len;
	    bufflen -= len;
	}

	if (pfi->path)
	{
	    if (pfi->path_ok)
	    {
	        snprintf (pos, bufflen, "path='%s'", pfi->path);
	    }
	    else
	    {
	        snprintf (pos, bufflen, "error='%s'", pfi->path);
	    }

	    len = strlen (pos);
	    pos += len;
	    bufflen -= len;
	}

	/* Terminal closing */
	strncat (pos, "}", bufflen);
    } 

    return (buffer);

} /* end of proc_fd_info_toa() */


int
get_proc_fd_count (const char *procname, proc_fd_info_list_t **p_list)
{
    static DIR *proc_fd = (DIR *) NULL;
    struct dirent *de;
    int count = 0;
    int rc;
    static char last_procname[PROCINFO_MAX_PATHLEN] = { 0 };
    char fname[PROCINFO_MAX_PATHLEN];

    if (procname == (char *) NULL) 
    {
        if (proc_fd != (DIR *) NULL)
	{
 	    last_procname[0] = '\0';
	    closedir (proc_fd);
	    proc_fd = (DIR *) NULL;
	}
	return (0);
    }

    /* Check to see if procname changed from last time. */
    if (strncmp (last_procname, procname, sizeof(last_procname)) != 0)
    {  
        if (proc_fd != (DIR *) NULL)
	{
	    closedir (proc_fd);
	    proc_fd = (DIR *) NULL;
	}
	last_procname[0] = '\0';
    }

    if (proc_fd == (DIR *) NULL) 
    {
        if (strlen (procname) > sizeof(fname) - 4)
	{
 	    return (- ENAMETOOLONG);
	}

	if ((rc = snprintf (fname, sizeof(fname), "%s/fd", procname)) < 0)
	{
	    return (- EINVAL);
	}
	else if (rc == sizeof(fname)) 
	{
 	    return ( - ENAMETOOLONG );
	}

        proc_fd = opendir (fname);
	if (proc_fd == (DIR *) NULL)
	    return -errno;

	/* Save last procname. */
	strncpy (last_procname, procname, sizeof(last_procname));
    }
    else
    {
      	rewinddir(proc_fd);
    }

    while ( (de = readdir(proc_fd)) != (struct dirent *) NULL)
    {
	if ((de->d_name[0] != '\0') &&
	    (strncmp(".", de->d_name, NAME_MAX) != 0) &&
	    (strncmp("..", de->d_name, NAME_MAX) != 0)) {
	    count++;

	    if (p_list != (proc_fd_info_list_t **) NULL)
	    {
	        char path[PROCINFO_MAX_PATHLEN];
		proc_fd_info_t *tmp;
		proc_fd_info_t  tmp_buff;
		
		/* is de->d_name[] null terminated? */
		snprintf (path, sizeof(path), "%s/fd/%s", last_procname,
			  de->d_name);
		
		/* Always clean your memory, in case you have an
		   accident and have to go to the hospital. */
		memset ((void *) &(tmp_buff), 0, sizeof(tmp_buff));

		/* Find information. Now! */
		tmp = get_proc_fd_info (&tmp_buff, path);
		if (tmp)
		{
		  (void) new_in_list (p_list, tmp,
				      PROCINFO_FD_LIST_SIZE, 0);
		}
	    }
	}
    }

    return (count);

} /* end of get_proc_fd_count() */


int
get_proc_stat_info (const char *procname, proc_stat_info_t *st)
{
    static FILE *proc_stat = (FILE *) NULL;
    int  rc = 0;	/* Our return/error code. */
    static char last_procname[PROCINFO_MAX_PATHLEN];
    char fname[PROCINFO_MAX_PATHLEN];

    if ((st == (proc_stat_info_t *) NULL) && (procname == (char *)  NULL))
    {
        if (proc_stat != (FILE *) NULL) 
	{
	    fclose (proc_stat);
	    proc_stat = (FILE *) NULL;
	}
	last_procname[0] = '\0';
	return (0);
    }

    if ((st == (proc_stat_info_t *) NULL) || (procname == (char *) NULL))
    {
        return (-EINVAL);
    }


    /* Check to see if procname changed from last time. */
    if (strncmp (last_procname, procname, sizeof(last_procname)) != 0)
    {  
        if (proc_stat != (FILE *) NULL)
	{
	    fclose (proc_stat);
	    proc_stat = (FILE *) NULL;
	}
	last_procname[0] = '\0';
    }

    memset ((void *) st, 0, sizeof (proc_stat_info_t));

    if (proc_stat != (FILE *) NULL) 
    {
        rewind (proc_stat);
    }
    else
    {
        if (strlen (procname) > sizeof(fname) - 6)
	{
 	    return (- ENAMETOOLONG);
	}

	if ((rc = snprintf (fname, sizeof(fname), "%s/stat", procname)) < 0)
	{
	    return (- EINVAL);
	}
	else if (rc == sizeof(fname)) 
	{
 	    return ( - ENAMETOOLONG );
	}

        proc_stat = fopen (fname, "r");
	if (proc_stat == (FILE *) NULL)
	  return (-errno);

	strncpy (last_procname, procname, sizeof(last_procname));
    }

    rc = fscanf (proc_stat,
		 "%d %256s %c "		/* pid         comm        state                 */
		 "%d %d %d %d "		/* ppid        pgrp        session     tty_nr    */
		 "%d %lu %lu %lu "	/* tpgid       flags       minflt      cminflt   */
		 "%lu %lu %lu %lu "	/* majflt      cmajflt     utime       stime     */
		 "%ld %ld %ld %ld "	/* cutime      cstime      priority    nice      */
		 "%ld %ld %llu %lu "    /* num_threads itrealvalue starttime   vsize     */  
		 "%lu %lu %lu %lu "	/* rss         rsslim        startcode   endcode   */ 
		 "%lu %lu %lu %lu "	/* startstack  kstkesp     kstkeip     signal    */
		 "%lu %lu %lu %lu "     /* blocked     sigignore   sigcatch    wchan     */
		 "%lu %lu %d %d"        /* nswap       cnswap      exit_signal processor */ 
		 , 
		 &(st->stat_pid),     &(st->stat_comm[0]),     &(st->stat_state),
		 &(st->stat_ppid),    &(st->stat_pgrp),        &(st->stat_session),   &(st->stat_tty_nr),
		 &(st->stat_tpgid),   &(st->stat_flags),       &(st->stat_minflt),    &(st->stat_cminflt),
		 &(st->stat_majflt),  &(st->stat_cmajflt),     &(st->stat_utime),     &(st->stat_stime),
		 &(st->stat_cutime),  &(st->stat_cstime),      &(st->stat_priority),  &(st->stat_nice),
		 &(st->stat_num_threads), &(st->stat_itrealvalue), &(st->stat_starttime), &(st->stat_vsize),
		 &(st->stat_rss),     &(st->stat_rsslim),        &(st->stat_startcode), &(st->stat_endcode),
		 &(st->stat_startstack), &(st->stat_kstkesp),  &(st->stat_kstkeip),   &(st->stat_signal),
		 &(st->stat_blocked), &(st->stat_sigignore),   &(st->stat_sigcatch),  &(st->stat_wchan),
		 &(st->stat_nswap),   &(st->stat_cnswap),      &(st->stat_exit_signal), &(st->stat_processor)
		 );

    if (rc == 0)
      return (-1);

    if (rc > 9)
      return (0);

    return (rc);

}; /* end of static int get_proc_stat_info (proc_stat_info_t *st) */


char *
proc_stat_info_toa (char *buffer, size_t bufflen, const proc_stat_info_t *st, const char *sep, int verbose)
{
    char *pos = buffer;

    if ((buffer == (char *) NULL) || (bufflen < 10) || (st == (proc_stat_info_t *) NULL))
        return "broken";

    if (sep == (char *) NULL)
        sep = "; ";

    *buffer = '\0';

#define _SEP(_sep)	{ if (*buffer) { unsigned int len;  strncat (pos, _sep, bufflen); len = strlen(pos); bufflen -= len; pos += len; } }

#define _PSI_TOA(_field,_name,_fmt, _cast)			\
    if ((verbose) || (st->_field != 0)) {		\
        unsigned int len;				\
	_SEP(sep);					\
	snprintf(pos, bufflen, _name "=" _fmt, _cast st->_field);	\
	len = strlen(pos);				\
	pos += len;					\
	bufflen -= len;					\
    }


#define PSI_XL(_field,_name)	_PSI_TOA(_field,_name, "0x%lx", )

#define PSI_P(_field,_name)	_PSI_TOA(_field,_name, "%p", (void *))

#define PSI_UL(_field,_name)	_PSI_TOA(_field,_name, "%lu", )

#define PSI_ULL(_field,_name)	_PSI_TOA(_field,_name, "%llu", )

#define PSI_L(_field,_name)	_PSI_TOA(_field,_name, "%ld", )

#define PSI_D(_field,_name)	_PSI_TOA(_field,_name, "%d", )

#define PSI_STR(_field,_name)	_PSI_TOA(_field,_name, "'%s'", )

#define PSI_C(_field,_name)	_PSI_TOA(_field,_name, "'%c'", )

    /* Same order as in /proc/self/stat */

    PSI_D(stat_pid, "pid");
    PSI_STR(stat_comm, "comm");
    PSI_C(stat_state, "state");

    PSI_D(stat_ppid, "ppid");
    PSI_D(stat_pgrp, "pgrp");
    PSI_D(stat_session, "session");
    PSI_D(stat_tty_nr, "tty_nr");

    PSI_D(stat_tpgid, "tpgid");
    PSI_XL(stat_flags, "flags");
    PSI_UL(stat_minflt, "minflt");
    PSI_UL(stat_cminflt, "cminflt");


    PSI_UL(stat_majflt, "majflt");
    PSI_UL(stat_cmajflt, "cmajflt");
    PSI_UL(stat_utime, "utime");
    PSI_UL(stat_stime, "stime");

    PSI_L(stat_cutime, "cutime");
    PSI_L(stat_cstime, "cstime");
    PSI_L(stat_priority, "priority");
    PSI_L(stat_nice, "nice");

    PSI_L(stat_num_threads, "num_threads");
    PSI_L(stat_itrealvalue, "itrealvalue");
    PSI_ULL(stat_starttime, "starttime");
    PSI_UL(stat_vsize, "vsize");

    PSI_L(stat_rss, "rss");
    PSI_UL(stat_rsslim, "rsslim");
    PSI_P(stat_startcode, "startcode");
    PSI_P(stat_endcode, "endcode");

    PSI_P(stat_startstack, "startstack");
    PSI_P(stat_kstkesp, "kstkesp");
    PSI_P(stat_kstkeip, "kstkeip");
    PSI_XL(stat_signal, "signal");

    PSI_XL(stat_blocked, "blocked");
    PSI_XL(stat_sigignore, "sigignore");
    PSI_XL(stat_sigcatch, "sigcatch");
    PSI_UL(stat_wchan, "wchan");

    PSI_UL(stat_nswap, "nswap");
    PSI_UL(stat_cnswap, "cnswap");
    PSI_D(stat_exit_signal, "exit_signal");
    PSI_D(stat_processor, "processor");

    return buffer;

} /* end of char * proc_stat_info_toa (char *buffer, size_t bufflen, const proc_stat_info_t *st, const char *sep, int verbose) */





int
get_proc_statm_info (const char *procname, proc_statm_info_t *stm)
{
    static FILE *proc_statm = (FILE *) NULL;
    int  rc = 0;	/* Our return/error code. */
    static char last_procname[PROCINFO_MAX_PATHLEN];
    char fname[PROCINFO_MAX_PATHLEN];

    if ((stm == (proc_statm_info_t *) NULL) && (procname == (char *)  NULL))
    {
        if (proc_statm != (FILE *) NULL) 
	{
	    fclose (proc_statm);
	    proc_statm = (FILE *) NULL;
	}
	last_procname[0] = '\0';
	return (0);
    }

    if ((stm == (proc_statm_info_t *) NULL) || (procname == (char *) NULL))
    {
        return (-EINVAL);
    }


    /* Check to see if procname changed from last time. */
    if (strncmp (last_procname, procname, sizeof(last_procname)) != 0)
    {  
        if (proc_statm != (FILE *) NULL)
	{
	    fclose (proc_statm);
	    proc_statm = (FILE *) NULL;
	}
	last_procname[0] = '\0';
    }

    memset ((void *) stm, 0, sizeof (proc_statm_info_t));

    if (proc_statm != (FILE *) NULL) 
    {
        rewind (proc_statm);
    }
    else
    {
        if (strlen (procname) > sizeof(fname) - 6)
	{
 	    return (- ENAMETOOLONG);
	}

	if ((rc = snprintf (fname, sizeof(fname), "%s/statm", procname)) < 0)
	{
	    return (- EINVAL);
	}
	else if (rc == sizeof(fname)) 
	{
 	    return ( - ENAMETOOLONG );
	}

        proc_statm = fopen (fname, "r");
	if (proc_statm == (FILE *) NULL)
	  return (-errno);

	strncpy (last_procname, procname, sizeof(last_procname));
    }

    rc = fscanf (proc_statm,
		 "%lu %lu %lu %lu "	/* size       resident     share     trs   */
		 "%lu %lu %lu"		/* drs        lrs          dt              */
		 , 
		 &(stm->statm_size),   &(stm->statm_resident),   &(stm->statm_share),	&(stm->statm_trs),
		 &(stm->statm_drs),    &(stm->statm_lrs),        &(stm->statm_dt)
		 );
    
    switch (rc) {
    case 7:
      return (0);

    case 0:
      return (-1);

    }

    return (rc);

}; /* end of static int get_proc_statm_info (proc_statm_info_t *stm) */


char *
proc_statm_info_toa (char *buffer, size_t bufflen, const proc_statm_info_t *stm, const char *sep, int verbose)
{
    char *pos = buffer;

    if ((buffer == (char *) NULL) || (bufflen < 10) || (stm == (proc_statm_info_t *) NULL))
        return "broken";

    if (sep == (char *) NULL)
        sep = "; ";

    *buffer = '\0';

#define _PSMI_TOA(_field,_name,_fmt, _cast)			\
    if ((verbose) || (stm->_field != 0)) {		\
        unsigned int len;				\
	_SEP(sep);					\
	snprintf(pos, bufflen, _name "=" _fmt, _cast stm->_field);	\
	len = strlen(pos);				\
	pos += len;					\
	bufflen -= len;					\
    }


#define PSMI_XL(_field,_name)	_PSMI_TOA(_field,_name, "0x%lx", )

#define PSMI_P(_field,_name)	_PSMI_TOA(_field,_name, "%p", (void *))

#define PSMI_UL(_field,_name)	_PSMI_TOA(_field,_name, "%lu", )

#define PSMI_ULL(_field,_name)	_PSMI_TOA(_field,_name, "%llu", )

#define PSMI_L(_field,_name)	_PSMI_TOA(_field,_name, "%ld", )

#define PSMI_D(_field,_name)	_PSMI_TOA(_field,_name, "%d", )

#define PSMI_STR(_field,_name)	_PSMI_TOA(_field,_name, "'%s'", )

#define PSMI_C(_field,_name)	_PSMI_TOA(_field,_name, "'%c'", )

    /* Same order as in /proc/self/statm */


    PSMI_UL(statm_size, "size");
    PSMI_UL(statm_resident, "resident");
    PSMI_UL(statm_share, "share");
    PSMI_UL(statm_trs, "trs");

    PSMI_UL(statm_drs, "drs");
    PSMI_UL(statm_lrs, "lrs");
    PSMI_UL(statm_dt, "dt");

    return buffer;

} /* end of char * proc_statm_info_toa (char *buffer, size_t bufflen, const proc_statm_info_t *stm, const char *sep, int verbose) */


int
delta_proc_statm_info (const proc_statm_info_t *old, const proc_statm_info_t *new, proc_statm_info_t *delta)
{
    int rc = 0;
    memset ((void *) delta, 0, sizeof (proc_statm_info_t));

#define DELTA_PSMI(_field,_code) _DELTA(_field,_code,old,new,delta,rc)

    DELTA_PSMI(statm_size,1);
    DELTA_PSMI(statm_resident,2);
    DELTA_PSMI(statm_share,4);
    DELTA_PSMI(statm_trs,8);
    DELTA_PSMI(statm_drs,16);
    DELTA_PSMI(statm_lrs,32);
    DELTA_PSMI(statm_dt,64);

    return rc;

} /* end of int delta_proc_statm_info (old, new, delta) */
