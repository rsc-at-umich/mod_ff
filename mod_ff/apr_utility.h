/*
        Apache Module utility routines

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: apr_utility.h,v 1.3 2013/03/12 19:06:16 rsc Exp $
*/

#if !defined(APR_UTILITY_H)
#  define APR_UTILITY_H "$Id: apr_utility.h,v 1.3 2013/03/12 19:06:16 rsc Exp $"

/*
 * Include the core server components.
 */
#  include "httpd.h"

typedef struct intlist intlist_t;
struct intlist {
  intlist_t *next;
  int	     num;
};
 
typedef struct strlist strlist_t;
struct strlist {
  strlist_t *next;
  char	    *str;
};
 

/*
 * For the following functions:
 * if 'sorted' is > 0, do an ascending sort.
 * if 'sorted' is < 0, do a descending sort.
 * if 'sorted' is 0, don't sort.
 */
extern int   intlist_insert (apr_pool_t *p, intlist_t **p_list, int sorted, int num);
extern int   intlist_delete (intlist_t **p_list, int sorted, int num); 
extern int   intlist_in (const intlist_t *list, int sorted, int num);
extern intlist_t *  intlist_dup (apr_pool_t *p, int sorted, const intlist_t *old);

extern int   strlist_insert (apr_pool_t *p, strlist_t **p_list, int sorted, const char *str);
extern int   strlist_delete (strlist_t **p_list, int sorted, const char *str); 
extern int   strlist_in (const strlist_t *list, int sorted, const char *str);
extern strlist_t *  strlist_dup (apr_pool_t *p, int sorted, const strlist_t *old);


extern char * my_apr_pstrdup_delim (apr_pool_t *p, const char *str, int delim, char **p_next);

typedef struct tag_val_pair_struct tag_val_pair_t;

struct tag_val_pair_struct {
  tag_val_pair_t *next;
  const char     *tag;	/* What we're looking for. */
  const char     *val;	/* What we found. */
};

extern tag_val_pair_t *ap_strlist_to_tag_val_pair (apr_pool_t *p, const strlist_t *list);

extern apr_table_entry_t * ff_apr_table_entry_next (const apr_table_t *t, apr_table_entry_t **p_pos, char **p_errmsg);

#endif /* defined(APR_UTILITY_H) */
