/*
        Apache Module utility routines

	Copyright 2012 by the Regents of the University of Michigan

	Author Richard S. Conto <rsc@umich.edu>

	All Rights Reserved

	CVSID: $Id: apr_utility.c,v 1.6 2013/03/12 19:06:16 rsc Exp $
*/

/*
 * Include the core server components.
 */
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include "utility.h"
#include "apr_utility.h"
#include "apr_strings.h"

static int strlist_insert2 (apr_pool_t *p, strlist_t **p_list, int sorted, char *str);



int
intlist_insert (apr_pool_t *p, intlist_t **p_list, int sorted, int num)
{
    intlist_t *new;

    if (p_list == (intlist_t **) NULL)
        return (-1);

    /* Search through the linked list. */
    for (; *p_list != (intlist_t *) NULL; p_list = &((*p_list)->next))
    {
	if ((*p_list)->num == num)
	    return (0);  /* Already present. */

	if (sorted != 0)
	{
	    if (sorted > 0)
	    {
		/* Create a sorted list, ascending */
	        if ((*p_list)->num > num)
		    break;
	    }
	    else
	    {
		/* Create a sorted list, ascending */
	        if ((*p_list)->num < num)
		    break;
	    }
	}
    }

    if ((new = (intlist_t *) apr_palloc (p, sizeof (intlist_t)) ) == (intlist_t *) NULL)
    {
	return (-2);
    }

    new->num = num;
    new->next = *p_list;

    *p_list  = new;

    return (1);  /* Success */
    
} /* end of intlist_insert() */

int
intlist_in (const intlist_t *list, int sorted, int num)
{
    for ( ; list != (intlist_t *) NULL ; list = list->next)
    {
	if (list->num == num)
	    return (1);	    /* Found */

	if (sorted != 0)
	{
	    /* Assumes sorted list, ascending. */
	    if (sorted > 0)
	    {
	      if (list->num > num )
		  return (0);
	    }
	    else
	    {
	        if (list->num < num )
		   return (0);
	    }
	}
    }

    /* Not found */
    return (0);

} /* end of intlist_in () */

int
intlist_delete (intlist_t **p_list, int sorted, int num)
{
    if (p_list == (intlist_t **) NULL)
        return (-1);
    
    for (; *p_list != (intlist_t *) NULL; p_list = &((*p_list)->next))
    {
	if ((*p_list)->num == num)
	{
	    /* Found */
	    *p_list = (*p_list)->next;	/* Assume APR pool memory will recover this later. */
	    return (1);
	}

	if (sorted != 0)
	{
	    if (sorted > 0)
	    {
	        /* Assumes sorted list, ascending. */
	        if ((*p_list)->num > num) 
		    return (0);/* Not found */
	    }
	    else
	    {
	        /* Assumes sorted list, descending. */
	        if ((*p_list)->num < num) 
		    return (0);/* Not found */
	    }
	}
    }
    
    /* Not found */
    return (0);
} /* end of intlist_delete() */


intlist_t *
intlist_dup (apr_pool_t *p, int sorted, const intlist_t *old)
{
    intlist_t *new = (intlist_t *) NULL;

    for (; old != (intlist_t *) NULL; old = old->next)
    {
        intlist_insert (p, &new, sorted, old->num);
    }
  
    return new;;
} /* end of intlist_dup() */




int
strlist_insert (apr_pool_t *p, strlist_t **p_list, int sorted, const char *str)
{
    strlist_t *new;

    if (p_list == (strlist_t **) NULL)
        return (-1);

    /* Search through the linked list. */
    for (; *p_list != (strlist_t *) NULL; p_list = &((*p_list)->next))
    {
        int cmp = strcmp ((*p_list)->str, str);

        if (cmp == 0)
	    return (0);  /* Already present. */

	/* Create a sorted list, ascending */
	if (cmp > 0)
	    break;
    }

    if ((new = (strlist_t *) apr_palloc (p, sizeof (strlist_t)) ) == (strlist_t *) NULL)
    {
	return (-2);
    }

    new->str = apr_pstrdup (p, str);
    new->next = *p_list;

    *p_list  = new;

    return (1);  /* Success */
    
} /* end of strlist_insert() */



static int
strlist_insert2 (apr_pool_t *p, strlist_t **p_list, int sorted, char *str)
{
    strlist_t *new;

    if (p_list == (strlist_t **) NULL)
        return (-1);

    /* Search through the linked list. */
    for (; *p_list != (strlist_t *) NULL; p_list = &((*p_list)->next))
    {
        int cmp = strcmp ((*p_list)->str, str);

        if (cmp == 0)
	    return (0);  /* Already present. */

	/* Create a sorted list, ascending */
	if (cmp > 0)
	    break;
    }

    if ((new = (strlist_t *) apr_palloc (p, sizeof (strlist_t)) ) == (strlist_t *) NULL)
    {
	return (-2);
    }

    new->str = str;
    new->next = *p_list;

    *p_list  = new;

    return (1);  /* Success */
    
} /* end of strlist_insert2() */

int
strlist_in (const strlist_t *list, int sorted, const char *str)
{
    for ( ; list != (strlist_t *) NULL ; list = list->next)
    {
        int cmp = strcmp (list->str, str);

	if (cmp == 0)
	    return (1);	    /* Found */

	/* Assumes sorted list, ascending. */
	if (cmp > 0 )
	    return (0);
    }

    /* Not found */
    return (0);

} /* end of strlist_in () */

int
strlist_delete (strlist_t **p_list, int sorted, const char *str)
{
    if ((p_list == (strlist_t **) NULL) || (str == (char *) NULL))
        return (-1);
    
    for (; *p_list != (strlist_t *) NULL; p_list = &((*p_list)->next))
    {
        int cmp = strcmp ((*p_list)->str, str);

	if (cmp == 0)
	{
	    /* Found */
	    *p_list = (*p_list)->next;	/* Assume APR pool memory will recover this later. */
	    return (1);
	}

	/* Assumes sorted list, ascending. */
	else if (cmp > 0)
	{
	    /* Not found */
	    return (0);
	}
    }
    
    /* Not found */
    return (0);
} /* end of strlist_delete() */


strlist_t *
strlist_dup (apr_pool_t *p, int sorted, const strlist_t *old)
{
    strlist_t *new = (strlist_t *) NULL;
  
    for (; old != (strlist_t *) NULL; old = old->next)
    {
        (void) strlist_insert2 (p, &new, sorted, old->str);
    }
  
    return new;;
} /* end of strlist_dup() */



tag_val_pair_t *
ap_strlist_to_tag_val_pair (apr_pool_t *p, const strlist_t *strlist)
{
    __FUNC(ap_strlist_to_tag_val_pair);
    tag_val_pair_t *list = (tag_val_pair_t *) NULL;
    tag_val_pair_t **p_list = &list;

    /*
     * Create tag_val_pair list in same order as strlist
     */
    for (; strlist; strlist = strlist->next)
    {
        *p_list = (tag_val_pair_t *) apr_pcalloc (p, sizeof (tag_val_pair_t));
	if ( *p_list == (tag_val_pair_t *) NULL)
	    return (list);

	/*
	 * Assumes that 'str' won't be deallocated in the current pool scope, 
	 * and also assumes that this code doesn't need to clean up new values.
	 */
	(*p_list)->tag = strlist->str;

	p_list = &((*p_list)->next);
    }

    return (list);

} /* end of ap_strlist_to_tag_val_pair() */


char *
my_apr_pstrdup_delim (apr_pool_t *p, const char *str, int delim, char **p_next)
{
    __FUNC(my_apr_pstrdup_delim);
    apr_size_t len;
    const char *found;

    if ((p == (apr_pool_t *) NULL) || (str == (char *) NULL))
        return ((char *) NULL);

    /* Degenerate case. */
    if (delim == 0)
    {
	if (p_next != (char **) NULL)
	{
	  *p_next = (char *) str + strlen (str);
	}
	return apr_pstrdup (p, str);
    }

    found = strchr (str, delim);
    if (found == (char *) NULL)
    {
	if (p_next != (char **) NULL)
	{
	  *p_next = (char *) str + strlen (str);
	}
	return apr_pstrdup (p, str);
    }

    len = found - str;

    return apr_pstrndup (p, str, len);
}




/*
 * Breaking the Apache API.. (gently)
 *
 *
 * Return key/value pairs from an apr_table_t * - in indeterministic order
 */
apr_table_entry_t *
ff_apr_table_entry_next (const apr_table_t *t, apr_table_entry_t **p_pos, char **p_errmsg)
{
    __FUNC(ff_apr_table_next);
    const apr_array_header_t *at = apr_table_elts(t);  /* per. API to get the array from the table */
    const apr_table_entry_t *end;

    /* Quietly fail if we're called incorrectly. */
    if (apr_is_empty_table (t) || ((apr_table_entry_t **) NULL == p_pos))
      {
	if (p_errmsg)
	  *p_errmsg = "Empty or missing table";

	return ((apr_table_entry_t *) NULL);
      }

    /* Quietly fail if we're called on a wrongly sized table/array. */
    if (at->elt_size != sizeof(apr_table_entry_t))
      {
	if (p_errmsg)
	  *p_errmsg = "Array size incorrect for apr_table_t";

	return ((apr_table_entry_t *) NULL);
      }

    if (at->nelts <= 0)
      {
	if (p_errmsg)
	  *p_errmsg = "Empty table after all";
	
	return ((apr_table_entry_t *) NULL);
      }

    /* If this is the first call, then return the first one and start things going. */
    if ((apr_table_entry_t *) NULL == *p_pos)
      {
	if (p_errmsg)
	  *p_errmsg = "Returned first element";

	*p_pos = (apr_table_entry_t *) (at->elts);

	return *p_pos;
      }

    /* Check to see if 'p_pos' is in range, using pointer arithmatic */
    end = ((apr_table_entry_t *) at->elts) + (at->nelts - 1);

    if ((*p_pos < ((apr_table_entry_t *) at->elts)) || (end <= *p_pos))
      {
	if (p_errmsg)
	  *p_errmsg = "Last element out of range";

	/* Quietly fail: Out of range */
	return ((apr_table_entry_t *) NULL);
      }

    if (p_errmsg)
      *p_errmsg = "Next element";

    /* Advance our "current state" */
    (*p_pos) ++;

    /* And return the next array element (until we're out-of-range per. above.) */
    return *p_pos;

} /* end of ff_apr_table_next() */

