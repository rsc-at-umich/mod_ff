/*
	Copyright 2012-2013 by the Regents of the University of Michigan

	All Rights Reserved
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "procinfo.h"
#include "rusage.h"
#include "ff_stat.h"


#if defined(_FreeBSD_)
static char procfs[] = "/compat/linux/proc";
#else
static char procfs[] = "/proc";
#endif 

static int verbose = 0;

static char *progname = "unknown";

static void display_ff_stat (const char *fname);
static void display_procinfo (const char *fname);
static void display (const char *proc);
int main (int argc, char *argv[]);


static const char * procfs_path (const char *pid);

static const char *
procfs_path (const char *pid)
{
    static char buffer[4096];

    snprintf (buffer, sizeof(buffer), "%s/%s", procfs, pid);

    return buffer;
}

static void
display_procinfo (const char *fname)
{
   proc_stat_info_t st;
   char buffer[4096];
   int rc;
   char *put;

   if ((rc = get_proc_stat_info (fname, &st)) != 0)
   {
	fprintf (stderr, "get_proc_stat_info('%s') failed, code=%d\n", fname, rc);
	return;
   }

   put = proc_stat_info_toa (buffer, sizeof(buffer), &st, " ;\n\t", verbose);

   printf ("%s: %s\n", progname, put);

} /* end of display_procinfo()  */


static void
display_ff_stat(const char *fname)
{
    int rc;
    char *put;
    ff_stat_t ff;
    char buffer[4096];


    memset ((void *) &ff, 0, sizeof(ff));

    rc = get_ff_stat (fname, &ff, /* overhead */ 2, 1);

    printf ( "get_ff_stat(\"%s\", ...) rc=%d\n", fname, rc);

    put = ff_stat_toa (buffer, sizeof(buffer), &ff,
		       "%c", " ;\n\t", verbose);

    printf ("%s: %s;\n", progname, put);

    buffer[0] = '\0';
    rusage_toa (buffer, sizeof(buffer), &(ff.overhead), ", overhead.", verbose);
    if (buffer[0])
    {
        printf ("%s: rusage()\n\toverhead.%s ;\n", progname, buffer);
    }

    buffer[0] = '\0';
    proc_statm_info_toa (buffer, sizeof(buffer), &(ff.statm), ", statm.statm_", verbose);
    if (buffer[0])
    {
        printf ("%s: proc_statm_info()\n\tstatm.statm_%s; \n", progname, buffer);
    }

    /* Cleanup */
    reset_ff_stat (&ff);

} /* end of display_ff_stat() */


static void
display (const char *proc)
{
    char * fname = procfs_path (proc);

    display_procinfo (fname);
    
    display_ff_stat (procfs);

} /* end of display_procinfo()  */


int main (int argc, char *argv[])
{
   int i;
   char *p;
   struct rusage r;
   proc_statm_info_t stm;
   char buffer[1024];


   for (p = argv[0]; *p; p++)
     {
       if (*p == '/')
	 progname = p + 1;
     }

   
   if (argc > 1)
   {
       if (strcmp (argv[1], "-v") == 0)
	{
	  verbose = 1;
	  argc --;
	  argv++;
	}
   }

   if (getrusage (RUSAGE_SELF, &r) == 0)
   {
     p = rusage_toa (buffer, sizeof(buffer), &r, " ;\n\t", verbose);

     printf ("%s: [rusage(RUSAGE_SELF)]\n\t%s;\n", progname,  p);
   }

   if (getrusage (RUSAGE_CHILDREN, &r) == 0)
   {
     p = rusage_toa (buffer, sizeof(buffer), &r, " ;\n\t", verbose);

     printf ("%s: [rusage(RUSAGE_CHILDREN)]\n\t%s;\n", progname,  p);
   }

   if (get_proc_statm_info (procfs_path ("self"), &stm) == 0)
   {
       p = proc_statm_info_toa (buffer, sizeof(buffer), &stm, ";\n\t", verbose);
       printf ("%s: [get_proc_statm_info()\n\t%s ;\n", progname, p);
   }

   if (argc == 1) {
	char ppid[20];

	sprintf (ppid, "%d", getppid());

	display (ppid);
   }

   else {
     for (i = 1; i < argc; i++) {
	if (i > 1)
	   printf("\n");

	display (argv[i]);
     }
   }


   
   if (getrusage (RUSAGE_SELF, &r) == 0)
   {
     p = rusage_toa (buffer, sizeof(buffer), &r, " ;\n\t", verbose);

     printf ("%s: [rusage(RUSAGE_SELF)]\n\t%s;\n", progname, p);
   }

   if (getrusage (RUSAGE_CHILDREN, &r) == 0)
   {
     p = rusage_toa (buffer, sizeof(buffer), &r, " ;\n\t", verbose);

     printf ("%s: [rusage(RUSAGE_CHILDREN)]\n\t%s;\n", progname, p);
   }


   return (0);  

	
} /* end of main() */

