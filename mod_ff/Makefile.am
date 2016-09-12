## Find apache sys config dir
APACHE2_SYSCONFDIR = `@APXS@ -q SYSCONFDIR`
APACHE2_MOD_DIR="@apache2_mod_dir@"

ACLOCAL_AMFLAGS=-I m4

## These are the shared libraries to be built
noinst_LIBRARIES = libff.a
lib_LTLIBRARIES = libmod_ff.la
AM_CFLAGS = -fPIC


bin_PROGRAMS = procinf
procinf_SOURCES = procinfo-test.c procinfo.h
procinf_LDADD = libff.a

libff_a_SOURCES = timevals.c timevals.h rusage.c rusage.h ff_stat.c ff_stat.h utility.c utility.h procinfo.c procinfo.h unpackage_autoconf.h

## Define the source file for the module
libmod_ff_la_SOURCES = mod_ff.c mod_ff.h ff_handlers.c apr_utility.c apr_utility.h
libmod_ff_la_LIBADD = libff.a


include_HEADERS = procinfo.h timevals.h rusage.h utility.h apr_utility.h ff_stat.h mod_ff.h unpackage_autoconf.h

## Define that an include directory is required.
AM_CPPFLAGS = -I@apache_httpd_include@ -I@apr_include@

procinfo.o: procinfo.c procinfo.h rusage.h timevals.h ff_stat.h

mod_ff.lo mod_ff.o: mod_ff.c procinfo.h timevals.h rusage.h utility.h apr_utility.h ff_stat.h mod_ff.h unpackage_autoconf.h

install-exec-local: install-apache-module

install-apache-module:
