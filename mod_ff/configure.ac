#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([mod_ff],[0.7],[rsc@umich.edu])
AM_INIT_AUTOMAKE(mod_ff, 0.7)
AC_CONFIG_SRCDIR([mod_ff.c])
dnl #AC_CONFIG_HEADER([config.h])
dnl #AM_CONFIG_HEADER([config.h])
AM_CONFIG_HEADER(config.h)
dnl
m4_defun([_LT_AC_LANG_CXX_CONFIG], [:])
m4_defun([_LT_AC_LANG_F77_CONFIG], [:])
dnl
# Checks for programs.
dnl #AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
dnl AC_PROG_RANLIB
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

# Checks for libraries.

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_FUNCS([localtime_r strcasecmp strchr strdup strerror strrchr strtol memset])
AC_FUNC_STRFTIME
AC_STRUCT_TM

# Added
dnl
dnl Note: AC_DEFUN goes here plus other stuff

AC_MSG_CHECKING(for apache APXS)
AC_ARG_WITH(apxs,
            [AS_HELP_STRING([[--with-apxs[=FILE]]],
                            [path to the apxs, defaults to "apxs".])],
[
    if test "$withval" = "yes"; then
      APXS=apxs
    else
      APXS="$withval"
    fi
])

if test -z "$APXS"; then
  for i in /usr/sbin /usr/local/sbin /usr/bin /usr/local/sbin ; do
    if test -f "$i/apxs2"; then
      APXS="$i/apxs2"
      break
    fi
    if test -f "$i/apxs"; then
      APXS="$i/apxs"
      break
    fi
  done
fi
if test -n "$APXS" -a -x "$APXS"; then
    AC_MSG_RESULT(Found at $APXS)
else
    AC_MSG_ERROR(Not found or $APXS not executable)
fi
dnl
dnl -- Determine how to find APR_CONFIG
AC_MSG_CHECKING(for apache apr-config/apr-1-config/etc)
AC_ARG_WITH(apr-1-config,
            [AS_HELP_STRING([[--with-apr-1-config[=FILE]]],
                            [path to the apr-1-config, defaults to "apr-1-config".])],
[
    if test "$withval" = "yes"; then
      APR_CONFIG=apr-1-config
    else
      APR_CONFIG="$withval"
    fi
])
if test -z "$APR_CONFIG" -a -x "$APXS" ; then
   APR_CONFIG=`$APXS -q APR_CONFIG`
fi
if test -z "$APR_CONFIG" ; then
  for i in /usr/sbin /usr/local/sbin /usr/bin /usr/local/sbin ; do
    if test -f "$i/app-1-config" ; then
      APR_CONFIG="$i/apr-1-config"
      break
    fi
    if test -f "$i/apr-config" ; then
      APR_CONFIG="$i/apr-config"
      break
    fi
  done
fi
if test -n "$APR_CONFIG" -a -x "$APR_CONFIG" ; then
    AC_MSG_RESULT(Found at $APR_CONFIG)
else
    AC_MSG_ERROR(Not found or $APR_CONFIG not executable)
fi
AC_DEFUN([APACHE_HTTPD_INCLUDE],[
  AC_ARG_WITH(
    apache_httpd_include,
    [  --with-apache-httpd-include[=DIR]     Apache httpd server includes],
    ,
    [with_apache_httpd_include="test"]
  )

  AC_MSG_CHECKING(for Apache httpd include directory)

  if test "$with_apache_httpd_include" = "test"; then
      with_apache_httpd_include=`${APXS} -q includedir`
  fi

  if test "$with_apache_httpd_include" = "no"; then
    AC_MSG_ERROR( Specify the apache httpd include directory using --with-apache-httpd-include)
  else
    # make sure that a well known include file exists
    if test -e "$with_apache_httpd_include/include/httpd.h" ; then
      apache_httpd_include="${with_apache_httpd_include}/include"
      AC_MSG_RESULT(at $apache_httpd_include)
    elif test -e "${with_apache_httpd_include}/httpd.h" ; then
      apache_httpd_include="${with_apache_httpd_include}"
      AC_MSG_RESULT(at $apache_httpd_include)
    else
      AC_MSG_ERROR( --with-apache-httpd-include ${with_apache_httpd_include} not found. )
    fi
  fi
])
dnl -- Evaluate
APACHE_HTTPD_INCLUDE
dnl
dnl -- Determine where to install the apache module
AC_DEFUN([APACHE_MOD_DIR],[
  AC_ARG_WITH(
    apache_mod_dir,
    [  --with-apache-mod-dir[=DIR]     Apache module directory],
    ,
    [with_apache_mod_dir="test"]
  )

  AC_MSG_CHECKING(for Apache module directory)

  if test "$with_apache_mod_dir" = "test"; then
      with_apache_mod_dir=`${APXS} -q LIBEXECDIR`
  fi

  if test "$with_apache_mod_dir" = "no"; then
    AC_MSG_ERROR( Specify the apache module directory using --with-apache-mod-dir)
  else
    # make sure that a well known include file exists
    if test -e "$with_apache_mod_dir/" ; then
      apache_mod_dir="${with_apache_mod_dir}"
      AC_MSG_RESULT(at $apache_mod_dir)
    else
      AC_MSG_ERROR( --with-apache-mod-dir ${with_apache_mod_dir} not found. )
    fi
  fi
])
dnl -- evaluate
APACHE_MOD_DIR
dnl
AC_DEFUN([APR_INCLUDE],[
  AC_ARG_WITH(
    apr_include,
    [ --with-apr-include[=DIR]     Apache apr includes],
    ,
    [with_apr_include="test"]
  )

  AC_MSG_CHECKING(for Apache apr include directory)

  if test "$with_apr_include" = "test"; then
      with_apr_include=`${APR_CONFIG} --includes|sed 's%^[ ]*-I%%' | sed 's%[ ]*$%%'`
  fi

  if test "$with_apr_include" = "no"; then
    AC_MSG_ERROR( Specify the apache apr include directory using --with-apr-include)
  else
    # make sure that a well known include file exists
    if test -e "$with_apr_include/include/apr.h" ; then
      apr_include="${with_apr_include}/include"
      AC_MSG_RESULT(at $apr_include)
    elif test -e "${with_apr_include}/apr.h" ; then
      apr_include="${with_apr_include}"
      AC_MSG_RESULT(at $apr_include)
    else
      AC_MSG_ERROR( --with-apr-include ${with_apr_include} not found. )
    fi
  fi
])
dnl -- Evaluate
APR_INCLUDE
dnl
# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_FUNC_MALLOC
dnl AC_PROG_CXX
AC_TYPE_OFF_T
# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_STAT

AC_SUBST(APXS)
AC_SUBST(APR_CONFIG)
AC_SUBST(apache_httpd_include)
AC_SUBST(apr_include)
AC_SUBST(apache_mod_dir)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
