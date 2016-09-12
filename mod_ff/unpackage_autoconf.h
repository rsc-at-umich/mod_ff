/*
 * Apache modules managed by autoconf don't cooperate well with
 * Apache itself (being managed by autoconf.)
 *
 * This attempts to rip out the Apache autoconf so that
 * the stuff pulled in by "config.h" works right.
 */

/* Resolve battling autoconfs */
#if defined(PACKAGE_BUGREPORT)
#  undef PACKAGE_BUGREPORT
#endif
#if defined(PACKAGE_VERSION)
#  undef PACKAGE_VERSION
#endif
#if defined(PACKAGE_STRING)
#  undef PACKAGE_STRING
#endif
#if defined(PACKAGE_TARNAME)
#  undef PACKAGE_TARNAME
#endif
#if defined(PACKAGE_NAME)
#  undef PACKAGE_NAME
#endif

/* Now pull in the local config.h */

#include "config.h"

