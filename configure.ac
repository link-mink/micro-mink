#               _____  ____ __
#   __ ____ _  /  _/ |/ / //_/
#  / // /  ' \_/ //    / ,<
#  \_,_/_/_/_/___/_/|_/_/|_|
#
# SPDX-License-Identifier: MIT
#

AC_PREREQ([2.68])
AC_INIT([umink],
        m4_esyscmd([scripts/git-version-gen .tarball-version]),
        [info@link-mink.com], ,
        [https://github.com/link-mink/umink])
config_flags="$*"
AC_DEFINE_UNQUOTED([CONFIG_FLAGS],["$config_flags"],[Flags passed to configure])
AC_SUBST(CONFIG_FLAGS, "$config_flags")
AM_INIT_AUTOMAKE([foreign subdir-objects nostdinc serial-tests 1.14])
AC_CONFIG_SRCDIR([src/services/sysagent/sysagentd.c])
AC_CONFIG_HEADERS([config.h])
AX_PREFIX_CONFIG_H(umink_pkg_config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_LANG([C])
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_AWK
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_SED
AC_CHECK_PROG(GPERF, gperf, gperf)
AS_IF([test -z "$GPERF"], [AC_MSG_ERROR([gperf not found!])])
PKG_PROG_PKG_CONFIG
LT_INIT

# save libs
COMMON_LIBS=$LIBS

# /***********************************/
# /* disable RT threads (SCHED_FIFO) */
# /***********************************/
AC_ARG_ENABLE(sched-fifo,
              [AS_HELP_STRING([--enable-sched-fifo], [Enable SCHED_FIFO scheduling [default=no]])],,
              [enable_sched_fifo=no])
AM_CONDITIONAL(ENABLE_SCHED_FIFO, test "x$enable_sched_fifo" = "xyes")
if test "x$enable_sched_fifo" != "xno"; then
    AC_DEFINE([ENABLE_SCHED_FIFO], [1], [Enable SCHED_FIFO scheduling])
fi

# /*******/
# /* Lua */
# /*******/
PKG_CHECK_MODULES([LUA], [lua >= 5.1], [], [AC_MSG_ERROR([Lua not found!])])

# /********/
# /* MQTT */
# /********/
AC_ARG_ENABLE(mqtt,
              [AS_HELP_STRING([--enable-mqtt], [Enable MQTT [default=no]])],,
              [enable_mqtt=no])
AM_CONDITIONAL(ENABLE_MQTT, test "x$enable_mqtt" = "xyes")
if test "x$enable_mqtt" != "xno"; then
    AC_DEFINE([ENABLE_MQTT], [1], [Enable MQTT])
    AC_CHECK_LIB([paho-mqtt3as],
                 [MQTTAsync_create],
                 [AC_SUBST([MQTT_LIBS], ["-lpaho-mqtt3as"])],
                 [AC_MSG_ERROR([paho-mqtt3as library not found!])])

fi

# /*************************/
# /* Mosquitto Auth plugin */
# /*************************/
AC_ARG_ENABLE(mosquitto-auth,
              [AS_HELP_STRING([--enable-mosquitto-auth], [Enable Mosquitto Auth [default=no]])],,
              [enable_mosquitto_auth=no])
AM_CONDITIONAL(ENABLE_MOSQUITTO_AUTH, test "x$enable_mosquitto_auth" = "xyes")
mosquitto_plg_v5=no
if test "x$enable_mosquitto_auth" != "xno"; then
    AC_DEFINE([ENABLE_MOSQUITTO_AUTH], [1], [Enable Mosquitto Auth])
    AC_CHECK_HEADERS([mosquitto.h mosquitto_plugin.h],
                     [],
                     [AC_MSG_ERROR([mosquitto headers not found!])],
                     [#include <mosquitto_broker.h>
                      #include <mosquitto.h>
                      #include <mosquitto_plugin.h>
                     ])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
                       [#include <mosquitto_broker.h>
                        #include <mosquitto.h>
                        #include <mosquitto_plugin.h>
                       ],
                       [#ifndef MOSQ_PLUGIN_VERSION
                        #error "mosquitto_plugin v5 required"
                        #endif
                       ])], [mosquitto_plg_v5=yes])
    AC_CHECK_LIB([jwt],
                 [jwt_decode],
                 [AC_SUBST([JWT_LIBS], ["-ljwt"])],
                 [AC_MSG_ERROR([libjwt not found!])])
fi
AM_CONDITIONAL(ENABLE_MOSQUITTO_PLUGIN_V5, test "x$mosquitto_plg_v5" = "xyes")
if test "x$mosquitto_plg_v5" = "xyes"; then
    AC_DEFINE([ENABLE_MOSQUITTO_PLUGIN_V5], [1], [Enable MOSQUITTO v5 plugin])
fi

# /******/
# /* rt */
# /******/
AC_CHECK_LIB([rt], [clock_gettime], , AC_MSG_ERROR([clock_gettime not found!]))

# /******/
# /* lm */
# /******/
AC_CHECK_LIB([m], [pow], , AC_MSG_ERROR([libm not found!]))

# /********/
# /* uuid */
# /********/
AC_CHECK_LIB([uuid], [uuid_generate], , AC_MSG_ERROR([libuuid not found!]))

# /***********/
# /* pthread */
# /***********/
AC_CHECK_LIB([pthread],
             [pthread_create], ,
             AC_MSG_ERROR([pthread library not found!]))

# /**********/
# /* json-c */
# /**********/
PKG_CHECK_MODULES([JSON_C], [json-c], [], [AC_MSG_ERROR([json-c not found!])])

# /***********/
# /* sqlite3 */
# /***********/
AC_CHECK_LIB([sqlite3],
             [sqlite3_open],
             [AC_SUBST([SQLITE_LIBS], ["-lsqlite3"])],
             [AC_MSG_ERROR([sqlite3 library not found!])])

# /********/
# /* CoAP */
# /********/
AC_ARG_ENABLE(coap,
              [AS_HELP_STRING([--enable-coap], [Enable CoAP [default=no]])],,
              [enable_coap=no])
AM_CONDITIONAL(ENABLE_COAP, test "x$enable_coap" = "xyes")
if test "x$enable_coap" != "xno"; then
    AC_DEFINE([ENABLE_COAP], [1], [Enable COAP])
    PKG_CHECK_MODULES([COAP], [libcoap-3], [], [AC_MSG_ERROR([libcoap-3 not found!])])
fi

# /***********/
# /* OpenWRT */
# /***********/
AC_ARG_ENABLE(openwrt,
              [AS_HELP_STRING([--enable-openwrt], [Enable OpenWRT support [default=no]])],,
              [enable_openwrt=no])
AM_CONDITIONAL(ENABLE_OPENWRT, test "x$enable_openwrt" = "xyes")
if test "x$enable_openwrt" != "xno"; then
    AC_DEFINE([ENABLE_OPENWRT], [1], [Enable OpenWRT support])
    AC_CHECK_LIB([ubox],
                 [blob_buf_init],
                 [AC_SUBST([UBOX_LIBS], ["-lubox"])],
                 [AC_MSG_ERROR([libubox not found!])])

    AC_CHECK_LIB([blobmsg_json],
                 [blobmsg_add_object],
                 [AC_SUBST([BLOBMSG_JSON_LIBS], ["-lblobmsg_json"])],
                 [AC_MSG_ERROR([libblobmsg_json not found!])])

    AC_CHECK_LIB([ubus],
                 [ubus_connect],
                 [AC_SUBST([UBUS_LIBS], ["-lubus"])],
                 [AC_MSG_ERROR([libubus not found!])])
fi

# /*********/
# /* dbus  */
# /*********/
AC_ARG_ENABLE(dbus,
              [AS_HELP_STRING([--enable-dbus], [Enable dbus support [default=no]])],,
              [enable_dbus=no])
AM_CONDITIONAL(ENABLE_DBUS, test "x$enable_dbus" = "xyes")
if test "x$enable_dbus" != "xno"; then
    AC_DEFINE([ENABLE_DBUS], [1], [Enable dbus support])
    PKG_CHECK_MODULES([DBUS], [dbus-1], [], [AC_MSG_ERROR([libdbus-1 not found!])])
fi




# /****************************/
# /* Checks for header files. */
# /****************************/
AC_CHECK_HEADERS([      arpa/inet.h \
                        fcntl.h \
                        inttypes.h \
                        locale.h \
                        netdb.h \
                        netinet/in.h \
                        stddef.h \
                        stdint.h \
                        stdlib.h \
                        string.h \
                        strings.h \
                        sys/ioctl.h \
                        sys/socket.h \
                        sys/time.h \
                        sys/timeb.h \
                        syslog.h \
                        pthread.h \
                        unistd.h], , AC_MSG_ERROR([Header file missing!]))

# /******************************************************************/
# /* Checks for typedefs, structures, and compiler characteristics. */
# /******************************************************************/
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# /*********************************/
# /* Checks for library functions. */
# /*********************************/
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm \
                atexit \
                bzero \
                gethostname \
                gettimeofday \
                inet_ntoa \
                isascii \
                localtime_r \
                memmove \
                memset \
                mkdir \
                mkfifo \
                pow \
                select \
                poll \
                setenv \
                socket \
                strchr \
                strdup \
                strerror \
                strncasecmp \
                strstr \
                strtoul \
                strtoull \
                sysinfo], , AC_MSG_ERROR([System function missing!]))

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
