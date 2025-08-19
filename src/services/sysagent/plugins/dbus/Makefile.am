pkglib_LTLIBRARIES += plg_sysagent_dbus.la
plg_sysagent_dbus_la_SOURCES = %reldir%/plg_sysagent_dbus.c
plg_sysagent_dbus_la_CFLAGS = ${COMMON_INCLUDES} \
                              ${LUA_CFLAGS} \
                              ${DBUS_CFLAGS} \
                              -Isrc/services/sysagent
plg_sysagent_dbus_la_LDFLAGS = -version-info 1:0:0 \
                               -shared \
                               -module \
                               -export-dynamic
plg_sysagent_dbus_la_LIBADD = ${LUA_LIBS} \
                              ${DBUS_LIBS}

check_LTLIBRARIES += check_plg_sysagent_dbus.la
check_plg_sysagent_dbus_la_SOURCES = %reldir%/plg_sysagent_dbus.c
check_plg_sysagent_dbus_la_CFLAGS = ${COMMON_INCLUDES} \
                                    ${ASAN_FLAGS} \
                                    -Isrc/services/sysagent
check_plg_sysagent_dbus_la_LDFLAGS = -version-info 1:0:0 \
                                     -shared \
                                     -module \
                                     -export-dynamic \
                                     -rpath /tmp
check_plg_sysagent_dbus_la_LIBADD = ${LUA_LIBS}



