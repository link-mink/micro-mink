pkglib_LTLIBRARIES += plg_sysagent_coap.la
plg_sysagent_coap_la_SOURCES = %reldir%/plg_sysagent_coap.c
plg_sysagent_coap_la_CFLAGS = ${COMMON_INCLUDES} \
                              ${LUA_CFLAGS} \
                              ${COAP_CFLAGS} \
			      ${JSON_C_CFLAGS} \
                              -Isrc/services/sysagent
plg_sysagent_coap_la_LDFLAGS = -version-info 1:0:0 \
                               -shared \
                               -module \
                               -export-dynamic
plg_sysagent_coap_la_LIBADD = ${LUA_LIBS} \
                              ${COAP_LIBS} \
			      ${JSON_C_LIBS}

check_LTLIBRARIES += check_plg_sysagent_coap.la
check_plg_sysagent_coap_la_SOURCES = %reldir%/plg_sysagent_coap.c
check_plg_sysagent_coap_la_CFLAGS = ${COMMON_INCLUDES} \
                                    ${ASAN_FLAGS} \
                                    -Isrc/services/sysagent
check_plg_sysagent_coap_la_LDFLAGS = -version-info 1:0:0 \
                                     -shared \
                                     -module \
                                     -export-dynamic \
                                     -rpath /tmp
check_plg_sysagent_coap_la_LIBADD = ${LUA_LIBS}



