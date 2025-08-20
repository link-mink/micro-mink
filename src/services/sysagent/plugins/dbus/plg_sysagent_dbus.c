/*
 *               _____  ____ __
 *   __ ____ _  /  _/ |/ / //_/
 *  / // /  ' \_/ //    / ,<
 *  \_,_/_/_/_/___/_/|_/_/|_|
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <umink_pkg_config.h>
#include <umink_plugin.h>
#include <umatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <umdaemon.h>
#include <uthash.h>
#include <time.h>
#include <utarray.h>
#include <spscq.h>
#include <semaphore.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <luaconf.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <dbus/dbus.h>
#include <umlua.h>

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "dbus";
static const char *intrspc_xml =
    "<node>"
    "  <interface name='com.umink.Signals'>"
    "    <method name='list'>"
    "      <arg type='a(sstb)' name='response' direction='out'/>"
    "    </method>"
    "    <method name='run'>"
    "      <arg type='s' name='id' direction='in'/>"
    "      <arg type='s' name='args' direction='in'/>"
    "      <arg type='s' name='auth' direction='in'/>"
    "      <arg type='s' name='response' direction='out'/>"
    "    </method>"
    "  </interface>"
    "  <interface name='org.freedesktop.DBus.Introspectable'>"
    "    <method name='Introspect'>"
    "      <arg direction='out' type='s'/>"
    "    </method>"
    "  </interface>"
    "</node>";
static umplg_mngr_t *umplgm;
static pthread_t dbus_th;

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
int COMMANDS[] = {
    // end of list marker
    -1
};

static void
handle_introspect(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    DBusMessageIter args;
    dbus_message_iter_init_append(reply, &args);
    const char *xml = intrspc_xml;
    dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &xml);
    dbus_connection_send(conn, reply, NULL);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
}

// match umsignal callback
static void
signal_match_cb(umplg_sh_t *shd, void *args)
{
    // skip special signals
    if (shd->id[0] == '@') {
        return;
    }

    // output list
    umplg_sh_t ***sgnl_lst = (umplg_sh_t ***)args;
    // add to list
    **sgnl_lst = shd;
    // next elem in output array
    (*sgnl_lst)++;
}

static void
list_signals(DBusMessage *msg, DBusConnection *conn)
{

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) {
        return;
    }

    // output list setup
    uint16_t sc = umplg_signal_count(umplgm);
    umplg_sh_t *sgnl_lst[sc];
    umplg_sh_t **slp = sgnl_lst;
    memset(sgnl_lst, 0, sizeof(umplg_sh_t *) * sc);

    // init target/function specific lua modules
    umplg_match_signal(umplgm, "*", &signal_match_cb, &slp);

    DBusMessageIter args;
    dbus_message_iter_init_append(reply, &args);
    // open array
    DBusMessageIter arr_itr;

    dbus_message_iter_open_container(&args,
                                     DBUS_TYPE_ARRAY,
                                     "(sstb)",
                                     &arr_itr);


    // loop result data
    for (int i = 0; i < sc; i++) {
        if (sgnl_lst[i] == NULL) {
            break;
        }

        // add signal struct
        DBusMessageIter sgnl_itr;
        dbus_message_iter_open_container(&arr_itr,
                                         DBUS_TYPE_STRUCT,
                                         NULL,
                                         &sgnl_itr);
        // signal id
        dbus_message_iter_append_basic(&sgnl_itr,
                                       DBUS_TYPE_STRING,
                                       &sgnl_lst[i]->id);

        // env path
        struct lua_env_d **env = utarray_eltptr(sgnl_lst[i]->args, 1);
        dbus_message_iter_append_basic(&sgnl_itr,
                                       DBUS_TYPE_STRING,
                                       &((*env)->path));

        // env interval
        dbus_message_iter_append_basic(&sgnl_itr,
                                       DBUS_TYPE_UINT64,
                                       &((*env)->interval));

        // env auto start
        dbus_bool_t b = UM_ATOMIC_GET(&(*env)->active);
        dbus_message_iter_append_basic(&sgnl_itr, DBUS_TYPE_BOOLEAN, &b);

        dbus_message_iter_close_container(&arr_itr, &sgnl_itr);
    }
    dbus_message_iter_close_container(&args, &arr_itr);

    // send reply
    dbus_connection_send(conn, reply, NULL);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
}

static void
run_signal(DBusMessage *msg, DBusConnection *conn)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) {
        return;
    }

    // input args
    char *arg_id = NULL;
    char *arg_args = NULL;
    char *arg_auth = NULL;
    int uflags = 0;

    DBusError err;
    dbus_error_init(&err);

    // Extract 3 string args
    if (!dbus_message_get_args(msg,
                               &err,
                               DBUS_TYPE_STRING, &arg_id,
                               DBUS_TYPE_STRING, &arg_args,
                               DBUS_TYPE_STRING, &arg_auth,
                               DBUS_TYPE_INVALID)) {
        umd_log(UMD, UMD_LLT_ERROR, "plg_dbus: Failed to parse args: %s", err.message);
        dbus_error_free(&err);
        return;
    }

    // user flags
    if (arg_auth != NULL && strlen(arg_auth) > 0) {
        uflags = atoi(arg_auth);
    }

    // input data
    umplg_data_std_t e_d = { .items = NULL };
    umplg_data_std_items_t items = { .table = NULL };
    umplg_data_std_item_t item = { .name = "", .value = arg_args };
    umplg_data_std_item_t auth_item = { .name = "", .value = arg_auth };

    // init std data
    umplg_stdd_init(&e_d);
    umplg_stdd_item_add(&items, &item);
    umplg_stdd_item_add(&items, &auth_item);
    umplg_stdd_items_add(&e_d, &items);

    // output buffer
    char *buff = NULL;
    size_t b_sz = 0;

    // run signal (set)
    int r = umplg_proc_signal(umplgm, arg_id, &e_d, &buff, &b_sz, uflags, NULL);
    char *p_buff = buff;
    // dbus reply
    DBusMessageIter iter;
    dbus_message_iter_init_append(reply, &iter);

    switch (r) {
        case UMPLG_RES_SUCCESS:
            if (p_buff != NULL) {
                dbus_message_iter_append_basic(&iter,
                                               DBUS_TYPE_STRING,
                                               &p_buff);
            }
            break;

        case UMPLG_RES_AUTH_ERROR: {
            const char *p_err = "authentication error";
            dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &p_err);
            break;
        }
        case UMPLG_RES_UNKNOWN_SIGNAL: {
            const char *p_err = "unknown signal";
            dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &p_err);
            break;
        }
        default: {
            const char *p_err = "unknown errorl";
            dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &p_err);
            break;
        }
    }
    HASH_CLEAR(hh, items.table);
    umplg_stdd_free(&e_d);
    free(buff);

    // send reply
    dbus_connection_send(conn, reply, NULL);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
}

// dbus thread
void *
thread_dbus(void *args)
{
    DBusConnection *conn;
    DBusError err;
    int ret;

    // init error
    dbus_error_init(&err);

    // connect
    conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (conn == NULL || dbus_error_is_set(&err)) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_dbus: Connection error: %s",
                err.message);

        dbus_error_free(&err);
        return NULL;
    }
    // request our name on the bus and check for errors
    ret = dbus_bus_request_name(conn,
                                "com.umink.Signals",
                                DBUS_NAME_FLAG_REPLACE_EXISTING,
                                &err);
    if (dbus_error_is_set(&err)) {
        umd_log(UMD, UMD_LLT_ERROR, "plg_dbus: Name error: %s", err.message);
        dbus_error_free(&err);
    }
    if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
        umd_log(UMD, UMD_LLT_ERROR, "plg_dbus: Not Primary Owner (%d)", ret);
        dbus_error_free(&err);
        return NULL;
    }

    while (!umd_is_terminating()) {
        // non blocking read, wait 50 msec
        dbus_connection_read_write(conn, 50);
        DBusMessage *msg = dbus_connection_pop_message(conn);

        // no msg, continue
        if (msg == NULL) {
            continue;
        }

        // handle list signals
        if (dbus_message_is_method_call(msg, "com.umink.Signals", "list")) {
            list_signals(msg, conn);

        // handle run signal
        } else if (dbus_message_is_method_call(msg,
                                               "com.umink.Signals",
                                               "run")) {
            run_signal(msg, conn);

        // handle introspect
        } else if (dbus_message_is_method_call(msg,
                                               "org.freedesktop.DBus.Introspectable",
                                               "Introspect")) {
            handle_introspect(conn, msg);
        }

        // free the message
        dbus_message_unref(msg);
    }
    // free dbus conn
    dbus_connection_unref(conn);
    dbus_error_free(&err);
    umd_log(UMD, UMD_LLT_INFO, "plg_dbus: [dbus thread terminating");
    return NULL;

}

/****************/
/* init handler */
/****************/
int
init(umplg_mngr_t *pm, umplgd_t *pd)
{
    umplgm = pm;
    pthread_create(&dbus_th, NULL, &thread_dbus, NULL);
    return 0;

}

/*********************/
/* terminate handler */
/*********************/
static void
term_phase_0(umplg_mngr_t *pm, umplgd_t *pd)
{
    // not used
}

static void
term_phase_1(umplg_mngr_t *pm, umplgd_t *pd)
{
    // not used
}

int
terminate(umplg_mngr_t *pm, umplgd_t *pd, int phase)
{
    switch (phase) {
    case 0:
        term_phase_0(pm, pd);
        break;
    case 1:
        term_phase_1(pm, pd);
        break;
    default:
        break;
    }
    return 0;
}



/*************************/
/* local command handler */
/*************************/
// GCOVR_EXCL_START
int
run_local(umplg_mngr_t *pm, umplgd_t *pd, int cmd_id, umplg_idata_t *data)
{
    // not used
    return 0;
}

/*******************/
/* command handler */
/*******************/
int
run(umplg_mngr_t *pm, umplgd_t *pd, int cmd_id, umplg_idata_t *data)
{
    // not used
    return 0;
}

