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
#include <umlua.h>
#include <linkhash.h>
#include <json_object.h>
#include <coap3/coap.h>
#include <coap3/coap_address.h>

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "coap";

int mink_lua_umcoap_send(lua_State *L);
static umplg_mngr_t *umplgm;
static struct umcoap_conn_mngr *umcoap_mngr;
static const struct luaL_Reg umcoap_lualib[] = { { "send",
                                                   &mink_lua_umcoap_send },
                                                 { NULL, NULL } };

typedef struct umcoap_ctx umcoap_ctx_t;

struct umcoap_ctx {
    struct {
        coap_context_t *ctx;
        coap_session_t *session;
        coap_address_t dst_addr;
        coap_uri_t uri;
    } coap;

    int coap_fd;
};

enum umcoap_connt_t {
    UMCOAP_CLIENT,
    UMCOAP_SERVER
};

struct umcoap_conn_d {
    char *name;
    enum umcoap_connt_t type;
    umplg_mngr_t *pm;
    umcoap_ctx_t *ctx;

    struct {
        char *ipv4;
        uint16_t port;
        pthread_t th;
        coap_resource_t *rsrc;
        char *rxh;
        char buff[2];

    } server;

    struct {
        char *uri;
        pthread_t th;

    } client;

    UT_hash_handle hh;
};

struct umcoap_conn_mngr {
    struct umcoap_conn_d *conns;
    pthread_mutex_t mtx;
};



/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
int COMMANDS[] = { CMD_COAP_SEND,
                   // end of list marker
                   -1 };

static umcoap_ctx_t *
umcoap_new_ctx(const char *s_uri, enum umcoap_connt_t type)
{
    // new context
    umcoap_ctx_t *ctx = calloc(1, sizeof(umcoap_ctx_t));

    // coap context
    ctx->coap.ctx = coap_new_context(NULL);
    if (ctx->coap.ctx == NULL) {
        free(ctx);
        return NULL;
    }

    if (type == UMCOAP_CLIENT) {
        // parse uri
        int len = coap_split_uri((const unsigned char *)s_uri,
                                 strlen(s_uri),
                                 &ctx->coap.uri);
        if (len != 0) {
            return NULL;
        }

        // resolve address
        coap_addr_info_t *addr_info =
            coap_resolve_address_info(&ctx->coap.uri.host,
                                      ctx->coap.uri.port,
                                      ctx->coap.uri.port,
                                      ctx->coap.uri.port,
                                      ctx->coap.uri.port,
                                      AF_UNSPEC,
                                      1 << ctx->coap.uri.scheme,
                                      COAP_RESOLVE_TYPE_REMOTE);

        if (!addr_info) {
            return NULL;

        } else {
            ctx->coap.dst_addr = addr_info->addr;
            coap_free_address_info(addr_info);
        }

        if (ctx->coap.uri.scheme == COAP_URI_SCHEME_COAP) {
            ctx->coap.session = coap_new_client_session(ctx->coap.ctx,
                                                        NULL,
                                                        &ctx->coap.dst_addr,
                                                        COAP_PROTO_UDP);

        } else if (ctx->coap.uri.scheme == COAP_URI_SCHEME_COAP_TCP) {
            ctx->coap.session = coap_new_client_session(ctx->coap.ctx,
                                                        NULL,
                                                        &ctx->coap.dst_addr,
                                                        COAP_PROTO_TCP);
        }
    } else if (type == UMCOAP_SERVER) {
        coap_context_set_block_mode(ctx->coap.ctx, COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);

    }

    return ctx;
}

static int
umcoap_send(umcoap_ctx_t *ctx, const void *data, size_t sz)
{
    // context check
    if (ctx == NULL) {
        return 1;
    }
    // buffer check
    if (data == NULL || sz == 0) {
        return 2;
    }
    // coap pdu
    coap_pdu_t *pdu =
        coap_pdu_init(COAP_MESSAGE_CON,
                      COAP_REQUEST_CODE_GET,
                      coap_new_message_id(ctx->coap.session),
                      coap_session_max_pdu_size(ctx->coap.session));
    if (!pdu) {
        return 1;
    }

    // add option list
    coap_optlist_t *optlist = NULL;
    unsigned char buff[100];

    int len = coap_uri_into_options(&ctx->coap.uri,
                                    &ctx->coap.dst_addr,
                                    &optlist,
                                    1,
                                    buff,
                                    sizeof(buff));
    if (len) {
        return 2;
    }

    if (optlist) {
        if (coap_add_optlist_pdu(pdu, &optlist) != 1) {
            return 3;
        }
    }

    coap_add_data(pdu, sz, data);

    // send
    if (coap_send(ctx->coap.session, pdu) == COAP_INVALID_MID) {
        return 4;
    }
    return 0;
}

struct umcoap_conn_d *
umcoap_conn_new(umplg_mngr_t *pm)
{
    struct umcoap_conn_d *c = calloc(1, sizeof(struct umcoap_conn_d));
    c->pm = pm;
    return c;
}

static struct umcoap_conn_mngr *
umcoap_mngr_new()
{
    struct umcoap_conn_mngr *m = malloc(sizeof(struct umcoap_conn_mngr));
    m->conns = NULL;
    pthread_mutex_init(&m->mtx, NULL);
    return m;
}

static void *
umcoap_io_thr(void *args)
{
    struct umcoap_conn_d *c = args;

    while (!umd_is_terminating()) {
        coap_io_process(c->ctx->coap.ctx, COAP_IO_WAIT);
    }

    umd_log(UMD,
            UMD_LLT_INFO,
            "%s: [thread (%s) terminating]",
            PLG_ID,
            c->name);
    return NULL;
}

void
umcoap_srvr_hndlr(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    // output buffer
    char *b = NULL;
    size_t b_sz = 0;
    struct umcoap_conn_d *c = coap_resource_get_userdata(resource);

    // process signal
    umplg_data_std_t e_d = { .items = NULL };
    umplg_data_std_items_t items = { .table = NULL };
    static char *methods[] = { "0.00",   "GET",   "POST",  "PUT",
                               "DELETE", "FETCH", "PATCH", "iPATCH" };
    umplg_data_std_item_t item_reqt = {
        .name = "request_type",
        .value = methods[coap_pdu_get_code(request)]
    };
    umplg_data_std_item_t item_data = { .name = "data", .value = NULL };
    size_t pdu_l = 0;
    const uint8_t *pdu_d = NULL;
    char *pdu_str = c->server.buff;
    if (coap_get_data(request, &pdu_l, &pdu_d) == 1) {
        // use dynamic buffer
        if (pdu_l >= sizeof(c->server.buff)) {
            pdu_str = malloc(pdu_l + 1);

        // use internal buffer
        }

        pdu_str[pdu_l] = '\0';
        memcpy(pdu_str, pdu_d, pdu_l);
        item_data.value = pdu_str;
        umplg_stdd_item_add(&items, &item_data);
    }

    // create signal input data
    umplg_stdd_init(&e_d);
    umplg_stdd_item_add(&items, &item_reqt);
    umplg_stdd_items_add(&e_d, &items);

    umplg_proc_signal(c->pm, c->server.rxh, &e_d, &b, &b_sz, 0, NULL);

    // free dynamic buffer
    if (pdu_str != c->server.buff) {
        free(pdu_str);
    }

    // check reply
    if (b_sz > 0 && b != NULL) {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
        coap_add_data(response, b_sz, (const uint8_t *)b);
        free(b);

    } else {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_VALID);
    }
}


static struct umcoap_conn_d *
umcoap_mngr_add_conn(struct umcoap_conn_mngr *m,
                     umplg_mngr_t *pm,
                     enum umcoap_connt_t type,
                     const struct json_object *j_conn)
{
    if (type == UMCOAP_CLIENT) {
        // name
        struct json_object *j_name = json_object_object_get(j_conn, "name");
        // uri
        struct json_object *j_uri = json_object_object_get(j_conn, "uri");
        // sanity check
        if (j_uri == NULL || j_name == NULL) {
            return NULL;
        }

        // label should not be present
        struct umcoap_conn_d *tmp_conn = NULL;
        // GCOVR_EXCL_BR_START
        HASH_FIND_STR(m->conns, json_object_get_string(j_name), tmp_conn);
        // GCOVR_EXCL_BR_STOP
        if (tmp_conn != NULL) {
            return NULL;
        }
        umcoap_ctx_t *ctx = umcoap_new_ctx(json_object_get_string(j_uri), UMCOAP_CLIENT);
        if (ctx == NULL) {
            return NULL;
        }
        // new connection
        struct umcoap_conn_d *c = umcoap_conn_new(pm);
        c->ctx = ctx;
        c->name = strdup(json_object_get_string(j_name));
        c->client.uri = strdup(json_object_get_string(j_uri));
        c->type = UMCOAP_CLIENT;
        // lock
        pthread_mutex_lock(&m->mtx);
        // add to conn list
        // GCOVR_EXCL_BR_START
        HASH_ADD_KEYPTR(hh, m->conns, c->name, strlen(c->name), c);
        // GCOVR_EXCL_BR_STOP
        // unlock
        pthread_mutex_unlock(&m->mtx);
        // start client thread
        pthread_create(&c->client.th, NULL, &umcoap_io_thr, c);
        return c;


    } else if (type == UMCOAP_SERVER) {
        // name
        struct json_object *j_name = json_object_object_get(j_conn, "name");
        // ipv4
        struct json_object *j_ipv4 = json_object_object_get(j_conn, "ipv4");
        // port
        struct json_object *j_port = json_object_object_get(j_conn, "port");

        // sanity check
        if (j_name == NULL || j_ipv4 == NULL || j_port == NULL) {
            return NULL;
        }

        // label should not be present
        struct umcoap_conn_d *tmp_conn = NULL;
        // GCOVR_EXCL_BR_START
        HASH_FIND_STR(m->conns, json_object_get_string(j_name), tmp_conn);
        // GCOVR_EXCL_BR_STOP
        if (tmp_conn != NULL) {
            return NULL;
        }
        umcoap_ctx_t *ctx = umcoap_new_ctx(NULL, UMCOAP_SERVER);
        if (ctx == NULL) {
            return NULL;
        }
        // new connection
        struct umcoap_conn_d *c = umcoap_conn_new(pm);
        c->ctx = ctx;
        c->type = UMCOAP_SERVER;
        c->name = strdup(json_object_get_string(j_name));
        c->server.ipv4 = strdup(json_object_get_string(j_ipv4));
        c->server.port = json_object_get_int(j_port);

        // init coap server
        uint32_t shb = coap_get_available_scheme_hint_bits(0, 0, COAP_PROTO_NONE);
        coap_str_const_t *s_addr = coap_make_str_const(c->server.ipv4);
        coap_addr_info_t *i_lst =
            coap_resolve_address_info(s_addr,
                                      c->server.port,
                                      c->server.port,
                                      c->server.port,
                                      c->server.port,
                                      0,
                                      shb,
                                      COAP_RESOLVE_TYPE_LOCAL);

        bool have_ep = false;
        for (coap_addr_info_t *info = i_lst; info != NULL; info = info->next) {
            coap_endpoint_t *ep;
            ep = coap_new_endpoint(ctx->coap.ctx, &info->addr, info->proto);
            if (!ep) {
                umd_log(UMD,
                        UMD_LLT_WARNING,
                        "%s: [cannot create endpoint for CoAP [%s], "
                        "proto [%u]]",
                        PLG_ID,
                        c->name,
                        info->proto);
            } else {
                have_ep = true;
            }
        }
        coap_free_address_info(i_lst);

        if (!have_ep) {
            umd_log(
                UMD,
                UMD_LLT_ERROR,
                "%s: [no context available for server [%s], interface [%s]]",
                PLG_ID,
                c->name,
                (const char *)s_addr->s);
            return NULL;
        }

        // create resources
        struct json_object *j_rsrcs = json_object_object_get(j_conn, "resources");
        if (j_rsrcs != NULL && json_object_is_type(j_rsrcs, json_type_array)) {
            int rsrc_l = json_object_array_length(j_rsrcs);
            for (int j = 0; j < rsrc_l; ++j) {
                // get array object
                struct json_object *j_res = json_object_array_get_idx(j_rsrcs, j);
                // verify type
                if (!json_object_is_type(j_res, json_type_object)) {
                    continue;
                }

                // get values
                struct json_object *j_res_name = json_object_object_get(j_res, "name");
                struct json_object *j_rxh = json_object_object_get(j_res, "rx_handler");
                // create coap resource
                coap_str_const_t *cres_name = coap_make_str_const(json_object_get_string(j_res_name));
                coap_resource_t *rsrc = coap_resource_init(cres_name, 0);
                coap_register_request_handler(rsrc, COAP_REQUEST_GET, &umcoap_srvr_hndlr);
                coap_register_request_handler(rsrc, COAP_REQUEST_POST, &umcoap_srvr_hndlr);
                coap_resource_set_userdata(rsrc, c);
                c->server.rsrc = rsrc;
                c->server.rxh = strdup(json_object_get_string(j_rxh));
                coap_add_resource(ctx->coap.ctx, rsrc);
            }
        }

        // start server thread
        pthread_create(&c->server.th, NULL, &umcoap_io_thr, c);

        return c;
    }

    return NULL;

}

struct umcoap_conn_d *
umcoap_mngr_get_conn(struct umcoap_conn_mngr *m, const char *name)
{
    if (m == NULL) {
        return NULL;
    }
    struct umcoap_conn_d *tmp_conn = NULL;
    // lock
    pthread_mutex_lock(&m->mtx);
    HASH_FIND_STR(m->conns, name, tmp_conn); // GCOVR_EXCL_BR_LINE
    // unlock
    pthread_mutex_unlock(&m->mtx);
    return tmp_conn;
}

static int
process_cfg(umplg_mngr_t *pm, struct umcoap_conn_mngr *mngr)
{
    // get config
    if (pm->cfg == NULL) {
        return 1;
    }
    // cast (100% json)
    struct json_object *jcfg = pm->cfg;
    // find plugin id
    if (!json_object_is_type(jcfg, json_type_object)) {
        return 2;
    }
    // loop keys
    struct json_object *plg_cfg = NULL;
    json_object_object_foreach(jcfg, k, v)
    {
        if (strcmp(k, PLG_ID) == 0) {
            plg_cfg = v;
            break;
        }
    }
    // config found?
    if (plg_cfg == NULL) {
        return 3;
    }
    // get clients
    struct json_object *jobj = json_object_object_get(plg_cfg, "clients");
    if (jobj != NULL && json_object_is_type(jobj, json_type_array)) {
        // loop an verify connections
        int conn_l = json_object_array_length(jobj);
        for (int i = 0; i < conn_l; ++i) {
            struct json_object *j_conn = json_object_array_get_idx(jobj, i);
            // check env object type
            if (!json_object_is_type(j_conn, json_type_object)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "%s: [%s]",
                        PLG_ID,
                        "invalid client connection object");
                return 4;
            }
            // get connection values
            struct json_object *j_n = json_object_object_get(j_conn, "name");
            struct json_object *j_uri = json_object_object_get(j_conn, "uri");
            // all values are mandatory
            if (!(j_n && j_uri)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "%s: [%s]",
                        PLG_ID,
                        "malformed client connection (missing values)");
                return 5;
            }
            // check types
            if (!(json_object_is_type(j_n, json_type_string) &&
                  json_object_is_type(j_uri, json_type_string))) {

                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "%s: [%s]",
                        PLG_ID,
                        "malformed client connection (wrong type)");
                return 6;
            }

            // create connection
            struct umcoap_conn_d *conn =
                umcoap_mngr_add_conn(mngr, pm, UMCOAP_CLIENT, j_conn);
            if (!conn) {
                continue;
            }

            umd_log(UMD,
                    UMD_LLT_INFO,
                    "%s: [adding client connection [%s]",
                    PLG_ID,
                    conn->name);
        }
    }

    // get servers
    jobj = json_object_object_get(plg_cfg, "servers");
    if (jobj != NULL && json_object_is_type(jobj, json_type_array)) {
        // loop an verify connections
        int conn_l = json_object_array_length(jobj);
        for (int i = 0; i < conn_l; ++i) {
            struct json_object *j_conn = json_object_array_get_idx(jobj, i);
            // check env object type
            if (!json_object_is_type(j_conn, json_type_object)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "%s: [%s]",
                        PLG_ID,
                        "invalid server connection object");
                return 4;
            }
            // get connection values
            struct json_object *j_n = json_object_object_get(j_conn, "name");
            struct json_object *j_ipv4 = json_object_object_get(j_conn, "ipv4");
            struct json_object *j_port = json_object_object_get(j_conn, "port");

            // all values are mandatory
            if (!(j_n && j_ipv4 && j_port)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "%s: [%s]",
                        PLG_ID,
                        "malformed server connection (missing values)");
                return 5;
            }
            // check types
            if (!(json_object_is_type(j_n, json_type_string) &&
                  json_object_is_type(j_ipv4, json_type_string) &&
                  json_object_is_type(j_port, json_type_int))) {

                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "%s: [%s]",
                        PLG_ID,
                        "malformed server connection (wrong type)");
                return 6;
            }

            // create connection
            struct umcoap_conn_d *conn =
                umcoap_mngr_add_conn(mngr, pm, UMCOAP_SERVER, j_conn);
            if (!conn) {
                continue;
            }

            umd_log(UMD,
                    UMD_LLT_INFO,
                    "%s: [adding server connection [%s]",
                    PLG_ID,
                    conn->name);

        }
    }
    return 0;
}

static void
init_umcoap_lua_module(lua_State *L)
{
    luaL_newlib(L, umcoap_lualib);
}
/********************************************/
/* COAP module create (signal init handler) */
/********************************************/
static int
umcoap_module_sig_run(umplg_sh_t *shd,
                      umplg_data_std_t *d_in,
                      char **d_out,
                      size_t *out_sz,
                      void *args)
{

    // get lua state (assume args != NULL)
    lua_State *L = args;

    // get M module from globals
    lua_getglobal(L, "M");
    // add COAP sub-module
    lua_pushstring(L, "coap");
    init_umcoap_lua_module(L);
    // add module table to M table
    lua_settable(L, -3);
    // remove M table from stack
    lua_pop(L, 1);

    // success
    return 0;
}

/****************/
/* init handler */
/****************/
int
init(umplg_mngr_t *pm, umplgd_t *pd)
{

    umplgm = pm;
    coap_startup();
    // conn manager
    umcoap_mngr = umcoap_mngr_new();
    if (process_cfg(pm, umcoap_mngr)) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "%s: [%s]",
                PLG_ID,
                "cannot process plugin configuration");
    }

    // create signal handler for creating COAP module
    // when per-thread Lua state creates the M module
    umplg_sh_t *sh = calloc(1, sizeof(umplg_sh_t));
    sh->id = strdup("@init_lua_sub_module:coap");
    sh->run = &umcoap_module_sig_run;
    sh->running = false;

    // register signal
    umplg_reg_signal(pm, sh);



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

/***********************************/
/* local CMD_COAP_SEAND (standard) */
/***********************************/
static void
impl_coap_send(umplg_data_std_t *data)
{
    // sanity check
    if (data == NULL || utarray_len(data->items) < 3) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "%s: [%s]",
                PLG_ID,
                "CMD_COAP_SEND invalid data");
        return;
    }
    // items elem at index
    const umplg_data_std_items_t *row = utarray_eltptr(data->items, 0);
    // sanity check (columns)
    if (HASH_COUNT(row->table) < 1) {
        return;
    }
    // get first column
    const umplg_data_std_item_t *column = row->table;

    // get connection
    struct umcoap_conn_d *c = umcoap_mngr_get_conn(umcoap_mngr, column->value);
    if (c == NULL) {
        return;
    }
    // data
    row = utarray_eltptr(data->items, 2);
    const umplg_data_std_item_t *coap_data = row->table;
    umcoap_send(c->ctx, coap_data->value, strlen(coap_data->value));
}

/*************************/
/* local command handler */
/*************************/
// GCOVR_EXCL_START
int
run_local(umplg_mngr_t *pm, umplgd_t *pd, int cmd_id, umplg_idata_t *data)
{
    // null checks
    if (data == NULL) {
        return -1;
    }

    // plugin2plugin local interface (standard)
    if (data->type == UMPLG_DT_STANDARD) {
        // plugin input data
        umplg_data_std_t *plg_d = data->data;
        // check command id
        switch (cmd_id) {
        case CMD_COAP_SEND:
            impl_coap_send(plg_d);
            break;

        default:
            break;
        }

        return 0;
    }

    // unsupported interface
    return -2;
}

int
mink_lua_umcoap_send(lua_State *L)
{
    // min 2 args: conn name, data
    if (lua_gettop(L) < 2) {
        lua_pushboolean(L, false);
        return 1;
    }

    // get args
    const char *c = lua_tostring(L, 1);
    const char *d = lua_tostring(L, 2);

    // get connection
    struct umcoap_conn_d *conn = umcoap_mngr_get_conn(umcoap_mngr, c);
    if (conn == NULL) {
        lua_pushboolean(L, false);
        return 1;
    }

    // send
    int r = umcoap_send(conn->ctx, d, strlen(d));
    // result
    lua_pushboolean(L, !r);
    return 1;

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

