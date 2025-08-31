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
#include <string.h>
#include <luaconf.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <umdaemon.h>
#include <umdb.h>
#include <json_object.h>
#include <json_tokener.h>

/*********/
/* Types */
/*********/
typedef struct {
    const char *key;
    const char *value;
} mink_cdata_column_t;

/**********/
/* Signal */
/**********/
static char *
mink_lua_signal(const char *s,
                const char *d,
                const char *auth,
                void *md,
                enum umplg_ret_t *res)
{
    // plugin manager
    umplg_mngr_t *pm = md;
    // check signal
    if (!s) {
        *res = UMPLG_RES_UNKNOWN_SIGNAL;
        return strdup("");
    }

    // check auth (already checked for errors)
    int usr_flags = 0;
    if (auth != NULL){
        json_object *j = json_tokener_parse(auth);
        json_object *j_usr = json_object_object_get(j, "flags");
        usr_flags = json_object_get_int(j_usr);
        json_object_put(j);
    }

    // create std data
    umplg_data_std_t e_d = { .items = NULL };
    umplg_data_std_items_t items = { .table = NULL };
    umplg_data_std_item_t item = { .name = "", .value = (char *)(d ? d : "") };
    umplg_data_std_item_t auth_item = { .name = "",
                                        .value = (char *)(auth ? auth : "") };
    // init std data
    umplg_stdd_init(&e_d);
    umplg_stdd_item_add(&items, &item);
    umplg_stdd_item_add(&items, &auth_item);
    umplg_stdd_items_add(&e_d, &items);
    // output buffer (allocated in signal handler)
    char *b = NULL;
    size_t sz = 0;
    // process signal
    int r = umplg_proc_signal(pm, s, &e_d, &b, &sz, usr_flags, NULL);
    *res = r;
    // success
    if (r == UMPLG_RES_SUCCESS) {
        // cleanup
        HASH_CLEAR(hh, items.table);
        umplg_stdd_free(&e_d);
        return b;

    // auth error
    } else if (r == UMPLG_RES_AUTH_ERROR) {
        // cleanup
        HASH_CLEAR(hh, items.table);
        umplg_stdd_free(&e_d);
        return strdup("");
    }

    // ** other errors **
    // cleanup
    HASH_CLEAR(hh, items.table);
    umplg_stdd_free(&e_d);
    // error
    return strdup("");
}

/*****************************/
/* Get plugin data row count */
/*****************************/
static size_t
mink_lua_cmd_data_sz(void *p)
{
    if (p == NULL) {
        return 0;
    }
    // cast (unsafe) to standard plugin data type
    const umplg_data_std_t *d = p;
    // row count
    return utarray_len(d->items);
}

/**************************************************/
/* Get plugin data columns count for specific row */
/**************************************************/
static size_t
mink_lua_cmd_data_row_sz(const int r, void *p)
{
    // cast (unsafe) to standard plugin data type
    umplg_data_std_t *d = p;
    // verify row index
    if (r >= utarray_len(d->items)) {
        return 0;
    }
    // items elem at index
    const umplg_data_std_items_t *items = utarray_eltptr(d->items, r);
    // column count for row at index
    return HASH_COUNT(items->table);
}

/********************************/
/* Get plugin data column value */
/********************************/
static mink_cdata_column_t
mink_lua_cmd_data_get_column(const int r, const int c, void *p)
{
    // get row count
    size_t rc = mink_lua_cmd_data_sz(p);
    // sanity check (rows)
    if (rc <= r) {
        mink_cdata_column_t cdata = { 0 };
        return cdata;
    }
    // cast (unsafe) to standard plugin data type
    umplg_data_std_t *d = p;
    // get row at index
    umplg_data_std_items_t *row = utarray_eltptr(d->items, r);
    // sanity check (columns)
    if (HASH_COUNT(row->table) <= c) {
        mink_cdata_column_t cdata = { 0 };
        return cdata;
    }
    // get column at index
    umplg_data_std_item_t *column = NULL;
    int i = 0;
    for (column = row->table; column != NULL; column = column->hh.next) {
        if (i == c) {
            // return column value
            mink_cdata_column_t cdata = { column->name, column->value };
            return cdata;
        }
        ++i;
    }

    mink_cdata_column_t cdata = { 0 };
    return cdata;
}

/*******************/
/* Free plugin res */
/*******************/
static void
mink_lua_free_res(void *p)
{
    umplg_data_std_t *d = p;
    umplg_stdd_free(d);
    free(d);
}

/**************************/
/* Create new plugin data */
/**************************/
static void *
mink_lua_new_cmd_data()
{
    umplg_data_std_t *d = malloc(sizeof(umplg_data_std_t));
    d->items = NULL;
    umplg_stdd_init(d);
    return d;
}

/************/
/* cmd_call */
/************/
static int
mink_lua_cmd_call(void *md, int argc, const char **args, void *out)
{
    // plugin manager
    umplg_mngr_t *pm = md;
    // argument count check
    if (argc < 1) {
        return -1;
    }
    // output check
    if (!out) {
        return -2;
    }
    // cmd data
    umplg_data_std_t *d = out;
    // get command id
    int cmd_id = umplg_get_cmd_id(pm, args[0]);
    // cmd arguments
    for (int i = 1; i < argc; i++) {
        // column map
        umplg_data_std_items_t cmap = { .table = NULL };
        // insert columns
        umplg_data_std_item_t item = { .name = "", .value = (char *)args[i] };
        umplg_stdd_item_add(&cmap, &item);
        // add row
        umplg_stdd_items_add(d, &cmap);
        // cleanup
        HASH_CLEAR(hh, cmap.table);
    }
    // plugin input data
    umplg_idata_t idata = { UMPLG_DT_STANDARD, d };
    // run plugin method
    int res = umplg_run(pm, cmd_id, idata.type, &idata, true);
    // result
    return res;

}

/************/
/* get_args */
/************/
int
mink_lua_get_args(lua_State *L)
{
    // get std data (only for SIGNALS)
    lua_pushstring(L, "mink_stdd");
    lua_gettable(L, LUA_REGISTRYINDEX);
    if (!lua_istable(L, -1)) {
        return 0;
    }
    // lua state per-thread ref counting
    size_t tl = lua_rawlen(L, -1);
    if (tl == 0) {
        return 0;
    }
    lua_pushnumber(L, tl);
    lua_gettable(L, -2);

    // get user data pointer
    umplg_data_std_t *d = lua_touserdata(L, -1);
    size_t sz = mink_lua_cmd_data_sz(d);

    // lua table
    lua_newtable(L);

    // tmp column key
    int k = 0;
    // loop result data (rows)
    for (int i = 0; i < sz; i++) {
        // table key (array)
        lua_pushnumber(L, i + 1);

        // create table row
        lua_newtable(L);

        // get column count
        size_t sz_c = mink_lua_cmd_data_row_sz(i, d);
        // reset tmp key
        k = 0;
        // loop columns
        for (int j = 0; j < sz_c; j++) {
            // get column key/value
            mink_cdata_column_t c = mink_lua_cmd_data_get_column(i, j, d);
            // add column to lua table
            if (c.value != NULL) {
                ++k;
                // update key, if not null
                if (c.key != NULL && strlen(c.key) > 0) {
                    // k = ffi.string(c.key)
                    lua_pushstring(L, c.key);

                } else {
                    // k = 1
                    lua_pushnumber(L, k);
                }

                // add value and add table column
                lua_pushstring(L, c.value);
                lua_settable(L, -3);
            }
        }

        // add table row
        lua_settable(L, -3);
    }

    // return table
    return 1;
}

/********************/
/* cmd_call wrapper */
/********************/
int
mink_lua_do_cmd_call(lua_State *L)
{
    if (!lua_istable(L, -1)) {
        return 0;
    }
    // table size (length)
    size_t sz = lua_objlen(L, -1);
    // crate string array
    char *cmd_arg[sz];
    for (int i = 0; i<sz; i++){
        // get t[i] table value
        lua_pushnumber(L, i + 1);
        lua_gettable(L, -2);
        // check type
        if (lua_isstring(L, -1)) {
            cmd_arg[i] = strdup(lua_tostring(L, -1));

        } else if (lua_isnumber(L, -1)) {
            cmd_arg[i] = malloc(32);
            snprintf(cmd_arg[i], 32, "%d", (int)lua_tonumber(L, -1));

        } else if (lua_isboolean(L, -1)) {
            cmd_arg[i] = malloc(2);
            snprintf(cmd_arg[i], 2, "%d", lua_toboolean(L, -1));

        } else {
            cmd_arg[i] = strdup("");
        }
        lua_pop(L, 1);
    }

    // get pm
    lua_pushstring(L, "mink_pm");
    lua_gettable(L, LUA_REGISTRYINDEX);
    umplg_mngr_t *pm = lua_touserdata(L, -1);

    // output buffer
    umplg_data_std_t d = { .items = NULL };
    umplg_stdd_init(&d);
    // call method
    int res = mink_lua_cmd_call(pm, sz, (const char **)cmd_arg, &d);
    // free tmp string array
    for (int i = 0; i < sz; i++) {
        free(cmd_arg[i]);
    }
    // if successful, copy C data to lua table
    if (res == 0){
        // result
        lua_newtable(L);
        // cmd data size
        sz = mink_lua_cmd_data_sz(&d);
        // loop result data (rows)
        for (int i = 0; i < sz; i++) {
            // add row to table
            lua_pushnumber(L, i + 1);
            // crate table row
            lua_newtable(L);
            // get column count
            size_t sz_c = mink_lua_cmd_data_row_sz(i, &d);
            // loop columns
            for (int j = 0; j < sz_c; j++) {
                // get column key/value
                mink_cdata_column_t c = mink_lua_cmd_data_get_column(i, j, &d);
                // add column to lua table
                if (c.value != NULL) {
                    int k = 1;
                    // update key, if not null
                    if (c.key != NULL && strlen(c.key) > 0) {
                        // k = ffi.string(c.key)
                        lua_pushstring(L, c.key);

                    } else {
                        // k = 1
                        lua_pushnumber(L, k);
                    }

                    // add value and add table column
                    lua_pushstring(L, c.value);
                    lua_settable(L, -3);
                }
            }
            // add table row
            lua_settable(L, -3);
        }
        // cleanup
        umplg_stdd_free(&d);
        return 1;

    }
    umplg_stdd_free(&d);
    return 0;
}

/******************/
/* signal wrapper */
/******************/
int
mink_lua_do_signal(lua_State *L)
{
    // signal name required
    if (lua_gettop(L) < 1) {
        lua_pushstring(L, "");
        lua_pushnumber(L, UMPLG_RES_UNKNOWN_SIGNAL);
    }
    // signal data/signal name
    const char *d = NULL;
    const char *s = NULL;
    const char *auth = NULL;
    int idx_offset = 0;

    // auth info present
    if (lua_gettop(L) >= 3) {
        idx_offset = -3;

    // signal name and payload
    } else if (lua_gettop(L) >= 2) {
        idx_offset = -2;

    // signal name only
    } else {
        idx_offset = -1;
    }

    // check types
    for (int i = idx_offset; i < 0; i++) {
        if (!lua_isstring(L, i)) {
            lua_pushstring(L, "");
            lua_pushnumber(L, UMPLG_RES_INVALID_TYPE);
            return 2;
        }
    }

    // get signal name
    s = lua_tostring(L, idx_offset++);
    // get payload data
    if (idx_offset < 0){
        d = lua_tostring(L, idx_offset++);
    }
    // get user info
    if (idx_offset < 0){
        auth = lua_tostring(L, idx_offset++);
    }

    // get pm
    lua_pushstring(L, "mink_pm");
    lua_gettable(L, LUA_REGISTRYINDEX);
    umplg_mngr_t *pm = lua_touserdata(L, -1);
    lua_pop(L, 1);

    // signal
    enum umplg_ret_t res = UMPLG_RES_UNKNOWN_SIGNAL;
    char *s_res = mink_lua_signal(s, d, auth, pm, &res);
    // string result
    if (s_res != NULL) {
        lua_pushstring(L, s_res);
        free(s_res);

    } else {
        lua_pushstring(L, "");
    }
    // status result
    lua_pushnumber(L, res);

    // return status and string result parts
    return 2;
}

/********************/
/* perf counter inc */
/********************/
int
mink_lua_do_perf_inc(lua_State *L)
{
    // counter name is required
    if (lua_gettop(L) < 1 || !lua_isstring(L, 1)) {
        return 0;
    }
    // counter name
    const char *id = lua_tostring(L, 1);
    // counter increment default value
    int inc = 1;
    // custom increment value
    if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
        inc = (int)lua_tonumber(L, 2);
    }
    // crate counter if needed
    umc_t *c = umc_new_counter(UMD->perf, id, UMCT_INCREMENTAL);
    // increment perf counter
    umc_inc(c, inc);

    return 0;
}

/********************/
/* perf counter set */
/********************/
int
mink_lua_do_perf_set(lua_State *L)
{
    // counter name and value are required
    if (lua_gettop(L) < 2) {
        return 0;
    }
    // check types
    if (!lua_isstring(L, 1) || !lua_isnumber(L, 2)) {
        return 0;
    }

    // counter name
    const char *id = lua_tostring(L, 1);
    // counter value
    int val = lua_tonumber(L, 2);
    // crate counter if needed
    umc_t *c = umc_new_counter(UMD->perf, id, UMCT_GAUGE);
    // set perf counter
    umc_set(c, val);

    return 0;
}

/***********************/
/* perf counters match */
/***********************/
static void
perf_match_cb(umc_t *c, void *arg)
{
    // create temp umc
    umc_t umc;
    // copy id pointer (safe) and type
    umc.idp = c->idp;
    umc.type = c->type;
    // copy last/max/ts_diff/delta values
    umc.values.last.value = c->values.last.value;
    umc.values.max = c->values.max;
    umc.values.delta = c->values.delta;
    umc.values.ts_diff = c->values.ts_diff;
    // add to list
    UT_array *lst = arg;
    utarray_push_back(lst, &umc);
}

int
mink_lua_do_perf_match(lua_State *L)
{
    // counter name is required
    if (lua_gettop(L) < 1 || !lua_isstring(L, 1)) {
        return 0;
    }
    // counter name
    const char *ptrn = lua_tostring(L, 1);
    // tmp result
    UT_array *lst;
    UT_icd umc_icd = { sizeof(umc_t), NULL, NULL, NULL };
    utarray_new(lst, &umc_icd);
    umc_match(UMD->perf, ptrn, true, perf_match_cb, lst);
    // generate lua result table
    lua_newtable(L);
    // loop result
    umc_t *umc_p = NULL;
    for (umc_p = (umc_t *)utarray_front(lst); umc_p != NULL;
         umc_p = (umc_t *)utarray_next(lst, umc_p)) {

        // outer table key (counter id)
        lua_pushstring(L, umc_p->idp);
        // inner table (row)
        lua_newtable(L);

        // last
        lua_pushstring(L, "last");
        lua_pushnumber(L, umc_p->values.last.value);
        lua_settable(L, -3);
        // max
        if (umc_p->type == UMCT_GAUGE) {
            lua_pushstring(L, "max");
            lua_pushnumber(L, umc_p->values.max);
            lua_settable(L, -3);
        }
        // rate
        if (umc_p->type == UMCT_INCREMENTAL) {
            lua_pushstring(L, "rate");
            lua_pushnumber(L, umc_get_rate(umc_p, false));
            lua_settable(L, -3);
        }

        // set outer table row
        lua_settable(L, -3);
    }

    // cleanup
    utarray_free(lst);

    // one table
    return 1;
}

/*****************/
/* user data set */
/*****************/
int
mink_lua_do_db_set(lua_State *L)
{
    // db name, key, and value are required
    if (lua_gettop(L) < 3) {
        return 0;
    }

    // string values required
    if (!(lua_isstring(L, 1) && lua_isstring(L, 2) && lua_isstring(L, 3))) {
        return 0;
    }

    // get values
    const char *db = lua_tostring(L, 1);
    const char *k = lua_tostring(L, 2);
    const char *v = lua_tostring(L, 3);
    uint8_t perm = 0;
    // default = in-mem dbm
    const char *dbm_name = "mink_dbm_mem";

    // perm flag
    if (lua_gettop(L) > 3 && lua_isnumber(L, 4)) {
        perm = (uint8_t)lua_tonumber(L, 4);
        // switch to permanent dbm
        if (perm == 1) {
            dbm_name = "mink_dbm_perm";
        }
    }

    // get dbm
    lua_pushstring(L, dbm_name);
    lua_gettable(L, LUA_REGISTRYINDEX);
    umdb_mngrd_t *dbm = lua_touserdata(L, -1);
    lua_pop(L, 1);

    // init storage
    int r = umdb_mngr_store_init(dbm, db);
    if (r != 0) {
        return 0;
    }

    // set data
    r = umdb_mngr_store_set(dbm, db, k, v);
    if (r != 0) {
        return 0;
    }

    return 0;
}

/*****************/
/* user data get */
/*****************/
int
mink_lua_do_db_get(lua_State *L)
{
    // db name and key are required
    if (lua_gettop(L) < 2) {
        return 0;
    }

    // string values required
    if (!(lua_isstring(L, 1) && lua_isstring(L, 2))) {
        return 0;
    }

    // get values
    const char *db = lua_tostring(L, 1);
    const char *k = lua_tostring(L, 2);
    uint8_t perm = 0;
    // default = in-mem dbm
    const char *dbm_name = "mink_dbm_mem";

    // perm flag
    if (lua_gettop(L) > 2 && lua_isnumber(L, 3)) {
        perm = (uint8_t)lua_tonumber(L, 3);
        // switch to permanent dbm
        if (perm == 1) {
            dbm_name = "mink_dbm_perm";
        }
    }

    // get dbm
    lua_pushstring(L, dbm_name);
    lua_gettable(L, LUA_REGISTRYINDEX);
    umdb_mngrd_t *dbm = lua_touserdata(L, -1);
    lua_pop(L, 1);

    // init storage
    int r = umdb_mngr_store_init(dbm, db);
    if (r != 0) {
        return 0;
    }

    // get data
    char *ob = NULL;
    size_t ob_sz = 0;
    r = umdb_mngr_store_get(dbm, db, k, &ob, &ob_sz);
    if (r != 0) {
        if (ob_sz > 0) {
            free(ob);
        }
        return 0;
    }

    lua_pushstring(L, ob);
    free(ob);
    return 1;
}

/*******/
/* log */
/*******/
int
mink_lua_log(lua_State *L)
{
    // level, message
    if (lua_gettop(L) < 2) {
        return 0;
    }

    // string values required
    if (!(lua_isstring(L, 1) && lua_isstring(L, 2))) {
        return 0;
    }

    // get values
    const char *l = lua_tostring(L, 1);
    const char *m = lua_tostring(L, 2);

    // default level
    int i_l = UMD_LLT_INFO;

    if (strcmp(l, "warn") == 0) {
        i_l = UMD_LLT_WARNING;
    } else if (strcmp(l, "error") == 0) {
        i_l = UMD_LLT_ERROR;
    }

    umd_log(UMD, i_l, m);

    return 0;

}
