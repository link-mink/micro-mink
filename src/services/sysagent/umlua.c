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
#include <linkhash.h>
#include <uthash.h>
#include <time.h>
#include <json_object.h>
#include <luaconf.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <utarray.h>
#include <umdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <umlua.h>

#ifdef UNIT_TESTING
#include <cmocka_tests.h>
#endif

/************************/
/* Thread local storage */
/************************/
static pthread_key_t tls_key;
pthread_t cli_server_th;

#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM == 501

#    define luaL_newlibtable(L, l) \
        lua_createtable(L, 0, sizeof(l) / sizeof((l)[0]) - 1)

#    define luaL_newlib(L, l) (luaL_newlibtable(L, l), luaL_setfuncs(L, l, 0))

/*
** Adapted from Lua 5.2.0
*/
static void
luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup)
{
    luaL_checkstack(L, nup + 1, "too many upvalues");
    for (; l->name != NULL; l++) { /* fill the table with given functions */
        int i;
        lua_pushstring(L, l->name);
        for (i = 0; i < nup; i++) /* copy upvalues to the top */
            lua_pushvalue(L, -(nup + 1));
        lua_pushcclosure(L, l->func, nup); /* closure with those upvalues */
        lua_settable(L, -(nup + 3));
    }
    lua_pop(L, nup); /* remove upvalues */
}
#endif

/*******************/
/* mink lua module */
/*******************/
int mink_lua_do_signal(lua_State *L);
int mink_lua_get_args(lua_State *L);
int mink_lua_do_cmd_call(lua_State *L);
int mink_lua_do_perf_inc(lua_State *L);
int mink_lua_do_perf_set(lua_State *L);
int mink_lua_do_perf_match(lua_State *L);
int mink_lua_do_db_set(lua_State *L);
int mink_lua_do_db_get(lua_State *L);
int mink_lua_log(lua_State *L);

// registered lua module methods
static const struct luaL_Reg mink_lualib[] = {
    { "get_args", &mink_lua_get_args },
    { "signal", &mink_lua_do_signal },
    { "cmd_call", &mink_lua_do_cmd_call },
    { "perf_inc", &mink_lua_do_perf_inc },
    { "perf_set", &mink_lua_do_perf_set },
    { "perf_match", &mink_lua_do_perf_match },
    { "db_set", &mink_lua_do_db_set },
    { "db_get", &mink_lua_do_db_get },
    { "log", &mink_lua_log },
    { NULL, NULL }
};

/***********/
/* globals */
/***********/
struct lua_env_mngr *lenv_mngr = NULL;

/*******************/
/* Lua env manager */
/*******************/
struct lua_env_mngr *
lenvm_new()
{
    struct lua_env_mngr *lem = malloc(sizeof(struct lua_env_mngr));
    lem->envs = NULL;
    lem->dbm_mem = NULL;
    lem->dbm_perm = NULL;
    pthread_mutex_init(&lem->mtx, NULL);
    return lem;
}

void
lenvm_free(struct lua_env_mngr *m)
{
    pthread_mutex_destroy(&m->mtx);
    free(m);
}

struct lua_env_d *
lenvm_get_envd(struct lua_env_mngr *lem, const char *n)
{
    // lock
    pthread_mutex_lock(&lem->mtx);
    // find env
    struct lua_env_d *env = NULL;
    HASH_FIND_STR(lem->envs, n, env); // GCOVR_EXCL_BR_LINE
    // unlock
    pthread_mutex_unlock(&lem->mtx);
    // return env
    return env;
}

struct lua_env_d *
lenvm_del_envd(struct lua_env_mngr *lem, const char *n, bool th_safe)
{
    // lock
    if (th_safe) {
        pthread_mutex_lock(&lem->mtx);
    }
    // find env
    struct lua_env_d *env = NULL;
    HASH_FIND_STR(lem->envs, n, env); // GCOVR_EXCL_BR_LINE
    if (env != NULL) {
        HASH_DEL(lem->envs, env); // GCOVR_EXCL_BR_LINE
    }
    // unlock
    if (th_safe) {
        pthread_mutex_unlock(&lem->mtx);
    }
    // return env
    return env;
}

struct lua_env_d *
lenvm_new_envd(struct lua_env_mngr *lem, struct lua_env_d *env)
{
    // lock
    pthread_mutex_lock(&lem->mtx);
    // find env
    struct lua_env_d *tmp_env = NULL;
    HASH_FIND_STR(lem->envs, env->name, tmp_env); // GCOVR_EXCL_BR_LINE
    if (tmp_env == NULL) {
        // GCOVR_EXCL_BR_START
        HASH_ADD_KEYPTR(hh, lem->envs, env->name, strlen(env->name), env);
        // GCOVR_EXCL_BR_STOP
        tmp_env = env;
    }
    // unlock
    pthread_mutex_unlock(&lem->mtx);
    // return new or exising env
    return tmp_env;
}

bool
lenvm_envd_exists(struct lua_env_mngr *lem, const char *n)
{
    // lock
    pthread_mutex_lock(&lem->mtx);
    // find env
    struct lua_env_d *tmp_env = NULL;
    HASH_FIND_STR(lem->envs, n, tmp_env); // GCOVR_EXCL_BR_LINE
    // unlock
    pthread_mutex_unlock(&lem->mtx);
    return (tmp_env != NULL);
}

void
lenvm_process_envs(struct lua_env_mngr *lem, void (*f)(struct lua_env_d *env))
{
    // lock
    pthread_mutex_lock(&lem->mtx);
    struct lua_env_d *c_env = NULL;
    struct lua_env_d *tmp_env = NULL;
    HASH_ITER(hh, lem->envs, c_env, tmp_env)
    {
        f(c_env);
    }
    // unlock
    pthread_mutex_unlock(&lem->mtx);
}

static void
init_counters(const char *id, const char *pfx, struct perf_d *p)
{
    char perf_id[UMC_NAME_MAX];
    snprintf(perf_id, sizeof(perf_id), "lua.%s.%s.count", pfx, id);
    p->cnt = umc_new_counter(UMD->perf, perf_id, UMCT_INCREMENTAL);

    snprintf(perf_id, sizeof(perf_id), "lua.%s.%s.error", pfx, id);
    p->err = umc_new_counter(UMD->perf, perf_id, UMCT_INCREMENTAL);

    snprintf(perf_id, sizeof(perf_id), "lua.%s.%s.lag", pfx, id);
    p->lag = umc_new_counter(UMD->perf, perf_id, UMCT_GAUGE);
}

static void
init_mink_lua_module(lua_State *L)
{
    // init mink module table
    luaL_newlib(L, mink_lualib);

    // add to globals
    lua_setglobal(L, "M");
}


// load script for lua env
static int
lua_env_load_script(struct lua_env_d *env, lua_State *L)
{
    int r = luaL_loadfile(L, env->path);
    switch (r) { // GCOVR_EXCL_BR_LINE
    case LUA_ERRSYNTAX:
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]:%s",
                env->name,
                "syntax error during pre-compilation");

        return 1;
    // GCOVR_EXCL_START
    case LUA_ERRMEM:
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]:%s",
                env->name,
                "memory allocation error");

        return 2;
    case LUA_ERRFILE:
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]:%s",
                env->name,
                "cannot open/read the file");

        return 3;
    // GCOVR_EXCL_STOP
    default:
        return 0;
    }
}

// setup lua state and load script for lua env
static int
lua_env_setup(struct lua_env_d *env, lua_State **L)
{
    *L = luaL_newstate();

    // init lua
    luaL_openlibs(*L);

    // init umink lua module
    init_mink_lua_module(*L);

    // init other submodules
    umplg_proc_signal(env->pm, "@init_lua_sub_modules", NULL, NULL, NULL, 0, *L);

    // table key = "mink_pm"
    // =================================
    // registry["mink_pm"] = pm
    lua_pushstring(*L, "mink_pm");
    lua_pushlightuserdata(*L, env->pm);
    lua_settable(*L, LUA_REGISTRYINDEX);

    // table key = "mink_dbm_mem"
    // =================================
    // registry["mink_dbm_mem"] = mem
    lua_pushstring(*L, "mink_dbm_mem");
    lua_pushlightuserdata(*L, env->dbm.mem);
    lua_settable(*L, LUA_REGISTRYINDEX);

    // table key = "mink_dbm_perm"
    // =================================
    // registry["mink_dbm_perm"] = perm
    lua_pushstring(*L, "mink_dbm_perm");
    lua_pushlightuserdata(*L, env->dbm.perm);
    lua_settable(*L, LUA_REGISTRYINDEX);

    return 0;
}

// dump lua stack
static void
lua_dumpstack(lua_State *L)
{
    int top = lua_gettop(L);
    for (int i = 1; i <= top; i++) {
        printf("%d\t%s\t", i, luaL_typename(L, i));
        switch (lua_type(L, i)) {
        case LUA_TNUMBER:
            printf("%g\n", lua_tonumber(L, i));
            break;
        case LUA_TSTRING:
            printf("%s\n", lua_tostring(L, i));
            break;
        case LUA_TBOOLEAN:
            printf("%s\n", (lua_toboolean(L, i) ? "true" : "false"));
            break;
        case LUA_TNIL:
            printf("%s\n", "nil");
            break;
        default:
            printf("%p\n", lua_topointer(L, i));
            break;
        }
    }
}

/*******************/
/* LUA Environment */
/*******************/
static void *
th_lua_env(void *arg)
{
    // lua envd
    struct lua_env_d *env = arg;

#if defined(__GNUC__) && defined(__linux__)
#    if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 12
    pthread_setname_np(env->th, env->name);
#    endif
#endif

    // perf counters
    init_counters(env->name, "environment", &env->env_perf);

    // lua state
    lua_State *L = NULL;
    if (lua_env_setup(env, &L) != 0) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot create Lua environment (%s)]",
                env->name);
        return NULL;
    }

    // sleep interval
    uint64_t sec = env->interval / 1000;
    uint64_t nsec = (uint64_t)env->interval % 1000 * 1000000;
    struct timespec st = { sec, nsec };
    umc_lag_t lag;

    umd_log(UMD,
            UMD_LLT_INFO,
            "plg_lua: [starting '%s' Lua environment, with '%s' attached]",
            env->name,
            env->path);

    // if not conserving memory, cache scripts
    if (!env->mem.conserve_mem && lua_env_load_script(env, L) != 0) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]",
                env->name);
        lua_close(L);
        return NULL;
    }

    // run
    while (!umd_is_terminating() && UM_ATOMIC_GET(&env->active)) {
        // mem optimizations (re-create lua state)
        if (env->mem.conserve_mem) {
            if (lua_env_load_script(env, L) != 0) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [cannot load Lua environment (%s)]",
                        env->name);
                lua_pop(L, 1);
                nanosleep(&st, NULL);
                continue;
            }

            // cached lua state, keep precompiled chunk
        } else {
            lua_pushvalue(L, -1);
        }

        // lag measurement start
        umc_lag_start(&lag);

        // run lua script
        int r = lua_pcall(L, 0, 1, 0);

        // lag measurement end
        umc_lag_end(&lag);

        // update perf
        umc_set(env->env_perf.lag, lag.ts_diff);

        if (r != 0) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [%s]:%s",
                    env->name,
                    lua_tostring(L, -1));

            // update counters
            umc_inc(env->env_perf.err, 1);

        } else {
            // update counter
            umc_inc(env->env_perf.cnt, 1);
        }

        // mem optimizations
        if (env->mem.agressive_gc) {
            lua_gc(L, LUA_GCCOLLECT, 0);
        }

        // pop result or error message
        lua_pop(L, 1);

        // one-time only
        if (env->interval == 0) {
            break;

            // next iteration
        } else {
            nanosleep(&st, NULL);
        }
    }
    // remove lua state
    lua_close(L);

    umd_log(UMD,
            UMD_LLT_INFO,
            "plg_lua: [stopping '%s' Lua environment]",
            env->name);

    return NULL;
}

/*****************************/
/* lua signal handler (term) */
/*****************************/
static void
lua_sig_therm_phase_0(umplg_sh_t *shd)
{
    // nothing for now
}

static void
lua_sig_therm_phase_1(umplg_sh_t *shd)
{
    pthread_mutex_destroy(&shd->mtx);
}

static int
lua_sig_hndlr_term(umplg_sh_t *shd, int phase)
{
    switch (phase) {
    case 0:
        lua_sig_therm_phase_0(shd);
        break;
    case 1:
        lua_sig_therm_phase_1(shd);
        break;
    default:
        break;
    }

    return 0;
}

// load script for lua signal
static int
lua_sig_load_script(umplg_sh_t *shd, lua_State *L)
{
    // get lua env
    struct lua_env_d **env = utarray_eltptr(shd->args, 1);

    int r = luaL_loadfile(L, (*env)->path);
    switch (r) { // GCOVR_EXCL_BR_LINE
    case LUA_ERRSYNTAX:
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]:%s",
                (*env)->name,
                "syntax error during pre-compilation");

        return 1;
    // GCOVR_EXCL_START
    case LUA_ERRMEM:
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]:%s",
                (*env)->name,
                "memory allocation error");

        return 2;
    case LUA_ERRFILE:
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot load Lua environment (%s)]:%s",
                (*env)->name,
                "cannot open/read the file");

        return 3;
    // GCOVR_EXCL_STOP
    default:
        return 0;
    }
}

// setup lua state and load script for lua signal
static int
lua_sig_setup(umplg_sh_t *shd, lua_State **L)
{
    // get lua env
    struct lua_env_d **env = utarray_eltptr(shd->args, 1);

    // lua state
    *L = luaL_newstate();
    if (!L) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot create Lua environment (%s)]",
                (*env)->name);
        return 1;
    }
    // init lua
    luaL_openlibs(*L);

    // init umink lua module
    init_mink_lua_module(*L);

    // init other submodules
    umplg_proc_signal((*env)->pm,
                      "@init_lua_sub_modules",
                      NULL,
                      NULL,
                      NULL,
                      0,
                      *L);

    // table key = "mink_pm"
    // =================================
    // registry["mink_pm"] = pm
    lua_pushstring(*L, "mink_pm");
    lua_pushlightuserdata(*L, (*env)->pm);
    lua_settable(*L, LUA_REGISTRYINDEX);

    // table key = "mink_dbm_mem"
    // =================================
    // registry["mink_dbm_mem"] = mem
    lua_pushstring(*L, "mink_dbm_mem");
    lua_pushlightuserdata(*L, (*env)->dbm.mem);
    lua_settable(*L, LUA_REGISTRYINDEX);

    // table key = "mink_dbm_perm"
    // =================================
    // registry["mink_dbm_perm"] = perm
    lua_pushstring(*L, "mink_dbm_perm");
    lua_pushlightuserdata(*L, (*env)->dbm.perm);
    lua_settable(*L, LUA_REGISTRYINDEX);

    return 0;
}

// lua signal handler (init)
static int
lua_sig_hndlr_init(umplg_sh_t *shd)
{
    // get lua env
    struct lua_env_d **env = utarray_eltptr(shd->args, 1);

    // init counters
    struct perf_d **perf = utarray_eltptr(shd->args, 2);
    init_counters((*env)->name, "signal", *perf);

    // success
    return 0;
}

// thread local storage destructor
static void
tls_dtor(void *arg)
{
    lua_close((lua_State *)arg);
}

// lua signal handler (run)
static int
lua_sig_hndlr_run(umplg_sh_t *shd,
                  umplg_data_std_t *d_in,
                  char **d_out,
                  size_t *out_sz,
                  void *args)
{
    // thread local storage
    static __thread int Lref;
    lua_State *L = pthread_getspecific(tls_key);

    // get lua env
    struct lua_env_d **env = utarray_eltptr(shd->args, 1);

    // crete per-thread lua state
    if(L == NULL){
        // setup lua state
        if (lua_sig_setup(shd, &L) != 0) {
            return UMPLG_RES_SIG_INIT_FAILED;
        }

        // set per-thread lua state
        pthread_setspecific(tls_key, L);

        // global registry setup
        // - arguments for signal handlers
        // - signal cache
        lua_pushstring(L, "mink_stdd");
        lua_newtable(L);
        lua_settable(L, LUA_REGISTRYINDEX);
        lua_pushstring(L, "mink_sig_cache");
        lua_newtable(L);
        lua_settable(L, LUA_REGISTRYINDEX);
    }

    // check if current per-thread lua state contains the current signal
    // handler in mink signal cache
    if (!(*env)->mem.conserve_mem) {
        // get sig cache table
        lua_pushstring(L, "mink_sig_cache");
        lua_gettable(L, LUA_REGISTRYINDEX);
        // get sig cache entry for current signal
        lua_pushstring(L, shd->id);
        lua_gettable(L, -2);
        // not found, preload
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            lua_pushstring(L, shd->id);
            if (lua_sig_load_script(shd, L) != 0) {
                // pop error message, sig cache table and signal id
                lua_pop(L, 3);
                return UMPLG_RES_SIG_SETUP_FAILED;
            }
            lua_settable(L, -3);

            // found, remove from stack
        } else {
            lua_pop(L, 1);
        }
        // remove sig cache table from stack
        lua_pop(L, 1);
    }

    // lock
    pthread_mutex_lock(&shd->mtx);
    // recursion prevention
    if (shd->running) {
        shd->running = false;

        // custom error message; cannot use luaL_error because of long jump
        const char *err_msg = "ERR [%s]: signal recursion prevented";
        size_t sz = snprintf(NULL, 0, err_msg, shd->id);
        char *out = malloc(sz + 1);
        snprintf(out, sz + 1, err_msg, shd->id);

        // set output and unlock
        *d_out = out;
        *out_sz = sz + 1;
        pthread_mutex_unlock(&shd->mtx);
        return UMPLG_RES_SUCCESS;
    }

    // load script each time if conserving memory
    if ((*env)->mem.conserve_mem) {
        if (lua_sig_load_script(shd, L) != 0) {
            lua_pop(L, 1);
            return UMPLG_RES_SIG_SETUP_FAILED;
        }
        // if not conserving memory, load precompiled chunk
        // from lua registry
    } else {
        lua_pushstring(L, "mink_sig_cache");
        lua_gettable(L, LUA_REGISTRYINDEX);
        lua_pushstring(L, shd->id);
        lua_gettable(L, -2);
        // remove sig cache table from stack
        lua_remove(L, -2);
    }

    // - inc current thread's signal reference counter
    // - used for proper signal arguments handling in case of signal recursion
    ++Lref;

    // set input arguments for this signal(via global registry)
    lua_pushstring(L, "mink_stdd");
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_pushnumber(L, Lref);
    lua_pushlightuserdata(L, d_in);
    lua_settable(L, -3);
    lua_remove(L, -1);

    // get perf counters
    struct perf_d **perf = utarray_eltptr(shd->args, 2);

    // run lua script
    shd->running = true;

    // lag measurement start
    umc_lag_t lag;
    umc_lag_start(&lag);

    // run signal
    int r = lua_pcall(L, 0, 1, 0);

    // lag measurement end
    umc_lag_end(&lag);

    // remove input arguments for this signal(via global registry)
    lua_pushstring(L, "mink_stdd");
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_pushnumber(L, Lref);
    lua_pushnil(L);
    lua_settable(L, -3);
    lua_remove(L, -1);

    // - dec current thread's signal reference counter
    // - used for proper signal arguments handling in case of signal recursion
    --Lref;

    // update perf
    umc_set((*perf)->lag, lag.ts_diff);

    if (r != 0) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [%s]:%s",
                shd->id,
                lua_tostring(L, -1));
        // update counter
        umc_inc((*perf)->err, 1);

    }else{
        // update counter
        umc_inc((*perf)->cnt, 1);
    }

    // mem optimizations
    if ((*env)->mem.agressive_gc) {
        lua_gc(L, LUA_GCCOLLECT, 0);
    }

    // check return (STRING/NUMBER)
    if (lua_isstring(L, -1)) {
        const char *str = lua_tostring(L, -1);
        size_t sl = strlen(str);
        // empty string is ok
        if (sl == 0) {
            *out_sz = 0;
            // pop result or error message
            lua_pop(L, 1);
            shd->running = false;
            pthread_mutex_unlock(&shd->mtx);
            return UMPLG_RES_SUCCESS;
        }

        // copy lua string to output buffer
        size_t sz = sl + 1;
        char *out = malloc(sz);
        r = snprintf(out, sz, "%s", str);
        // error (buffer too small)
        if (r <= 0 || r >= sz) {
            free(out);
            *out_sz = 0;
            // pop result or error message
            lua_pop(L, 1);
            shd->running = false;
            pthread_mutex_unlock(&shd->mtx);
            return UMPLG_RES_BUFFER_OVERFLOW;

        // success
        } else {
            *d_out = out;
            *out_sz = sz;
        }
    }
    // pop result or error message
    lua_pop(L, 1);
    shd->running = false;
    pthread_mutex_unlock(&shd->mtx);

    // success
    return UMPLG_RES_SUCCESS;
}

// process plugin configuration
static int
process_cfg(umplg_mngr_t *pm, struct lua_env_mngr *lem)
{
    // get config
    if (pm->cfg == NULL) {
        return 1;
    }
    // cast (100% json)
    const struct json_object *jcfg = pm->cfg;
    // find plugin id
    if (!json_object_is_type(jcfg, json_type_object)) {
        return 2;
    }
    // loop keys
    const struct json_object *plg_cfg = NULL;
    json_object_object_foreach(jcfg, k, v)
    {
        if (strcmp(k, "umlua") == 0) {
            plg_cfg = v;
            break;
        }
    }
    // config found?
    if (plg_cfg == NULL) {
        return 3;
    }

    // get DB (permanent)
    struct json_object *j_db = json_object_object_get(plg_cfg, "db");
    if (j_db != NULL && json_object_is_type(j_db, json_type_string)) {
        lem->dbm_perm = umdb_mngr_new(json_object_get_string(j_db), false);
    }
    // init in-memory DB
    lem->dbm_mem = umdb_mngr_new(NULL, true);

    // memory optimizations
    // aggresive lua gc
    const struct json_object *j_agr_gc = json_object_object_get(plg_cfg, "aggressive_gc");
    bool agr_gc = false;
    if (j_agr_gc != NULL) {
        if (!json_object_is_type(j_agr_gc, json_type_boolean)) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [wrong type for 'aggressive_gc']");
            return 6;

        } else {
            agr_gc = json_object_get_boolean(j_agr_gc);
        }
    }

    // conserve memory (do not cache lua state, re-read scripts per-execution)
    const struct json_object *j_cs_mem = json_object_object_get(plg_cfg, "conserve_memory");
    bool cs_mem = false;
    if (j_cs_mem != NULL) {
        if (!json_object_is_type(j_cs_mem, json_type_boolean)) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [wrong type for 'conserve_memory']");
            return 6;
        } else {
            cs_mem = json_object_get_boolean(j_cs_mem);
        }
    }

    // get envs
    const struct json_object *jobj = json_object_object_get(plg_cfg, "envs");
    if (jobj != NULL && json_object_is_type(jobj, json_type_array)) {
        // loop an verify envs
        int env_l = json_object_array_length(jobj);
        for (int i = 0; i < env_l; ++i) {
            // get array object (v declared in json_object_object_foreach macro)
            v = json_object_array_get_idx(jobj, i);
            // check env object type
            if (!json_object_is_type(v, json_type_object)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [cannot start Lua environment]");
                return 4;
            }
            // *******************************
            // *** Get ENV values (verify) ***
            // *******************************
            // get values
            struct json_object *j_n = json_object_object_get(v, "name");
            struct json_object *j_as = json_object_object_get(v, "auto_start");
            struct json_object *j_int = json_object_object_get(v, "interval");
            struct json_object *j_p = json_object_object_get(v, "path");
            struct json_object *j_ev = json_object_object_get(v, "events");
            struct json_object *j_mauth = json_object_object_get(v, "min_auth");
            // all values are mandatory
            if (!(j_n && j_as && j_int && j_p && j_ev)) {
                umd_log(
                    UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [malformed Lua environment (missing values)]");
                return 5;
            }

            // minimum auth is optional
            if (j_mauth != NULL &&
                !json_object_is_type(j_mauth, json_type_int)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [malformed Lua environment (wrong type for "
                        "'min_auth')]");
                return 6;
            }

            // check types
            if (!(json_object_is_type(j_n, json_type_string) &&
                  json_object_is_type(j_as, json_type_boolean) &&
                  json_object_is_type(j_int, json_type_int) &&
                  json_object_is_type(j_p, json_type_string) &&
                  json_object_is_type(j_ev, json_type_array))) {

                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [malformed Lua environment (wrong type)]");
                return 6;
            }

            // check lua script size
            const char *s_p = json_object_get_string(j_p);
            FILE *f = fopen(s_p, "r");
            if (f == NULL) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [malformed Lua script (%s)]",
                        s_p);
                return 6;
            }
            if (fseek(f, 0, SEEK_END) < 0) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [malformed Lua script (%s)]",
                        s_p);
                fclose(f);
                return 7;
            }
            int32_t fsz = ftell(f);
            if (fsz <= 0) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_lua: [malformed Lua script (%s)]",
                        s_p);
                fclose(f);
                return 8;
            }
            fclose(f);

            // create ENV descriptor
            struct lua_env_d *env = calloc(1, sizeof(struct lua_env_d));
            env->name = strdup(json_object_get_string(j_n));
            env->interval = json_object_get_int(j_int);
            env->pm = pm;
            env->dbm.mem = lem->dbm_mem;
            env->dbm.perm = lem->dbm_perm;
            env->mem.agressive_gc = agr_gc;
            env->mem.conserve_mem = cs_mem;
            UM_ATOMIC_COMP_SWAP(&env->active, 0, json_object_get_boolean(j_as));
            env->path = strdup(json_object_get_string(j_p));

            // register events
            int ev_l = json_object_array_length(j_ev);
            // alloc perf counters list
            env->sgnl_perf = malloc(ev_l * sizeof(struct perf_d));
            // process events
            for (int j = 0; j < ev_l; ++j) {
                // get array object (v declared in json_object_object_foreach
                // macro)
                json_object *v2 = json_object_array_get_idx(j_ev, j);
                // verify type
                if (!json_object_is_type(v2, json_type_string)) {
                    continue;
                }
                // create signal
                umplg_sh_t *sh = calloc(1, sizeof(umplg_sh_t));
                sh->id = strdup(json_object_get_string(v2));
                sh->run = &lua_sig_hndlr_run;
                sh->init = &lua_sig_hndlr_init;
                sh->term = &lua_sig_hndlr_term;
                sh->running = false;

                // minimum auth level
                if (j_mauth != NULL) {
                    sh->min_auth_lvl = json_object_get_int(j_mauth);
                } else {
                    sh->min_auth_lvl = 0;
                }

                pthread_mutexattr_t attr;
                pthread_mutexattr_init(&attr);
                pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
                pthread_mutex_init(&sh->mtx, &attr);

                UT_icd icd = { sizeof(void *), NULL, NULL, NULL };
                utarray_new(sh->args, &icd);
                utarray_push_back(sh->args, &pm);
                utarray_push_back(sh->args, &env);

                // performance counters
                ++env->sgnl_nr;
                struct perf_d *p = &env->sgnl_perf[env->sgnl_nr - 1];
                utarray_push_back(sh->args, &p);

                // register signal
                umplg_reg_signal(pm, sh);
                umd_log(UMD,
                        UMD_LLT_INFO,
                        "plg_lua: [attaching '%s' to '%s' event]",
                        env->path,
                        sh->id);
            }
            // add to list
            lenvm_new_envd(lem, env);
        }
    }

    return 0;
}

static void
process_lua_envs(struct lua_env_d *env)
{
    // check if ENV should auto-start
    if (env->interval >= 0 && env->active &&
        pthread_create(&env->th, NULL, th_lua_env, env)) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot start [%s] environment",
                env->name);
    }
}

static void
shutdown_lua_envs(struct lua_env_d *env)
{
    // cleanup
    lenvm_del_envd(lenv_mngr, env->name, false);
    free(env->name);
    free(env->path);
    free(env->sgnl_perf);
    free(env);
}

static void
stop_lua_envs(struct lua_env_d *env)
{
    if (UM_ATOMIC_GET(&env->active)) {
        pthread_join(env->th, NULL);
    }
}

struct cli_cd {
    int s;
    struct sockaddr_un addr;
    umplg_mngr_t *pm;
};

void *
th_cli_client(void *args)
{
    struct cli_cd *ccd = args;
    char buf[1024];
    memset(buf, 0, sizeof(buf));

    // lua state
    lua_State *L = NULL;

    // create ENV descriptor
    struct lua_env_d *env = calloc(1, sizeof(struct lua_env_d));
    env->name = NULL;
    env->interval = 0;
    env->pm = ccd->pm;
    env->dbm.mem = lenv_mngr->dbm_mem;
    env->dbm.perm = lenv_mngr->dbm_perm;
    env->mem.agressive_gc = true;
    env->mem.conserve_mem = true;
    UM_ATOMIC_COMP_SWAP(&env->active, 0, true);
    env->path = NULL;

    // setup
    lua_env_setup(env, &L);

    // socket poll
    struct pollfd pfd = { .events = POLLIN, .fd = ccd->s };

    // process client
    while (!umd_is_terminating()) {
        // poll socket
        int br = poll(&pfd, 1, 1000);
        // error
        if (br < 0) {
            break;

            // timeout
        } else if (br == 0) {
            continue;
        }

        // rx data
        br = recv(ccd->s, buf, sizeof(buf), 0);
        if (br == -1) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [cannot read client data on Lua UNIX domain "
                    "socket (%s)]",
                    strerror(errno));
            break;
        // error
        } else if (br == 0) {
            break;
        }

        // null terminate
        buf[br] = '\0';

        // compile string
        if (luaL_loadstring(L, buf)) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [script error on Lua UNIX DOMAIN socket (%s)]",
                    lua_tostring(L, -1));
            break;
        }

        // run lua script
        int r = lua_pcall(L, 0, 1, 0);

        // lua error
        if (r != 0) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [%s]:%s",
                    env->name,
                    lua_tostring(L, -1));
        }

        // mem optimizations
        if (env->mem.agressive_gc) {
            lua_gc(L, LUA_GCCOLLECT, 0);
        }

        // check return (STRING)
        if (lua_isstring(L, -1)) {
            // copy lua string to output buffer
            size_t sz = strlen(lua_tostring(L, -1)) + 1;
            char *out = malloc(sz);
            snprintf(out, sz, "%s", lua_tostring(L, -1));
            send(ccd->s, out, sz, 0);
            free(out);
        }

        // pop result or error message
        lua_pop(L, 1);
    }
    // cleanup
    lua_close(L);
    close(ccd->s);
    free(env);
    free(ccd);
    umd_log(UMD,
            UMD_LLT_INFO,
            "plg_lua: [client disconnected from Lua UNIX domain socket]");
    return NULL;
}

void *
th_cli_server(void *args)
{
    // sockets and addresses
    int s_s = -1;
    int c_s = -1;
    struct sockaddr_un s_addr;
    struct sockaddr_un c_addr;
    char buf[1024];
    umplg_mngr_t *pm = args;

    // init buffers
    memset(&s_addr, 0, sizeof(struct sockaddr_un));
    memset(&c_addr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, sizeof(buf));

    // create unix domain socket (non blocking)
    s_s = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s_s == -1) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot create Lua UNIX domain socket");
        return NULL;
    }

    // setup socket
    s_addr.sun_family = AF_UNIX;
    strcpy(s_addr.sun_path, "/tmp/umink.sock");
    socklen_t sz = sizeof(s_addr);
    unlink("/tmp/umink.sock");

    // bind
    int r = bind(s_s, (struct sockaddr *)&s_addr, sz);
    if(r == -1){
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot bind Lua UNIX domain socket, (%s)",
                strerror(errno));
        return NULL;
    }

    // listen for connections
    r = listen(s_s, 5);
    if (r == -1) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot listen on Lua UNIX domain socket, (%s)",
                strerror(errno));
        return NULL;
    }
    umd_log(UMD,
            UMD_LLT_INFO,
            "plg_lua: [listening for new clients on Lua UNIX domain socket]");

    // setup socket polling
    struct pollfd pfd = { .events = POLLIN, .fd = s_s };

    // accept clients
    while (!umd_is_terminating()) {
        // poll socket
        r = poll(&pfd, 1, 1000);
        // error
        if (r < 0) {
            break;

            // timeout
        } else if (r == 0) {
            continue;
        }

        // get nec client
        c_s = accept(s_s, (struct sockaddr *)&c_addr, &sz);
        if (c_s == -1) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_lua: [cannot accept client on Lua UNIX domain socket, "
                    "(%s)",
                    strerror(errno));
            close(c_s);
            close(s_s);
            break;
        }

        umd_log(UMD,
                UMD_LLT_INFO,
                "plg_lua: [accepting new client on Lua UNIX domain socket]");

        // get client info
        sz = sizeof(c_s);
        r = getpeername(c_s, (struct sockaddr *)&c_addr, &sz);
        if (r == -1) {
            umd_log(
                UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot get client info on Lua UNIX domain socket, "
                "(%s)",
                strerror(errno));
            close(c_s);
            close(s_s);
            break;
        }
        umd_log(UMD,
                UMD_LLT_INFO,
                "plg_lua: [new client connected to Lua UNIX domain socket]");

        // create client thread
        pthread_t th_c;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        struct cli_cd *ccd = malloc(sizeof(struct cli_cd));
        ccd->s = c_s;
        ccd->addr = c_addr;
        ccd->pm = pm;
        pthread_create(&th_c, &attr, &th_cli_client, ccd);
    }

    // finished
    umd_log(UMD, UMD_LLT_INFO, "plg_lua: [closing Lua UNIX domain socket]");

    if (s_s > 0) {
        close(s_s);
    }
    return NULL;
}


/***************************************************/
/* Signal handler for creating other M sub-modules */
/***************************************************/
static void
signal_match_cb(umplg_sh_t *shd, void *args)
{
    // run matched handler
    shd->run(NULL, NULL, NULL, NULL, args);
}

static int
create_m_sub_modules(umplg_sh_t *shd,
                     umplg_data_std_t *d_in,
                     char **d_out,
                     size_t *out_sz,
                     void *args)
{

    // get lua state (assume args != NULL)
    lua_State *L = args;

    // get pm
    umplg_mngr_t **pm = utarray_eltptr(shd->args, 0);

    // init target/function specific lua modules
    umplg_match_signal(*pm, "@init_lua_sub_module:*", &signal_match_cb, L);

    // success
    return 0;
}

/**************/
/* umlua init */
/**************/
int
umlua_init(umplg_mngr_t *pm)
{
    pthread_key_create(&tls_key, &tls_dtor);

    // create signal handler for creating M sub-modules
    // defined in other plugins
    umplg_sh_t *sh = calloc(1, sizeof(umplg_sh_t));
    sh->id = strdup("@init_lua_sub_modules");
    sh->run = &create_m_sub_modules;
    sh->min_auth_lvl = 0;
    sh->running = false;

    UT_icd icd = { sizeof(void *), NULL, NULL, NULL };
    utarray_new(sh->args, &icd);
    utarray_push_back(sh->args, &pm);

    // register signal
    umplg_reg_signal(pm, sh);

    // lue env manager
    lenv_mngr = lenvm_new();
    if (process_cfg(pm, lenv_mngr)) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_lua: [cannot process plugin configuration]");
    }
    return 0;
}

/********************/
/* umlua start envs */
/********************/
void
umlua_start(umplg_mngr_t *pm)
{
    // create environments
    lenvm_process_envs(lenv_mngr, &process_lua_envs);
    // domain socket lua cli
    pthread_create(&cli_server_th, NULL, &th_cli_server, pm);
}

/******************/
/* umlua shutdown */
/******************/
void
umlua_shutdown()
{
    // stop cli
    pthread_join(cli_server_th, NULL);
    // stop env threads
    lenvm_process_envs(lenv_mngr, &stop_lua_envs);
    // free envs
    lenvm_process_envs(lenv_mngr, &shutdown_lua_envs);
    // free shared db managers
    umdb_mngr_free(lenv_mngr->dbm_mem);
    umdb_mngr_free(lenv_mngr->dbm_perm);
    // free env manager
    lenvm_free(lenv_mngr);
}

