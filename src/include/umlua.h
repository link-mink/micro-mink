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
#include <pthread.h>
#include <umdaemon.h>
#include <uthash.h>
#include <time.h>
#include <utarray.h>
#include <umdb.h>

/****************/
/* LUA ENV data */
/****************/
struct lua_env_data {
    umplg_mngr_t *pm;
};

/********************************/
/* LUA ENV performance counters */
/********************************/
struct perf_d {
    // successful execution count
    umc_t *cnt;
    // error count
    umc_t *err;
    // lag
    umc_t *lag;
};

/**********************/
/* LUA ENV Descriptor */
/**********************/
struct lua_env_d {
    // label
    char *name;
    // in case of long running
    // envs, time between each
    // execution
    // 0 - one time execution
    uint64_t interval;
    // activity flag (used only
    // with long running envs)
    uint8_t active;
    // path to lua script
    char *path;
    // plugin manager pointer
    umplg_mngr_t *pm;
    // thread
    pthread_t th;
    // perf counters
    struct perf_d env_perf;
    // number of signals
    size_t sgnl_nr;
    // signal perf counters
    struct perf_d *sgnl_perf;
    // dbm
    struct {
        // in-memory
        umdb_mngrd_t *mem;
        // permanent
        umdb_mngrd_t *perm;
    } dbm;
    // mem options
    struct {
        // agressive lua gc
        bool agressive_gc;
        // uncached lua state
        bool conserve_mem;
    } mem;
    // hashable
    UT_hash_handle hh;
};

/*******************/
/* LUA ENV Manager */
/*******************/
struct lua_env_mngr {
    // lua envs
    struct lua_env_d *envs;
    // shared dbm
    umdb_mngrd_t *dbm_perm;
    umdb_mngrd_t *dbm_mem;
    // lock
    pthread_mutex_t mtx;
};


