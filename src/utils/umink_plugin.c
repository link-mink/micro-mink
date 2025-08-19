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
#include <umdaemon.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fnmatch.h>

#ifdef UNIT_TESTING
#include <cmocka_tests.h>
#endif

umplgd_t *
umplg_load(umplg_mngr_t *pm, const char *fpath)
{
    // open and resolve symbols now
    void *h = dlopen(fpath, RTLD_NOW);
    if (!h) {
        umd_log(UMD, UMD_LLT_ERROR, "umplg_load (%s): %s", fpath, dlerror());
        return NULL;
    }

    // success, check if plg is a valid plugin
    // check for init, term and cmd handler
    const int *reg_hooks = dlsym(h, UMPLG_CMD_LST);
    umplg_inith_t init = dlsym(h, UMPLG_INIT_FN);
    umplg_termh_t term = dlsym(h, UMPLG_TERM_FN);
    umplg_cmdh_t cmdh = dlsym(h, UMPLG_CMD_HNDLR);
    umplg_cmdh_t cmdh_l = dlsym(h, UMPLG_CMD_HNDLR_LOCAL);

    // first 4 must exist
    if (!(reg_hooks && init && term && cmdh)) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "umplg_load (%s): missing handlers [%p, %p, %p, %p, %p]",
                fpath,
                reg_hooks,
                init,
                term,
                cmdh,
                cmdh_l);
        dlclose(h);
        return NULL;
    }
    // check if all requested hooks are free
    const int *tmp_rh = reg_hooks;
    umplg_hkd_t *hook = NULL;
    while (*tmp_rh != -1) {
        HASH_FIND_INT(pm->hooks, tmp_rh, hook); // GCOVR_EXCL_BR_LINE
        if (hook != NULL) {
            dlclose(h);
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "umplg_load (%s): hook [%d] already exists",
                    fpath,
                    *tmp_rh);
            return NULL;
        }
        tmp_rh++;
    }

    // create descriptor
    umplgd_t pd = { .handle = h,
                    .name = strdup(fpath),
                    .type = 0,
                    .cmdh = cmdh,
                    .cmdh_l = cmdh_l,
                    .termh = term,
                    .data = NULL,
                    .terminated = false };
    // add to list
    utarray_push_back(pm->plgs, &pd);
    umplgd_t *pdp = utarray_back(pm->plgs);

    // attach hooks to plugin
    tmp_rh = reg_hooks;
    while (*tmp_rh != -1) {
        // create new hook descriptor
        hook = malloc(sizeof(umplg_hkd_t));
        hook->id = *tmp_rh;
        hook->plgp = pdp;
        // add to map
        HASH_ADD_INT(pm->hooks, id, hook); // GCOVR_EXCL_BR_LINE
        // next
        tmp_rh++;
    }

    // run ninit method
    init(pm, pdp);
    // return descriptor
    return pdp;
}

int
umplg_unload(umplg_mngr_t *pm, umplgd_t *pd)
{
    return 0;
}

int
umplg_run(umplg_mngr_t *pm, int cmd_id, int idt, umplg_idata_t *data, bool is_local)
{

    // find plugin from cmd_id (hook)
    umplg_hkd_t *hook = NULL;
    HASH_FIND_INT(pm->hooks, &cmd_id, hook); // GCOVR_EXCL_BR_LINE
    if (hook == NULL) {
        return 1;
    }
    // local
    if (is_local) {
        // handler implemented? (optional)
        if (hook->plgp->cmdh_l) {
            return hook->plgp->cmdh_l(pm, hook->plgp, cmd_id, data);

            // local handler not found
        } else {
            return -1;
        }
    }

    // remote
    return hook->plgp->cmdh(pm, hook->plgp, cmd_id, data);
}

int
umplg_reg_signal(umplg_mngr_t *pm, umplg_sh_t *sh)
{
    // single handler descriptor
    umplg_sh_t *tmp_shd = NULL;
    // check if signal was already registered
    HASH_FIND_STR(pm->signals, sh->id, tmp_shd); // GCOVR_EXCL_BR_LINE
    if (tmp_shd != NULL) {
        return 1;
    }
    // run init
    if (sh->init != NULL) {
        int ires = sh->init(sh);
        if (ires != 0) {
            return ires;
        }
    }
    // add signal
    // GCOVR_EXCL_BR_START
    HASH_ADD_KEYPTR(hh, pm->signals, sh->id, strlen(sh->id), sh);
    // GCOVR_EXCL_BR_STOP

    // no error
    return 0;
}

int
umplg_proc_signal(umplg_mngr_t *pm,
                  const char *s,
                  umplg_data_std_t *d_in,
                  char **d_out,
                  size_t *out_sz,
                  int usr_flags,
                  void *args)
{
    // signal missing
    if (s == NULL) {
        return UMPLG_RES_UNKNOWN_SIGNAL;
    }
    // single handler descriptor
    umplg_sh_t *tmp_shd = NULL;
    // find signal
    HASH_FIND_STR(pm->signals, s, tmp_shd); // GCOVR_EXCL_BR_LINE
    if (tmp_shd == NULL) {
        return UMPLG_RES_UNKNOWN_SIGNAL;
    }
    // check min auth level
    if (usr_flags < tmp_shd->min_auth_lvl) {
        return UMPLG_RES_AUTH_ERROR;
    }

    // run
    return tmp_shd->run(tmp_shd, d_in, d_out, out_sz, args);
}

void
umplg_match_signal(umplg_mngr_t *pm,
                   const char *ptrn,
                   umplg_shfn_match_t cb,
                   void *args)
{
    umplg_sh_t *c_sh = NULL;
    umplg_sh_t *tmp_sh = NULL;
    HASH_ITER(hh, pm->signals, c_sh, tmp_sh)
    {
        if (fnmatch(ptrn, c_sh->id, 0) == 0) {
            cb(c_sh, args);
        }
    }
}

uint16_t
umplg_signal_count(umplg_mngr_t *pm)
{
    return HASH_COUNT(pm->signals);
}

static void
add_cmd_id_map_item(int cmd_id, const char *name, umplg_mngr_t *pm)
{
    umplg_cmd_map_t *cmd = malloc(sizeof(umplg_cmd_map_t));
    cmd->id = cmd_id;
    cmd->name = name;
    // GCOVR_EXCL_BR_START
    HASH_ADD_KEYPTR(hh, pm->cmd_map, cmd->name, strlen(cmd->name), cmd);
    // GCOVR_EXCL_BR_STOP
}

umplg_mngr_t *
umplg_new_mngr()
{
    // mem alloc
    umplg_mngr_t *pm = malloc(sizeof(umplg_mngr_t));
    // utarray icd
    UT_icd pd_icd = { sizeof(umplgd_t), NULL, NULL, NULL };
    // create plugins array
    utarray_new(pm->plgs, &pd_icd);
    // init hooks hashmap
    pm->hooks = NULL;
    // init signals hashmap
    pm->signals = NULL;
    // init cmd str/id map
    pm->cmd_map = NULL;
    // add mappings
    add_cmd_id_map_item(UNKNWON_COMMAND, "UNKNWON_COMMAND", pm);
    add_cmd_id_map_item(CMD_MQTT_PUBLISH, "CMD_MQTT_PUBLISH", pm);
    add_cmd_id_map_item(CMD_LUA_CALL, "CMD_LUA_CALL", pm);
    add_cmd_id_map_item(CMD_MQTT_BINARY_UPLOAD, "CMD_MQTT_BINARY_UPLOAD", pm);
    // pm pointer
    return pm;
}

void
umplg_free_mngr(umplg_mngr_t *pm)
{
    umplgd_t *pd = NULL;
    // free signals
    umplg_sh_t *c_sh = NULL;
    umplg_sh_t *tmp_sh = NULL;
    HASH_ITER(hh, pm->signals, c_sh, tmp_sh)
    {
        HASH_DEL(pm->signals, c_sh); // GCOVR_EXCL_BR_LINE
        if (c_sh->term != NULL && !c_sh->terminated) {
            c_sh->term(c_sh, 0);
            c_sh->term(c_sh, 1);
        }
        free(c_sh->id);
        if (c_sh->args != NULL) {
            utarray_free(c_sh->args);
        }
        free(c_sh);
    }

    // free hooks
    umplg_hkd_t *c_hk = NULL;
    umplg_hkd_t *tmp_hk = NULL;
    HASH_ITER(hh, pm->hooks, c_hk, tmp_hk)
    {
        HASH_DEL(pm->hooks, c_hk); // GCOVR_EXCL_BR_LINE
        free(c_hk);
    }

    // free mappings
    umplg_cmd_map_t *c_cm = NULL;
    umplg_cmd_map_t *tmp_cm = NULL;
    HASH_ITER(hh, pm->cmd_map, c_cm, tmp_cm)
    {
        HASH_DEL(pm->cmd_map, c_cm); // GCOVR_EXCL_BR_LINE
        free(c_cm);
    }

    // free plugins
    for (pd = (umplgd_t *)utarray_front(pm->plgs); pd != NULL;
         pd = (umplgd_t *)utarray_next(pm->plgs, pd)) {

        // terminate
        if (!pd->terminated) {
            pd->termh(pm, pd, 0);
            pd->termh(pm, pd, 1);
        }
        // free mem
        dlclose(pd->handle);
        free(pd->name);
    }
    // freeplugin list
    utarray_free(pm->plgs);

    // free mngr
    free(pm);
}

void
umplg_terminate_all(umplg_mngr_t *pm, int phase)
{
    // free signals
    umplg_sh_t *c_sh = NULL;
    umplg_sh_t *tmp_sh = NULL;

    // loop signals
    HASH_ITER(hh, pm->signals, c_sh, tmp_sh)
    {
        if (c_sh->term != NULL) {
            c_sh->term(c_sh, phase);
            c_sh->terminated = true;
        }
    }

    // loop plugins
    for (umplgd_t *pd = (umplgd_t *)utarray_front(pm->plgs); pd != NULL;
         pd = (umplgd_t *)utarray_next(pm->plgs, pd)) {
        // terminate
        pd->termh(pm, pd, phase);
        pd->terminated = true;
    }
}


static void
std_items_copy(void *_dst, const void *_src)
{
    // cast to hashmaps
    umplg_data_std_items_t *dst = (umplg_data_std_items_t *)_dst;
    umplg_data_std_items_t *src = (umplg_data_std_items_t *)_src;
    // temp pointers
    umplg_data_std_item_t *s, *tmp, *n;
    // init hashmap to NULL
    dst->table = NULL;
    // deep copy hash items
    HASH_ITER(hh, src->table, s, tmp)
    {
        n = malloc(sizeof(umplg_data_std_item_t));
        n->name = strdup(s->name);
        n->value = strdup(s->value);
        // GCOVR_EXCL_BR_START
        HASH_ADD_KEYPTR(hh, dst->table, n->name, strlen(n->name), n);
        // GCOVR_EXCL_BR_STOP
    }
}

static void
std_items_dtor(void *_elt)
{
    // cast to hashmaps
    umplg_data_std_items_t *elt = (umplg_data_std_items_t *)_elt;
    // temp pointers
    umplg_data_std_item_t *s, *tmp;
    // free and remove hashmap elements
    HASH_ITER(hh, elt->table, s, tmp)
    {
        HASH_DEL(elt->table, s); // GCOVR_EXCL_BR_LINE
        free(s->name);
        free(s->value);
        free(s);
    }
}

void
umplg_stdd_init(umplg_data_std_t *data)
{
    // sanity check
    if (data == NULL) {
        return;
    }
    // create new std data
    if (data->items == NULL) {
        // icd
        UT_icd icd = { sizeof(umplg_data_std_items_t),
                       NULL,
                       &std_items_copy,
                       &std_items_dtor };

        // new items array
        utarray_new(data->items, &icd);
    }
}

void
umplg_stdd_free(umplg_data_std_t *data)
{
    // sanity check
    if (data == NULL || data->items == NULL) {
        return;
    }
    utarray_free(data->items);
}

int
umplg_stdd_items_add(umplg_data_std_t *data, const umplg_data_std_items_t *items)
{
    // sanity check
    if (data == NULL || items == NULL) {
        return 1;
    }
    // create new std data table
    if (data->items == NULL) {
        umplg_stdd_init(data);
    }
    // add new item
    utarray_push_back(data->items, items);

    // success
    return 0;
}

int
umplg_stdd_item_add(umplg_data_std_items_t *items, umplg_data_std_item_t *item)
{
    // sanity check
    if (items == NULL || item == NULL) {
        return 1;
    }
    // add item
    // GCOVR_EXCL_BR_START
    HASH_ADD_KEYPTR(hh, items->table, item->name, strlen(item->name), item);
    // GCOVR_EXCL_BR_STOP

    // success
    return 0;
}

int
umplg_get_cmd_id(umplg_mngr_t *pm, const char *cmd_str)
{
    umplg_cmd_map_t *cmd = NULL;
    HASH_FIND_STR(pm->cmd_map, cmd_str, cmd); // GCOVR_EXCL_BR_LINE
    // id found
    if (cmd != NULL) {
        return cmd->id;
    }
    // not found
    return -1;
}
