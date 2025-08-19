/*
 *               _____  ____ __
 *   __ ____ _  /  _/ |/ / //_/
 *  / // /  ' \_/ //    / ,<
 *  \_,_/_/_/_/___/_/|_/_/|_|
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef UMINK_PLUGIN
#define UMINK_PLUGIN

#include <stdbool.h>
#include <pthread.h>
#include <utarray.h>
#include <uthash.h>

// types
typedef struct umplgd umplgd_t;
typedef struct umplg_mngrd umplg_mngrd_t;
typedef struct umplg_idata umplg_idata_t;
typedef struct umplg_mngr umplg_mngr_t;
typedef struct umplg_sh umplg_sh_t;
typedef struct umplg_data_std_items umplg_data_std_items_t;
typedef struct umplg_data_std_item umplg_data_std_item_t;
typedef struct umplg_data_std umplg_data_std_t;
typedef struct umplg_hkd umplg_hkd_t;
typedef struct umplg_cmd_map umplg_cmd_map_t;

// consts
#define UMPLG_INIT_FN         "init"
#define UMPLG_TERM_FN         "terminate"
#define UMPLG_CMD_HNDLR       "run"
#define UMPLG_CMD_HNDLR_LOCAL "run_local"
#define UMPLG_CMD_LST         "COMMANDS"

/**
 * Plugin CMD ids
 */
enum umplg_cmd_t {
    /** Unknown */
    UNKNWON_COMMAND = 0,
    /** Get system info */
    CMD_GET_SYSINFO = 1,
    /** Get CPU stats */
    CMD_GET_CPUSTATS = 2,
    /** Get memory usage */
    CMD_GET_MEMINFO = 3,
    /** Get system uname string */
    CMD_GET_UNAME = 4,
    /** Get list of processes */
    CMD_GET_PROCESS_LST = 5,
    /** Get file info */
    CMD_GET_FILE_STAT = 6,
    /** Invoke ubus call */
    CMD_UBUS_CALL = 7,
    /** Run shell exec */
    CMD_SHELL_EXEC = 8,
    /** Set generic data */
    CMD_SET_DATA = 9,
    /** Run generic rules */
    CMD_RUN_RULES = 10,
    /** Load generic rules */
    CMD_LOAD_RULES = 11,
    /** AUthenticate */
    CMD_AUTH = 12,
    /** Setup proxy socket */
    CMD_SOCKET_PROXY = 13,
    /** Request firmware update */
    CMD_FIRMWARE_UPDATE = 14,
    /** Start syslog */
    CMD_SYSLOG_START = 15,
    /** Stop syslog */
    CMD_SYSLOG_STOP = 16,
    /** Start remote execution */
    CMD_REMOTE_EXEC_START = 17,
    /** Stop remote execution */
    CMD_REMOTE_EXEC_STOP = 18,
    /** Get system monitor data */
    CMD_GET_SYSMON_DATA = 19,
    /** Generic TCP SEND */
    CMD_NET_TCP_SEND = 20,
    /** Create cgroup2 group */
    CMD_CG2_GROUP_CREATE = 21,
    /** Delete cgroup2 group */
    CMD_CG2_GROUP_DELETE = 22,
    /** Get cgroup2 groups */
    CMD_CG2_GROUPS_LST = 23,
    /** Get cgroup2 controller */
    CMD_CG2_CONTROLLER_GET = 24,
    /** Set cgroup2 controller */
    CMD_CG2_CONTROLLER_SET = 25,
    /** Get cgroup2 controllers */
    CMD_CG2_CONTROLLERS_LST = 26,
    /** Get firewall zones */
    CMD_SYSD_FWLD_GET_ZONES = 27,
    /** Get firewall rules */
    CMD_SYSD_FWLD_GET_RICH_RULES = 28,
    /** Add firewall rule */
    CMD_SYSD_FWLD_ADD_RICH_RULE = 29,
    /** Delete firewall rule */
    CMD_SYSD_FWLD_DEL_RICH_RULE = 30,
    /** Reload firewall */
    CMD_SYSD_FWLD_RELOAD = 31,
    /** Write one bit using modbus */
    CMD_MODBUS_WRITE_BIT = 32,
    /** Read bits using modbus */
    CMD_MODBUS_READ_BITS = 33,
    /** Get NDPI statistics */
    CMD_NDPI_GET_STATS = 34,
    /** Publish via MQTT */
    CMD_MQTT_PUBLISH = 35,
    /** Ivoke Lua call */
    CMD_LUA_CALL = 36,
    /** Setup MQTT binary file upload */
    CMD_MQTT_BINARY_UPLOAD = 37
};

/**
 * mink plugin/signal result codes
 */
enum umplg_ret_t {
    /** success */
    UMPLG_RES_SUCCESS = 0,
    /** signal not found */
    UMPLG_RES_UNKNOWN_SIGNAL = 1,
    /** insufficient privileges */
    UMPLG_RES_AUTH_ERROR = 2,
    /** signal init error */
    UMPLG_RES_SIG_INIT_FAILED = 3,
    /** signal setup error */
    UMPLG_RES_SIG_SETUP_FAILED = 4,
    /** signal execution error */
    UMPLG_RES_SIG_EXEC_FAILED = 5,
    /** buffer overflow */
    UMPLG_RES_BUFFER_OVERFLOW = 6,
    /** invalid type */
    UMPLG_RES_INVALID_TYPE = 7

};

/**
 * Plugin init handler
 *
 * @param[in]   pm      Pointer to MINK plugin manager
 * @param[in]   pd      Pointer to plugin descriptor
 * @return      0 for success
 */
typedef int (*umplg_inith_t)(umplg_mngr_t *pm, umplgd_t *pd);

/**
 * Plugin terminate handler
 *
 * @param[in]   pm      Pointer to MINK plugin manager
 * @param[in]   pd      Pointer to plugin descriptor
 * @param[in]   phase   Termination phase
 * @return      0 for success
 */
typedef int (*umplg_termh_t)(umplg_mngr_t *pm, umplgd_t *pd, int phase);

/**
 * Plugin cmd handler
 *
 * @param[in]       pm      Pointer to MINK plugin manager
 * @param[in]       pd      Pointer to plugin descriptor
 * @param[in]       hk      MINK daemon hook
 * @param[in,out]   data    Custom data
 * @return          0 for success
 */
typedef int (*umplg_cmdh_t)(umplg_mngr_t *pm,
                            umplgd_t *pd,
                            int cmd_id,
                            umplg_idata_t *data);
/**
 * Signal handler method (init)
 *
 * @param[in]   shd       Pointer to signal handler descriptor
 * @return      0 for success
 */
typedef int (*umplg_shfn_init_t)(umplg_sh_t *shd);

/**
 * Signal handler method (run)
 *
 * @param[in]       shd       Pointer to signal handler descriptor
 * @param[in]       d_in      Pointer to plugin standard input data
 * @param[in,out]   d_out     Output data buffer pointer
 * @param[in,out]   out_sz    Output data size pointer
 * @param[in]       args      User data
 * @return          0 for success
 */
typedef int (*umplg_shfn_run_t)(umplg_sh_t *shd,
                                umplg_data_std_t *d_in,
                                char **d_out,
                                size_t *out_sz,
                                void *args);
/**
 * Signal handler method (term)
 *
 * @param[in]   shd         Pointer to signal handler descriptor
 * @param[in]   phase       Termination phase
 * @return      0 for success
 */
typedef int (*umplg_shfn_term_t)(umplg_sh_t *shd, int phase);

/**
 * Signal handler match callback
 *
 * @param[in]   shd         Pointer to signal handler descriptor
 * @param[in]   args        User data
 *
 */
typedef void (*umplg_shfn_match_t)(umplg_sh_t *shd, void *args);

/** String/CMD mapping */
struct umplg_cmd_map {
    /** CMD id */
    int id;
    /** CMD name */
    const char *name;
    UT_hash_handle hh;
};

/** Input data type for local interface */
enum umplgd_t {
    /** unknown data type (error) */
    UMPLG_DT_UNKNOWN = 0,
    /** JSON-RPC (UNIX socket) */
    UMPLG_DT_JSON_RPC = 1,
    /** plugin-specific (custom plugin2plugin) */
    UMPLG_DT_SPECIFIC = 2,
    /** plugin-to-plugin standard in/out format */
    UMPLG_DT_STANDARD = 4
};

/** Standard data item */
struct umplg_data_std_item {
    /** Item name */
    char *name;
    /** Item value */
    char *value;
    // hashable
    UT_hash_handle hh;
};

/** Standard data items */
struct umplg_data_std_items {
    /** Items hashmap */
    umplg_data_std_item_t *table;
};

/** Standard data descriptor */
struct umplg_data_std {
    /** Items array */
    UT_array *items;
};

/** Input data descriptor */
struct umplg_idata {
    /** Item type */
    enum umplgd_t type;
    /** Item data */
    void *data;
};

/** Plugin descriptor */
struct umplgd {
    /** Plugin handle */
    void *handle;
    /** Plugin name */
    char *name;
    /** Plugin type */
    int type;
    /** Plugin cmd handler method */
    umplg_cmdh_t cmdh;
    /** Plugin cmd handler method (local) */
    umplg_cmdh_t cmdh_l;
    /** Plugin terminate method */
    umplg_termh_t termh;
    /** Custom data filled by plugin */
    void *data;
    /** terminated flag */
    bool terminated;
    // hashable
    UT_hash_handle hh;
};

/** Hook descriptor */
struct umplg_hkd {
    /** Id */
    int id;
    /** Plugin pointer */
    umplgd_t *plgp;
    // hashable
    UT_hash_handle hh;
};

/** Signal handler descriptor */
struct umplg_sh {
    /** Signal id */
    char *id;
    /** Signal invocation init */
    umplg_shfn_init_t init;
    /** Signal invocation run */
    umplg_shfn_run_t run;
    /** Signal invocation terminate */
    umplg_shfn_term_t term;
    /** Extra arguments */
    UT_array *args;
    /** Running flag */
    bool running;
    /** minimum user auth level */
    uint16_t min_auth_lvl;
    /** terminated flag */
    bool terminated;
    /** Lock */
    pthread_mutex_t mtx;
    // hashable
    UT_hash_handle hh;
};

/** Plugin manager descriptor */
struct umplg_mngr {
    /** Array of registered plugins */
    UT_array *plgs;
    /** Hashmap of plugin <-> hook mappings */
    umplg_hkd_t *hooks;
    /** Hasmap of registered signals */
    umplg_sh_t *signals;
    /** CMD str -> CMD id */
    umplg_cmd_map_t *cmd_map;
    /** Configuration data */
    void *cfg;
};

/**
 * Create new plugin manager
 *
 * @return  New plugin manager
 */
umplg_mngr_t *umplg_new_mngr();

/**
 * Free plugin manager
 *
 * @param[in]   pm  Plugin manager
 */
void umplg_free_mngr(umplg_mngr_t *pm);

/**
 * Terminate plugins
 *
 * @param[in]   pm      Plugin manager
 * @param[in]   phase   Termination phase
 */
void umplg_terminate_all(umplg_mngr_t *pm, int phase);

/**
 * Load and verify plugin
 *
 * @param[in]   pm          Pointer to plugin manager
 * @param[in]   fpath       Plugin file path
 * @return      new plugin descriptor or NULL on error
 */
umplgd_t *umplg_load(umplg_mngr_t *pm, const char *fpath);

/**
 * Unload plugin; call plugin's terminate method and
 * remove from list of active plugins
 *
 * @param[in]   pd          Pointer to plugin descriptor
 * @return      0 for success or error
 */
int umplg_unload(umplg_mngr_t *pm, umplgd_t *pd);

/**
 * Run plugin hook
 *
 * @param[in]   cmd_id  Command id
 * @param[in]   data    Custom data (input/output)
 * @param[in]   local   Local request flag
 *
 * @return      0 for success or error code
 */
int umplg_run(umplg_mngr_t *pm,
              int cmd_id,
              int idt,
              umplg_idata_t *data,
              bool is_local);

// register signal handler
/**
 * Register signal handler
 *
 * @param[in]   pm      Plugin manager
 * @param[in]   sh      Signal handler
 *
 * @return      0 for success or error code
 */
int umplg_reg_signal(umplg_mngr_t *pm, umplg_sh_t *sh);

/**
 * Process signal
 *
 * @param[in]   pm          Plugin manager
 * @param[in]   s           Signal name
 * @param[in]   d_in        Signal input data
 * @param[out]  d_out       Signal output buffer
 * @param[out]  out_sz      Size of data in output buffer
 * @param[in]   usr_flags   Signal output buffer
 * @param[in]   args        User data
 *
 * @return      0 for success or error code
 */
int umplg_proc_signal(umplg_mngr_t *pm,
                      const char *s,
                      umplg_data_std_t *d_in,
                      char **d_out,
                      size_t *out_sz,
                      int usr_flags,
                      void *args);

/**
 * Find signals by name
 *
 * @param[in]   pm          Plugin manager
 * @param[in]   ptrn        Pattern to match agains
 * @param[in]   cb          Callback function to call when matched
 * @param[in]   args        User data
 *
 */
void umplg_match_signal(umplg_mngr_t *pm,
                        const char *ptrn,
                        umplg_shfn_match_t cb,
                        void *args);

/**
 * Get signal count
 *
 * @param[in]   pm          Plugin manager
 * @return      number of registered signals
 */
uint16_t umplg_signal_count(umplg_mngr_t *pm);

/**
 * Add items to standard data descriptor
 *
 * @param[in]   data    Standard data item
 * @param[in]   items   Standard data items
 *
 * @return      0 for success or error code
 */
int umplg_stdd_items_add(umplg_data_std_t *data,
                         const umplg_data_std_items_t *items);

/**
 * Add standard item to standard items
 *
 * @param[in]   items   Standard data items
 * @param[in]   item    Standard data item
 *
 * @return      0 for success or error code
 */
int umplg_stdd_item_add(umplg_data_std_items_t *items,
                        umplg_data_std_item_t *item);

/**
 * Init standard data descriptor
 *
 * @param[in]  data    Standard data
 */
void umplg_stdd_init(umplg_data_std_t *data);

/**
 * Free standard data descriptor
 *
 * @param[in]  data    Standard data
 */

void umplg_stdd_free(umplg_data_std_t *data);

/**
 * Get CMD string from CMD id
 *
 * @param[in]   pm      Plugin manager
 * @param[in]   cmd_str CMD string
 *
 * @return      CMD id
 */
int umplg_get_cmd_id(umplg_mngr_t *pm, const char *cmd_str);

#endif /* ifndef UMINK_PLUGIN */
