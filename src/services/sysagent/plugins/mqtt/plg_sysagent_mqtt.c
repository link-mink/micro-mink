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
#include <utarray.h>
#include <MQTTAsync.h>
#include <spscq.h>
#include <semaphore.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <luaconf.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "mqtt";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
int COMMANDS[] = { CMD_MQTT_PUBLISH,
                   CMD_MQTT_BINARY_UPLOAD,
                   // end of list marker
                   -1 };

/*************/
/* constants */
/*************/
static const int SIG_SEM_TIMEOUT = 5;

/******************************/
/* MQTT connection descriptor */
/******************************/
struct mqtt_conn_d {
    // label
    char *name;
    // mqtt async client
    MQTTAsync client;
    // plugin manager pointer
    umplg_mngr_t *pm;
    // mqtt topics
    UT_array *topics;
    // signal thread
    pthread_t sig_th;
    // signal thread q
    spsc_qd_t *sig_q;
    // signal queue size
    int sig_qsz;
    // binary upload path
    char *bin_upl_path;
    // signal thread semaphore
    sem_t sig_sem;
    // rx signal handler
    char *rxh;
    // hashable
    UT_hash_handle hh;
};

/***************************/
/* MQTT connection manager */
/***************************/
struct mqtt_conn_mngr {
    // mqtt connections
    struct mqtt_conn_d *conns;
    // lock
    pthread_mutex_t mtx;
};

/**************************/
/* binary file descriptor */
/**************************/
struct mqtt_file_d {
    // uuid
    char uuid[37];
    // file path
    char path[128];
    // expected file size
    size_t size;
    // timestamp
    time_t ts;
    // hashable
    UT_hash_handle hh;
};


/********************/
/* fwd declarations */
/********************/
static int mqtt_conn_sub(struct mqtt_conn_d *conn, const char *t);
static int mqtt_conn_connect(struct mqtt_conn_d *conn,
                             const struct json_object *j_conn);
static void *mqtt_proc_thread(void *arg);

/*********/
/* types */
/*********/
typedef struct mqtt_file_d mqtt_file_d_t;

/***********/
/* globals */
/***********/
struct mqtt_conn_mngr *mqtt_mngr = NULL;
static mqtt_file_d_t *bin_uploads = NULL;
static pthread_mutex_t bin_upl_mtx;

/***********************/
/* MQTT lua sub-module */
/***********************/
int mink_lua_mqtt_pub(lua_State *L);

static const struct luaL_Reg mqtt_lualib[] = { { "publish",
                                                 &mink_lua_mqtt_pub },
                                               { NULL, NULL } };

struct mqtt_conn_d *
mqtt_conn_new(umplg_mngr_t *pm)
{
    struct mqtt_conn_d *c = calloc(1, sizeof(struct mqtt_conn_d));
    c->pm = pm;
    utarray_new(c->topics, &ut_str_icd);
    return c;
}

static void *
mqtt_proc_thread(void *args)
{
    // context
    struct mqtt_conn_d *conn = args;
    umplg_data_std_t *data = NULL;
    struct timespec ts = { 0, 1000000 };

#if defined(__GNUC__) && defined(__linux__)
#    if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 12
    pthread_setname_np(conn->sig_th, "umink_mqtt_proc");
#    endif
#endif

    while (!umd_is_terminating()) {
        // get semaphore timeout
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_mqtt: [(%s) CLOCK_REALTIME error, terminating...",
                    conn->name);
            exit(EXIT_FAILURE);
        }
        // set semaphore timeout
        ts.tv_sec += SIG_SEM_TIMEOUT;

        // wait on semaphore
        sem_timedwait(&conn->sig_sem, &ts);
        // check if process is terminating
        if (umd_is_terminating()) {
            break;
        }

        // check queue
        if (spscq_pop(conn->sig_q, (void **)&data) == 0) {
            // output buffer
            char *b = NULL;
            size_t b_sz = 0;
            // process signal
            umplg_proc_signal(conn->pm, conn->rxh, data, &b, &b_sz, 0, NULL);
            if (b != NULL) {
                free(b);
            }
            // cleanup
            umplg_stdd_free(data);
            free(data);
        }
    }

    // flush
    while (spscq_pop(conn->sig_q, (void **)&data) == 0) {
        // cleanup
        umplg_stdd_free(data);
        free(data);
    }
    return NULL;
}

/********************************/
/* add new binary file metadata */
/********************************/
static mqtt_file_d_t *
mqtt_bin_upl_add(const char *path, size_t fsz)
{
    // sanity check
    if (fsz == 0) {
        return NULL;
    }

    mqtt_file_d_t *f = NULL;
    pthread_mutex_lock(&bin_upl_mtx);
    // gen uuid
    uuid_t uuid;
    uuid_generate(uuid);
    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);
    // check for uuid
    HASH_FIND_STR(bin_uploads, uuid_str, f); // GCOVR_EXCL_BR_LINE
    if (f != NULL) {
        pthread_mutex_unlock(&bin_upl_mtx);
        return NULL;
    }
    // add new
    f = malloc(sizeof(mqtt_file_d_t));
    strcpy(f->path, path);
    memcpy(f->uuid, uuid_str, sizeof(uuid_str));
    f->ts = time(NULL);
    f->size = fsz;
    HASH_ADD_STR(bin_uploads, uuid, f); // GCOVR_EXCL_BR_LINE

    pthread_mutex_unlock(&bin_upl_mtx);
    return f;
}

/*******************************/
/* remove binary file metadata */
/*******************************/
static int
mqtt_bin_upl_del(const char *uuid)
{
    mqtt_file_d_t *f = NULL;
    pthread_mutex_lock(&bin_upl_mtx);

    // check for uuid
    HASH_FIND_STR(bin_uploads, uuid, f); // GCOVR_EXCL_BR_LINE
    if (f == NULL) {
        pthread_mutex_unlock(&bin_upl_mtx);
        return 1;
    }
    // remove
    HASH_DEL(bin_uploads, f); // GCOVR_EXCL_BR_LINE
    free(f);

    pthread_mutex_unlock(&bin_upl_mtx);
    return 0;
}

// create temp file name string
static void
gen_temp_fname(const mqtt_file_d_t *f, char *b)
{
    b[0] = '\0';
    strcat(b, f->path);
    strcat(b, "/");
    strcat(b, f->uuid);
    strcat(b, ".tmp");
}

/************************/
/* handle binary topics */
/************************/
static int
mqtt_handle_bin(const char *tpc, const MQTTAsync_message *msg)
{
    // temp copy of topic string
    char tmp_t[strlen(tpc) + 1];
    char *sp;
    const char *dev_uuid = NULL;
    const char *file_uuid = NULL;
    const char *file_op = NULL;
    strcpy(tmp_t, tpc);
    // tokenize
    int tc = 0;
    char *t = strtok_r(tmp_t, "/", &sp);
    while (t != NULL) {
        ++tc;
        switch (tc) {
        // device uuid
        case 2:
            dev_uuid = t;
            break;

            // file uuid
        case 3:
            file_uuid = t;
            break;

            // file op
        case 4:
            file_op = t;
            break;

        default:
            break;
        }
        t = strtok_r(NULL, "/", &sp);
    }

    // sanity check
    if (dev_uuid == NULL || file_uuid == NULL || file_op == NULL) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_mqtt: [invalid topic for binary file upload]");
        return 1;
    }

    mqtt_file_d_t *f = NULL;
    HASH_FIND_STR(bin_uploads, file_uuid, f); // GCOVR_EXCL_BR_LINE
    if (f == NULL) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_mqtt: [missing metadata for binary file upload]");
        return 2;
    }

    // file op
    if (strcmp(file_op, "upload") == 0) {
        // create file path str
        char fp[strlen(f->path) + strlen(f->uuid) + 6];
        gen_temp_fname(f, fp);
        // open for writing
        int fh = open(fp, O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
        if (fh < 0) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_mqtt: [cannot initate binary file uipload: (%s)]",
                    strerror(errno));
            return 3;
        }
        // file size check
        size_t fsz = lseek(fh, 0, SEEK_END);
        if(fsz >= f->size){
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_mqtt: [maximum filesize (%lu) reached for file (%s)]",
                    fsz,
                    fp);
            return 4;
        }

        // write in chunks
        size_t sz = msg->payloadlen;
        const uint8_t *pld = msg->payload;
        size_t chunk = sz < 2097152 ? sz : 2097152;
        while (sz > 0) {
            // overflow check
            fsz += chunk;
            if (fsz > f->size) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_mqtt: [attempting to overflow (%s) file with "
                        "(%lu) extra bytes]",
                        fp,
                        fsz - f->size);

                break;
            }
            // write chunk
            write(fh, pld, chunk);
            // dec size
            sz -= chunk;
            // fwd payload buffer
            pld += chunk;
            // set chunk size
            if (sz < chunk) {
                chunk = sz;
            }
            // flush
            fsync(fh);
        }
        // update ts
        f->ts = time(NULL);
        // get current file size
        fsz = lseek(fh, 0, SEEK_END);
        // close file descriptor
        close(fh);
        // remove metadata descriptor if finished
        if (f->size == fsz) {
            mqtt_bin_upl_del(f->uuid);
            // rename ".tmp" extension
            size_t sl = strlen(fp) - 4;
            char fp2[sl + 1];
            memcpy(fp2, fp, sl);
            fp2[sl] = '\0';
            rename(fp, fp2);
        }
    }
    // ok
    return 0;
}

// clean stale uploads
static void
mqtt_bin_cleanup()
{
    // free expired binary uploads
    time_t now = time(NULL);
    pthread_mutex_lock(&bin_upl_mtx);
    mqtt_file_d_t *f;
    mqtt_file_d_t *f_tmp;
    HASH_ITER(hh, bin_uploads, f, f_tmp)
    {
        if (now - f->ts > SIG_SEM_TIMEOUT) {
            HASH_DEL(bin_uploads, f); // GCOVR_EXCL_BR_LINE
            // create file path str
            char fp[strlen(f->path) + strlen(f->uuid) + 6];
            gen_temp_fname(f, fp);
            // remove file
            unlink(fp);
            free(f);
        }
    }
    pthread_mutex_unlock(&bin_upl_mtx);

}

static int
mqtt_on_rx(void *ctx, char *t, int t_sz, MQTTAsync_message *msg)
{
    // mink.bin/<device_uuid>/<session_or_file_uuid>/upload
    if (strncmp(t, "mink.bin/", 9) == 0) {
        if (mqtt_handle_bin(t, msg) != 0) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_mqtt: [error while starting binary file upload (%s)",
                    t);
        }

        // free expired binary uploads
        mqtt_bin_cleanup();

        // cleanup
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(t);
        return 1;
    }

    // context
    struct mqtt_conn_d *conn = ctx;
    // msg data
    char s[msg->payloadlen + 1];
    memcpy(s, msg->payload, msg->payloadlen);
    s[msg->payloadlen] = '\0';
    // data
    umplg_data_std_t *e_d = calloc(1, sizeof(umplg_data_std_t));
    umplg_data_std_items_t items = { .table = NULL };
    umplg_data_std_item_t item_topic = { .name = "mqtt_topic", .value = t };
    umplg_data_std_item_t item_pld = { .name = "mqtt_payload", .value = s };
    umplg_data_std_item_t item_conn = { .name = "mqtt_connection",
                                        .value = conn->name };
    // create signal input data
    umplg_stdd_init(e_d);
    umplg_stdd_item_add(&items, &item_topic);
    umplg_stdd_item_add(&items, &item_pld);
    umplg_stdd_item_add(&items, &item_conn);
    umplg_stdd_items_add(e_d, &items);

    // push to sig proc thread
    if (spscq_push(conn->sig_q, 1, e_d) != 0) {
        // cleanup
        umplg_stdd_free(e_d);
        free(e_d);
        umd_log(UMD,
                UMD_LLT_WARNING,
                "plg_mqtt: [(%s) SIGPROC queue full",
                conn->name);

    } else {
        sem_post(&conn->sig_sem);
    }

    // cleanup
    MQTTAsync_freeMessage(&msg);
    MQTTAsync_free(t);
    HASH_CLEAR(hh, items.table);

    return 1;
}

static void
mqtt_on_connect(void *context, char *cause)
{
    // context
    struct mqtt_conn_d *conn = context;
    umd_log(UMD,
            UMD_LLT_INFO,
            "plg_mqtt: [connection (%s) established]",
            conn->name);

    // get topics
    char **t = NULL;
    while ((t = (char **)utarray_next(conn->topics, t))) {
        mqtt_conn_sub(conn, *t);
    }
}

static int
mqtt_conn_connect(struct mqtt_conn_d *conn, const struct json_object *j_conn)
{
    // address and client id
    struct json_object *j_addr = json_object_object_get(j_conn, "address");
    struct json_object *j_clid = json_object_object_get(j_conn, "client_id");
    // username and password
    struct json_object *j_usr = json_object_object_get(j_conn, "username");
    struct json_object *j_pwd = json_object_object_get(j_conn, "password");
    // keep-alive interval
    struct json_object *j_ka = json_object_object_get(j_conn, "keep_alive");
    int ka = 20;
    if (j_ka != NULL && json_object_is_type(j_ka, json_type_int)) {
        ka = json_object_get_int(j_ka);
    }

    // mqtt connec tion setup
    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
    int rc = MQTTAsync_create(&conn->client,
                              json_object_get_string(j_addr),
                              json_object_get_string(j_clid),
                              MQTTCLIENT_PERSISTENCE_NONE,
                              NULL);
    if (rc != MQTTASYNC_SUCCESS) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_mqtt: [(%s) cannot create MQTT connection handle",
                conn->name);
        return 1;
    }

    // set callbacks (RX)
    if (MQTTAsync_setCallbacks(conn->client, conn, NULL, mqtt_on_rx, NULL) !=
        MQTTASYNC_SUCCESS) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_mqtt: [(%s) cannot set MQTT connection callbacks",
                conn->name);
        return 2;
    }
    // connection options
    conn_opts.keepAliveInterval = ka;
    conn_opts.cleansession = 1;
    conn_opts.onSuccess = NULL;
    conn_opts.onFailure = NULL;
    conn_opts.automaticReconnect = 1;
    conn_opts.context = conn;
    conn_opts.username = json_object_get_string(j_usr);
    conn_opts.password = json_object_get_string(j_pwd);
    conn_opts.ssl = &ssl_opts;

    // set callbacks
    MQTTAsync_setConnected(conn->client, conn, mqtt_on_connect);

    // connect
    rc = MQTTAsync_connect(conn->client, &conn_opts);
    if (rc != MQTTASYNC_SUCCESS) {
        umd_log(UMD,
                UMD_LLT_ERROR,
                "plg_mqtt: [(%s) cannot establish MQTT connection, "
                "error code = [%d]",
                conn->name,
                rc);
        return 3;
    }

    // success
    return 0;
}

static int
mqtt_conn_pub(struct mqtt_conn_d *conn,
              const char *d,
              size_t d_sz,
              const char *t,
              bool retain)
{
    // sanity check
    if (conn->client == NULL) {
        return 1;
    }
    // setup mqtt payload
    MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    opts.context = conn;
    pubmsg.payload = (void *)d;
    pubmsg.payloadlen = d_sz;
    pubmsg.qos = 1;
    pubmsg.retained = retain;
    // send
    if (MQTTAsync_sendMessage(conn->client, t, &pubmsg, &opts) != MQTTASYNC_SUCCESS) {
        // error
        return 1;
    }
    // ok
    return 0;
}

static int
mqtt_conn_sub(struct mqtt_conn_d *conn, const char *t)
{
    // sanity check
    if (conn->client == NULL) {
        return 1;
    }
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    if (MQTTAsync_subscribe(conn->client, t, 1, &opts) != MQTTASYNC_SUCCESS) {
        // error
        return 1;
    }
    // ok
    return 0;
}

static void
mqtt_conn_add_topic(struct mqtt_conn_d *conn, const char *t)
{
    utarray_push_back(conn->topics, &t);
}

static struct mqtt_conn_mngr *
mqtt_mngr_new()
{
    struct mqtt_conn_mngr *m = malloc(sizeof(struct mqtt_conn_mngr));
    m->conns = NULL;
    pthread_mutex_init(&m->mtx, NULL);
    return m;
}

static struct mqtt_conn_d *
mqtt_mngr_add_conn(struct mqtt_conn_mngr *m,
                   umplg_mngr_t *pm,
                   const struct json_object *j_conn)
{

    // address
    struct json_object *j_addr = json_object_object_get(j_conn, "address");
    // label
    struct json_object *j_name = json_object_object_get(j_conn, "name");
    // proc thread queue size
    struct json_object *j_pth_qsz = json_object_object_get(j_conn, "proc_thread_qsize");
    // binary upload path
    struct json_object *j_bin_path = json_object_object_get(j_conn, "bin_upload_path");
    // rx handler
    struct json_object *j_rxh = json_object_object_get(j_conn, "rx_handler");
    // sanity check
    if (j_addr == NULL || j_name == NULL) {
        return NULL;
    }
    // label should not be present
    struct mqtt_conn_d *tmp_conn = NULL;
    // GCOVR_EXCL_BR_START
    HASH_FIND_STR(m->conns, json_object_get_string(j_name), tmp_conn);
    // GCOVR_EXCL_BR_STOP
    if (tmp_conn != NULL) {
        return NULL;
    }
    // new mqtt connection
    struct mqtt_conn_d *c = mqtt_conn_new(pm);
    c->name = strdup(json_object_get_string(j_name));
    // queue size optional (default = 256)
    c->sig_qsz = json_object_get_int(j_pth_qsz);
    if (c->sig_qsz < 256) {
        c->sig_qsz = 256;
    }
    c->sig_q = spscq_new(c->sig_qsz);
    sem_init(&c->sig_sem, 0, 0);
    // binary upload path
    if(j_bin_path != NULL){
        if (mkdir(json_object_get_string(j_bin_path),
                  S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0 &&
            errno != EEXIST) {
            umd_log(UMD,
                    UMD_LLT_ERROR,
                    "plg_mqtt: [cannot create binary upload directory]");

        }else{
            c->bin_upl_path = strdup(json_object_get_string(j_bin_path));
        }
    }
    // set default path
    if (c->bin_upl_path == NULL) {
        c->bin_upl_path = strdup("/tmp");
    }
    // rx handler
    if (j_rxh != NULL){
        c->rxh = strdup(json_object_get_string(j_rxh));
    }
    pthread_create(&c->sig_th, NULL, &mqtt_proc_thread, c);
    // lock
    pthread_mutex_lock(&m->mtx);
    // add to conn list
    // GCOVR_EXCL_BR_START
    HASH_ADD_KEYPTR(hh, m->conns, c->name, strlen(c->name), c);
    // GCOVR_EXCL_BR_STOP
    // unlock
    pthread_mutex_unlock(&m->mtx);
    // return new conn
    return c;
}

static void
mqtt_mngr_process_conns(struct mqtt_conn_mngr *m, void (*f)(struct mqtt_conn_d *conn))
{
    // lock
    pthread_mutex_lock(&m->mtx);
    struct mqtt_conn_d *c_conn = NULL;
    struct mqtt_conn_d *tmp_conn = NULL;
    HASH_ITER(hh, m->conns, c_conn, tmp_conn)
    {
        f(c_conn);
    }
    // unlock
    pthread_mutex_unlock(&m->mtx);
}

static void
mqtt_mngr_del_conn(struct mqtt_conn_mngr *m, const char *name, bool th_safe)
{
    struct mqtt_conn_d *tmp_conn = NULL;
    // lock
    if (th_safe) {
        pthread_mutex_lock(&m->mtx);
    }
    HASH_FIND_STR(m->conns, name, tmp_conn); // GCOVR_EXCL_BR_LINE
    if (tmp_conn != NULL) {
        pthread_join(tmp_conn->sig_th, NULL);
        sem_destroy(&tmp_conn->sig_sem);
        spscq_free(tmp_conn->sig_q);
        HASH_DEL(m->conns, tmp_conn); // GCOVR_EXCL_BR_LINE
        MQTTAsync_destroy(&tmp_conn->client);
        free(tmp_conn->name);
        free(tmp_conn->rxh);
        utarray_free(tmp_conn->topics);
        free(tmp_conn->bin_upl_path);
        free(tmp_conn);
    }
    // unlock
    if (th_safe) {
        pthread_mutex_unlock(&m->mtx);
    }
}

static void
mqtt_term(struct mqtt_conn_d *conn)
{
    mqtt_mngr_del_conn(mqtt_mngr, conn->name, false);
}

int
mqtt_mngr_send(const struct mqtt_conn_mngr *m,
               struct mqtt_conn_d *c,
               const char *t,
               bool retain,
               void *d,
               size_t dsz)
{
    if (!(m != NULL && c != NULL && t != NULL && d != NULL && dsz > 0)) {
        return -100;
    }

    // setup mqtt payload
    MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    opts.context = c;
    pubmsg.payload = d;
    pubmsg.payloadlen = dsz;
    pubmsg.qos = 1;
    pubmsg.retained = retain;

    // send
    return  MQTTAsync_sendMessage(c->client, t, &pubmsg, &opts);
}

struct mqtt_conn_d *
mqtt_mngr_get_conn(struct mqtt_conn_mngr *m, const char *name)
{
    if (m == NULL) {
        return NULL;
    }
    struct mqtt_conn_d *tmp_conn = NULL;
    // lock
    pthread_mutex_lock(&m->mtx);
    HASH_FIND_STR(m->conns, name, tmp_conn); // GCOVR_EXCL_BR_LINE
    // unlock
    pthread_mutex_unlock(&m->mtx);
    return tmp_conn;
}

static int
process_cfg(umplg_mngr_t *pm, struct mqtt_conn_mngr *mngr)
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
    // get connections
    struct json_object *jobj = json_object_object_get(plg_cfg, "connections");
    if (jobj != NULL && json_object_is_type(jobj, json_type_array)) {
        // loop an verify connections
        int conn_l = json_object_array_length(jobj);
        for (int i = 0; i < conn_l; ++i) {
            // get array object (v declared in json_object_object_foreach macro)
            struct json_object *j_conn = json_object_array_get_idx(jobj, i);
            // check env object type
            if (!json_object_is_type(j_conn, json_type_object)) {
                umd_log(UMD, UMD_LLT_ERROR, "plg_mqtt: [invalid MQTT connection object]");
                return 4;
            }
            // get connection values
            struct json_object *j_n = json_object_object_get(j_conn, "name");
            struct json_object *j_addr = json_object_object_get(j_conn, "address");
            struct json_object *j_clid = json_object_object_get(j_conn, "client_id");
            struct json_object *j_usr = json_object_object_get(j_conn, "username");
            struct json_object *j_pwd = json_object_object_get(j_conn, "password");
            struct json_object *j_pth_qsz = json_object_object_get(j_conn, "proc_thread_qsize");
            struct json_object *j_bin_path = json_object_object_get(j_conn, "bin_upload_path");
            struct json_object *j_rxh = json_object_object_get(j_conn, "rx_handler");
            // all values are mandatory
            if (!(j_n && j_addr && j_clid && j_usr && j_pwd)) {
                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_mqtt: [malformed MQTT connection (missing values)]");
                return 5;
            }
            // check types
            if (!(json_object_is_type(j_n, json_type_string) &&
                  json_object_is_type(j_addr, json_type_string) &&
                  json_object_is_type(j_clid, json_type_string) &&
                  json_object_is_type(j_usr, json_type_string) &&
                  json_object_is_type(j_pwd, json_type_string))) {

                umd_log(UMD,
                        UMD_LLT_ERROR,
                        "plg_mqtt: [malformed MQTT connection (wrong type)]");
                return 6;
            }
            // proc thread queue size
            if (j_pth_qsz != NULL) {
                if (!json_object_is_type(j_pth_qsz, json_type_int)) {
                    umd_log(UMD,
                            UMD_LLT_ERROR,
                            "plg_mqtt: [wrong type for 'proc_thread_qsize']");
                    return 6;
                }
            }
            // binary upload path
            if (j_bin_path != NULL) {
                if (!json_object_is_type(j_bin_path, json_type_string)) {
                    umd_log(UMD,
                            UMD_LLT_ERROR,
                            "plg_mqtt: [wrong type for 'bin_upload_path']");
                    return 6;
                }
            }

            // rx handler
            if (j_rxh != NULL) {
                if (!json_object_is_type(j_rxh, json_type_string)) {
                    umd_log(UMD,
                            UMD_LLT_ERROR,
                            "plg_mqtt: [wrong type for 'rx_handler']");
                    return 6;
                }
            }

            // create MQTT connection
            struct mqtt_conn_d *conn = mqtt_mngr_add_conn(mngr, pm, j_conn);
            if (!conn) {
                continue;
            }
            // subscribe to topics
            struct json_object *j_sub = json_object_object_get(j_conn, "subscriptions");
            if (j_sub != NULL && json_object_is_type(j_sub, json_type_array)) {
                int sub_l = json_object_array_length(j_sub);
                for (int j = 0; j < sub_l; ++j) {
                    // get array object (v declared in json_object_object_foreach macro)
                    v = json_object_array_get_idx(j_sub, j);
                    // verify type
                    if (!json_object_is_type(v, json_type_string)) {
                        continue;
                    }
                    mqtt_conn_add_topic(conn, json_object_get_string(v));
                }
            }
            umd_log(UMD, UMD_LLT_INFO, "plg_mqtt: [adding connection [%s]", conn->name);
            mqtt_conn_connect(conn, j_conn);
        }
    }

    return 0;
}

static void
init_mqtt_lua_module(lua_State *L)
{
    luaL_newlib(L, mqtt_lualib);

}

/********************************************/
/* MQTT module create (signal init handler) */
/********************************************/
static int
mqtt_module_sig_run(umplg_sh_t *shd,
                    umplg_data_std_t *d_in,
                    char **d_out,
                    size_t *out_sz,
                    void *args)
{

    // get lua state (assume args != NULL)
    lua_State *L = args;

    // get M module from globals
    lua_getglobal(L, "M");
    // add MQTT sub-module
    lua_pushstring(L, "mqtt");
    init_mqtt_lua_module(L);
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
    // mqtt conn manager
    mqtt_mngr = mqtt_mngr_new();
    if (process_cfg(pm, mqtt_mngr)) {
        umd_log(UMD, UMD_LLT_ERROR, "plg_mqtt: [cannot process plugin configuration]");
    }
    // binary file upload lock
    pthread_mutex_init(&bin_upl_mtx, NULL);

    // create signal handler for creating MQTT module
    // when per-thread Lua state creates the M module
    umplg_sh_t *sh = calloc(1, sizeof(umplg_sh_t));
    sh->id = strdup("@init_lua_sub_module:mqtt");
    sh->run = &mqtt_module_sig_run;
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
    mqtt_mngr_process_conns(mqtt_mngr, &mqtt_term);
}

static void
term_phase_1(umplg_mngr_t *pm, umplgd_t *pd)
{
    free(mqtt_mngr);
    mqtt_bin_cleanup();
    pthread_mutex_destroy(&bin_upl_mtx);
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

/*************************************/
/* local CMD_MQTT_PUBLISH (standard) */
/*************************************/
static void
impl_mqtt_publish(umplg_data_std_t *data)
{
    // sanity check
    if (data == NULL || utarray_len(data->items) < 3) {
        umd_log(UMD, UMD_LLT_ERROR, "plg_mqtt: [CMD_MQTT_PUBLISH invalid data]");
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
    struct mqtt_conn_d *c = mqtt_mngr_get_conn(mqtt_mngr, column->value);
    if (c == NULL) {
        return;
    }
    // mqtt data
    row = utarray_eltptr(data->items, 2);
    const umplg_data_std_item_t *mqtt_data = row->table;
    // mqtt topic
    row = utarray_eltptr(data->items, 1);
    const umplg_data_std_item_t *mqtt_topic = row->table;

    // do not retain by default
    bool retain = false;
    // check retain flag in input data
    if (utarray_len(data->items) >= 4) {
        row = utarray_eltptr(data->items, 3);
        retain = atoi(row->table->value);
    }

    // publish
    mqtt_conn_pub(c,
                  mqtt_data->value,
                  strlen(mqtt_data->value),
                  mqtt_topic->value,
                  retain);
}

/********************************/
/* local CMD_MQTT_BINARY_UPLOAD */
/********************************/
static void
impl_mqtt_bin_upload(umplg_data_std_t *data)
{
    // sanity check
    if (data == NULL || utarray_len(data->items) < 2) {
        umd_log(UMD, UMD_LLT_ERROR, "plg_mqtt: [CMD_MQTT_BINARY_UPLOAD invalid data]");
        return;
    }
    // get connection
    const umplg_data_std_items_t *cname = utarray_eltptr(data->items, 0);
    // get filesize
    const umplg_data_std_items_t *fsz = utarray_eltptr(data->items, 1);
    // sanity chhecks
    if (HASH_COUNT(fsz->table) < 1 || HASH_COUNT(cname->table) < 1) {
        return;
    }
    // connection
    const struct mqtt_conn_d *c = mqtt_mngr_get_conn(mqtt_mngr, cname->table->value);
    if (c == NULL) {
        return;
    }
    // add new file
    mqtt_file_d_t *fd = mqtt_bin_upl_add(c->bin_upl_path, atoi(fsz->table->value));
    if (fd == NULL) {
        return;
    }
    // return file uuid
    umplg_data_std_items_t items = { .table = NULL };
    umplg_data_std_item_t item_uuid = { .name = "file_uuid",
                                        .value = fd->uuid };
    umplg_stdd_item_add(&items, &item_uuid);
    umplg_stdd_items_add(data, &items);
    // cleanup
    HASH_CLEAR(hh, items.table);
}

/*************************/
/* local command handler */
/*************************/
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
        case CMD_MQTT_PUBLISH:
            impl_mqtt_publish(plg_d);
            break;
        case CMD_MQTT_BINARY_UPLOAD:
            impl_mqtt_bin_upload(plg_d);
            break;

        default:
            break;
        }

        return 0;
    }

    // unsupported interface
    return -2;
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
