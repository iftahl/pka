#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_ssl_engine.h>


#define EXTERNAL_POLL_DEFAULT_INTERVAL              1     // Default polling interval is 1ms

ngx_msec_t pka_engine_external_poll_interval; // xxx msec polling interval

typedef struct {
    ngx_str_t       engine_id;
    /* if this engine can be released during worker is shutting down */
    // ngx_flag_t      releasable;
    /* only async for pka engine, typically sync or async */
    ngx_str_t       offload_mode;

    /* no need for pka engine, typically event or poll */
    ngx_str_t       notify_mode;

    /* no need for pka engine */
    ngx_str_t       poll_mode;

    /* xxx ms */
    ngx_int_t       external_poll_interval;

} ngx_ssl_engine_pka_conf_t;

//static ngx_int_t ngx_ssl_engine_pka_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_ssl_engine_pka_send_ctrl(ngx_cycle_t *cycle);
static ngx_int_t ngx_ssl_engine_pka_register_handler(ngx_cycle_t *cycle);
//static ngx_int_t ngx_ssl_engine_pka_release(ngx_cycle_t *cycle);

static char *ngx_ssl_engine_pka_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_ssl_engine_pka_create_conf(ngx_cycle_t *cycle);
static char *ngx_ssl_engine_pka_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_ssl_engine_pka_process_init(ngx_cycle_t *cycle);
static void ngx_ssl_engine_pka_process_exit(ngx_cycle_t *cycle);

static ENGINE          *pka_engine;

static ngx_str_t      ssl_engine_pka_name = ngx_string("pka");

static ngx_command_t  ngx_ssl_engine_pka_commands[] = {

    { ngx_string("pka_engine"),
      NGX_SSL_ENGINE_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_ssl_engine_pka_block,
      0,
      0,
      NULL },

    { ngx_string("pka_offload_mode"),
      NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_engine_pka_conf_t, offload_mode),
      NULL },

    { ngx_string("pka_notify_mode"),
      NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_engine_pka_conf_t, notify_mode),
      NULL },

    { ngx_string("pka_poll_mode"),
      NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_engine_pka_conf_t, poll_mode),
      NULL },

    { ngx_string("pka_external_poll_interval"),
    NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    0,
    offsetof(ngx_ssl_engine_pka_conf_t, external_poll_interval),
    NULL },

      ngx_null_command
};

ngx_ssl_engine_module_t  ngx_ssl_engine_pka_module_ctx = {
    &ssl_engine_pka_name,
    ngx_ssl_engine_pka_create_conf,               /* create configuration */
    ngx_ssl_engine_pka_init_conf,                 /* init configuration */

    {
        NULL,
        ngx_ssl_engine_pka_send_ctrl,
        ngx_ssl_engine_pka_register_handler,
        NULL,
        NULL
    }
};

ngx_module_t  ngx_ssl_engine_pka_module = {
    NGX_MODULE_V1,
    &ngx_ssl_engine_pka_module_ctx,         /* module context */
    ngx_ssl_engine_pka_commands,            /* module directives */
    NGX_SSL_ENGINE_MODULE,                  /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_ssl_engine_pka_process_init,        /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_ssl_engine_pka_process_exit,        /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_ssl_engine_pka_send_ctrl(ngx_cycle_t *cycle)
{
    const char *engine_id = "pka";
    ENGINE     *e;

    e = ENGINE_by_id(engine_id);
    if (e == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ENGINE_by_id(\"pka\") failed");
        return NGX_ERROR;
    }

    /* send ctrl before engine init */

    // external interval zero means that we're relying on the LibPKA polling threads
    int poll_status = 0;
    if (pka_engine_external_poll_interval != 0){
        if (!ENGINE_ctrl_cmd(e, "ENABLE_EXTERNAL_POLLING", 0, &poll_status, NULL, 0)) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "PKA Engine ENABLE_EXTERNAL_POLLING failed");
        }
    }

    /* ssl engine global variable set */

    ENGINE_free(e);

    return NGX_OK;
}


static char *
ngx_ssl_engine_pka_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char           *rv;
    ngx_conf_t      pcf;

    pcf = *cf;
    cf->cmd_type = NGX_SSL_ENGINE_SUB_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return NGX_CONF_OK;
}

//TODO: set offload_mode, notify_mode, poll_mode
static void *
ngx_ssl_engine_pka_create_conf(ngx_cycle_t *cycle)
{
    ngx_ssl_engine_pka_conf_t  *sedcf;

    sedcf = ngx_pcalloc(cycle->pool, sizeof(ngx_ssl_engine_pka_conf_t));
    if (sedcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sedcf->offload_mode = NULL
     *     sedcf->notify_mode = NULL
     *     sedcf->poll_mode = NULL
     */


     sedcf->external_poll_interval = NGX_CONF_UNSET;

    return sedcf;
}


static char *
ngx_ssl_engine_pka_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_ssl_engine_pka_conf_t *sedcf = conf;
    ngx_ssl_engine_conf_t * corecf =
        ngx_engine_cycle_get_conf(cycle, ngx_ssl_engine_core_module);
    if(corecf == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                     "conf of engine_core_module is null");
        return NGX_CONF_ERROR;
    }


    if (0 != corecf->ssl_engine_id.len) {
        ngx_conf_init_str_value(sedcf->engine_id, corecf->ssl_engine_id.data);
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "No engine id found.");
        return NGX_CONF_ERROR;
    }

    /* init the conf values not set by the user */

    ngx_conf_init_str_value(sedcf->offload_mode, "async");
    ngx_conf_init_str_value(sedcf->notify_mode, "poll");
    ngx_conf_init_str_value(sedcf->poll_mode, "external");

    ngx_conf_init_value(sedcf->external_poll_interval,
                            EXTERNAL_POLL_DEFAULT_INTERVAL);
    
    if (sedcf->external_poll_interval > 100
        || sedcf->external_poll_interval < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "invalid external poll interval");
        return NGX_CONF_ERROR;
    }

    pka_engine_external_poll_interval = sedcf->external_poll_interval;



    /* check the validity of the conf vaules */
/*
    if (ngx_strcmp(sedcf->offload_mode.data, "async") != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "wrong type for pka_offload_mode");
        return NGX_CONF_ERROR;
    }
*/

    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_ssl_engine_pka_process_init(ngx_cycle_t *cycle){

ngx_ssl_engine_pka_conf_t *conf =
        ngx_engine_cycle_get_conf(cycle, ngx_ssl_engine_pka_module);
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                     "conf of engine_core_module is null");
        return NGX_ERROR;
    }

    if (0 == (const char *) conf->engine_id.len) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                     "engine id not found");
        return NGX_ERROR;
    }

    pka_engine = ENGINE_by_id((const char *) conf->engine_id.data);
    if (pka_engine == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ENGINE_by_id(\"%s\") failed", conf->engine_id.data);
        return NGX_ERROR;
    }

    return NGX_OK;
}



static void
ngx_ssl_engine_pka_process_exit(ngx_cycle_t *cycle)
{
    ENGINE_cleanup();
}


static void
pka_engine_external_poll_handler(ngx_event_t *ev)
{
    
    int poll_status = 0;

    if (!ENGINE_ctrl_cmd(pka_engine, "POLL", 0, &poll_status, NULL, 0)) {
            ngx_log_error(NGX_LOG_EMERG, ev->log, 0, "PKA Engine failed: POLL");
    }

 //   fprintf(stderr,"pid=%d , pka_engine_external_poll_interval=%ld\n ",getpid(),pka_engine_external_poll_interval);

    ngx_add_timer(ev, pka_engine_external_poll_interval);
}

    


static ngx_event_t      pka_engine_external_poll_event;
static ngx_connection_t dumb;

static ngx_int_t
ngx_ssl_engine_pka_register_handler(ngx_cycle_t *cycle)
{

    //relying on PKA's internal polling thread if 0 or sync mode PKA if -1
    if (pka_engine_external_poll_interval == 0){
        return NGX_OK;
    }
    
    memset(&pka_engine_external_poll_event, 0, sizeof(ngx_event_t));

    dumb.fd = (ngx_socket_t) -1;
    pka_engine_external_poll_event.data = &dumb;

    pka_engine_external_poll_event.handler = pka_engine_external_poll_handler;
    pka_engine_external_poll_event.log = cycle->log;
    pka_engine_external_poll_event.cancelable = 0;

    ngx_add_timer(&pka_engine_external_poll_event, 100);
    pka_engine_external_poll_event.timer_set = 1;

    return NGX_OK;
}


