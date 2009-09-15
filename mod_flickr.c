#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"

#include "ap_config.h"
#include "apr_hooks.h"
#include "apr_hash.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "apr_lib.h"

#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/types.h>
#include "md5.h"

#include "flick.h"

#ifdef WITH_CACHING
#include <libmemcached/memcached.h>
#if APR_HAS_THREADS
#include "apr_thread_mutex.h"
#endif
#endif

/*
 * mod_flickr
 * Apache module curl'ing flickr api's to
 * retrieve user's album etc..
 * 
 */

/*
 * The following are initialized by each
 * child process in the child_init hook.
 *
 * They are _strictly_ supposed to be read
 * only.
 */

typedef struct {
	char *user_id;				/* "user_id" string		*/
	char *who;					/* who: me ?			*/

	/*
	 * this hash contains the api
	 * name as the key and a pointer
	 * to the function that implements
	 * the API as the value.
	 */
	apr_hash_t *api_call_table;

	/*
	 * only if caching is enabled.
	 */
#ifdef WITH_CACHING
	memcached_st *memc;
	memcached_server_st *servers;
#if APR_HAS_THREADS
	/* 
	 * mutex to protect the cache from
	 * concurrent access.
	 */
	apr_thread_mutex_t *mutex;
#endif
#endif
} svr_constants;

svr_constants *svr_cfg;

module AP_MODULE_DECLARE_DATA mod_flickr;

/* --------------------------------------------------------- */
/*						HELPER ROUTINES						 */

/*
 * Generate MD5 hash for the string.
 * XXX: Uses request pool to store the
 * generated hash, no need to free().
 */
static char
*flickr_md5_gen(apr_pool_t *p, char *str)
{
        return MD5_string(p, str);
}

/*
 * Preapare the signature string for
 * which the hash has to be calculated.
 */
static char
*flickr_signature_string(apr_pool_t *p, page_data *pg)
{
        return (apr_psprintf(p, FLICKR_SIGNATURE_STRING,
										SECRET(pg),
										APIKEY(pg),
										AUTHTKN(pg),
										RAWSIGN(pg)));
}

/*
 * Prepare the Auth part of the API call.
 */
static char
*flickr_auth_string(apr_pool_t *p, char *hash, page_data *pg)
{
        return (apr_psprintf(p, FLICKR_AUTH_STRING,
										APIKEY(pg),
										AUTHTKN(pg),
										hash,
										RAWARGS(pg)));
}

/*
 * duuplicate the string in a given
 * memory pool.
 */

static char 
*flickr_dup_string(apr_pool_t *p, char *s)
{
	return apr_pstrdup(p, s);
}

/* These macros are crocky !!! */
#define	DUP(p,s)		flickr_dup_string(p,s)

/*
 * Set/Get the API function pointer
 * from the api_call_table.
 */
#define	APIENTRY(k,v)	apr_hash_set(svr_cfg->api_call_table,	\
											DUP(pchild,k),		\
											APR_HASH_KEY_STRING,\
											v)
#define	APIGET(h,k)		apr_hash_get(h, k,\
					 			APR_HASH_KEY_STRING)
/*
 * Duplicate string (key/value) and 
 * set it in the table.
 *
 * @args:
 *	p: pool to strdup() the string.
 *	m: table name
 *	k: Key
 *	v: value
 */
#define ATS(m,k,v)		apr_table_setn(m, k, v)
/* strdup() both key/value. */
#define ATSD(p,m,k,v)	apr_table_setn(m, DUP(p, k), DUP(p,v))
/* strdup() the key. */
#define ATSKD(p,m,k,v)	apr_table_setn(m, DUP(p, k), v)
/* strdup() the value */
#define ATSVD(p,m,k,v)	apr_table_setn(m, k, DUP(p,v))

static int
add_length(void *tbl, char *key, char *value)
{
	table_stat *t = (table_stat *) tbl;

	t->args_len += strlen(key) + strlen(value);
	t->nr_iterations++;
	
	return 1;
}

static int
flatten_table(void *data, char *key, char *value)
{
	page_data *pg = (page_data *) data;

	memcpy(SIGOFFT(pg), key, strlen(key));
	pg->offset_t += strlen(key);

	memcpy(SIGOFFT(pg), value, strlen(value));
	pg->offset_t += strlen(value);

	return 1;
}

static int
flatten_table_for_args(void *data, char *key, char *value)
{
	page_data *pg = (page_data *) data;

	memcpy(ARGOFFT(pg), key, strlen(key));
	pg->offset_t += strlen(key);

	memcpy(ARGOFFT(pg), "=", 1);
	pg->offset_t++;

	memcpy(ARGOFFT(pg), value, strlen(value));
	pg->offset_t += strlen(value);

	pg->iterations--;
	if (pg->iterations) {
		memcpy(ARGOFFT(pg), "&", 1);
		pg->offset_t++;
	}

	return 1;
}
/*
 * Get 'nargs' parameters separated
 * by '/' from the argument string.
 *
 * On return, the passes array (arena)
 * will look something like:
 *	([ptr to 1st arg], [ptr to 2nd arg]...[ptr to nth arg]
 */
static int
flickr_get_xtra_params(request_rec *r, page_data *pg, char **arena,
									   					int nargs)
{
	int i = 0;
	char *temp;

	for (; i < nargs; i++) {
		if (!pg->uri_len) {
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
					"%d args can't be extracted from arg string, Uri: %s",
					nargs, r->unparsed_uri);
			return 0;
		}

		if (!(arena[i] = ap_strchr(pg->my_uri, '/'))) {
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
						"Premature Absence of '/' in arg list for Uri: %s",
						r->unparsed_uri);
			return 0;
		}

		*(arena[i]) = '\0';
		arena[i]++;

		temp = arena[i];
		arena[i] = pg->my_uri;
		pg->my_uri = temp;

		pg->uri_len -= (strlen(arena[i]) + 1);
	}

	return 1;
}

/* ------------------------------------------------------------- */

/* ---------------- cURL invocation routines here. ------------- */

static int
flickr_memory_alloc(void *data, size_t size)
{
	mem_chunk *memory = (mem_chunk *) data;

	if (!(memory->api_response))
		memory->api_response = malloc(size);
	else
		memory->api_response = realloc(memory->api_response,
									size + memory->size);

	return (memory->api_response != NULL);
}

static size_t
curl_process_chunk(void *remote_data, size_t sz, 
									 size_t mems,
									 void *data)
{
	size_t total_size = sz * mems;
	mem_chunk *dt;

	if (flickr_memory_alloc(data, total_size)) {
		dt = (mem_chunk*) data;

		memcpy((dt->api_response) + dt->size,
				(char *)remote_data,
				total_size);
		dt->size += total_size;
		*((dt->api_response) + dt->size) = 0;
	}
	return total_size;
}

static void
flickr_request_data(mem_chunk *mem, char *api)
{

	CURL *curl_handle;

	mem->api_response = NULL;
	mem->size	 = 0;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();

	curl_easy_setopt(curl_handle, CURLOPT_URL, api);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
									 curl_process_chunk);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA,
									 (void *)mem);

	curl_easy_perform(curl_handle);
	curl_easy_cleanup(curl_handle);
}


/* ------------------------------------------------------------- */

/*
 * Return (non)configured user creds from
 * the user_cred hash.
 */
static void
*get_user(user_cred *uc, char *user)
{
	return apr_hash_get(uc->user, user, APR_HASH_KEY_STRING);
}

/*
 * Parse the request URI into username and album.
 * Create the flickr resource if the username has
 * creds given in the httpd conf file.
 * TODO: Improve this routine.
 */
static int
parse_request(request_rec *r, page_data *pg, user_cred *uc)
{
	pg->uri_len = strlen(r->unparsed_uri);

	if (r->unparsed_uri[pg->uri_len - 1] != '/') {
		pg->my_uri = apr_pstrdup(r->pool,
									apr_pstrcat(r->pool,
												r->unparsed_uri, "/",
												NULL));
		pg->uri_len++;
	} else {
		pg->my_uri = apr_pstrdup(r->pool, r->unparsed_uri);
	}

	if (!(pg->user = ap_strchr(pg->my_uri + 1, '/')))
		return 0;

	*(pg->user) = '\0';
	pg->user++;

	pg->uri_len -= 8;

	if (!(pg->api_call = ap_strchr(pg->user, '/')))
		return 0;

	*(pg->api_call) = '\0';
	pg->api_call++;

	if (!(pg->creds = (api_key_secret *) get_user(uc, pg->user)))
		return 0;

	pg->uri_len -= (strlen(pg->user) + 1);

	if (!(pg->my_uri = ap_strchr(pg->api_call, '/')))
		return 0;

	*(pg->my_uri) = '\0';
	pg->my_uri++;

	pg->uri_len -= (strlen(pg->api_call) + 1);

	return 1;
}

static void
*create_per_server_config(apr_pool_t *p, server_rec *s)
{
	user_cred *uc = apr_pcalloc(p, sizeof(user_cred));
	
	uc->on_off	= 0;		/* Off by default */
	uc->user	= apr_hash_make(p);
#ifdef WITH_CACHING
	uc->memc_svr = apr_array_make(p, 6, sizeof(char *));
#endif

	return uc;
}

static char
*flickr_set_on_off(cmd_parms *cmd, void *dummy, char *arg)
{
	user_cred *uc = ap_get_module_config(cmd->server->module_config,
									  	&mod_flickr);

	if (uc)
		uc->on_off = arg ? 1 : 0;

	return NULL;
}

#ifdef WITH_CACHING
static char
*flickr_set_cache_server(cmd_parms *cmd, void *dummy, char *arg)
{
	user_cred *uc = ap_get_module_config(cmd->server->module_config,
										&mod_flickr);
	if (uc) {
		char **entry = apr_array_push(uc->memc_svr);
		*entry = (void *)arg;
	}
	return NULL;
}

static char
*flickr_set_cache_timeout(cmd_parms *cmd, void *dummy, char *user,
														char *val)
{
	api_key_secret *cred;
	user_cred *uc = ap_get_module_config(cmd->server->module_config,
										&mod_flickr);

	if (uc) {
		if ( (cred = get_user(uc, user)) ) {
			char c = val[strlen(val) - 1];
			int multiplier = 1;

			if (!apr_isdigit(c)) {
				switch (c) {
					case 's':
					case 'S':
						multiplier = 1;
						break;
					case 'm':
					case 'M':
						multiplier = 60;
						break;
					case 'h':
					case 'H':
						multiplier = 3600;
						break;
					case 'd':
					case 'D':
						multiplier = 24 * 3600;
						break;
				}
			}
			cred->delta_cache_timeout = atoi(val) * multiplier;
		}
	}

	return NULL;
}
#endif

static char
*flickr_set_user(cmd_parms *cmd, void *dummy, char *arg)
{
	api_key_secret *cred = apr_pcalloc(cmd->pool,
									  sizeof(api_key_secret));

#ifdef WITH_CACHING
	/* don't cache by default. */
	cred->delta_cache_timeout = -1;
#endif

	/*
	 * Set default privacy level to public.
	 *
	 * Privacy Levels: (from flickr API documentation)
	 *	1 - public photos
	 *	2 - private photos visible to friends
	 *	3 - private photos visible to family
	 *	4 - private photos visible to friends & family
	 *	5 - completely private photos
	 */
	cred->privacy = 1;

	user_cred *uc = ap_get_module_config(cmd->server->module_config,
										&mod_flickr);

	if (uc)
		apr_hash_set(uc->user, arg, APR_HASH_KEY_STRING,
									(void *)cred);

	return NULL;
}

/*
 * Common routine for setting
 * user creds.
 */
static const char
*flickr_set_var(cmd_parms *cmd, void *dummy, char *user, char *var)
{
	api_key_secret *cred;
	int offset = (int)(long) cmd->info;
	user_cred *uc = ap_get_module_config(cmd->server->module_config,
												&mod_flickr);

	if (uc) {
		if ( (cred = get_user(uc, user)) ) {
			*(const char **)((char *)cred + offset) = var;
		}
	}
	return NULL;
}

/*
 * Set user privacy level.
 * Levels are as follows: (case sensitive)
 *	- Public
 *	- FriendsOnly
 *	- FamilyOnly
 *	- FriendsAndFamily
 *	- PrivateOnly
 */

static const char
*flickr_set_user_privacy(cmd_parms *cmd, void *dummy, char *user, char *arg)
{
	api_key_secret *cred;
    user_cred *uc = ap_get_module_config(cmd->server->module_config,
                                                &mod_flickr);

	if (uc) {
		if ( (cred = get_user(uc, user)) ) {
			/* ha, ha, ha, am i clever? Crapppppp. */
			if ( (*arg == 'P') && (!strcmp(arg, "PrivateOnly")) )
				cred->privacy = 5;
			else {
				if (!strcmp(arg, "FriendsOnly"))
					cred->privacy = 2;
				else
					if (!strcmp(arg, "FamilyOnly"))
						cred->privacy = 3;
					else
						if (!strcmp(arg, "FriendsAndFamily"))
							cred->privacy = 4;
			}
		}
	}

	return NULL;
}


static const command_rec module_cmds[] = {
	AP_INIT_FLAG("FlickrMod", flickr_set_on_off, NULL, RSRC_CONF,
				"Enables/Disables the flickr module"),
#ifdef WITH_CACHING
	AP_INIT_ITERATE("FlickrCacheServers", flickr_set_cache_server, NULL,
				RSRC_CONF, "Enable/Disable memcache, takes list\
								of memcache servers"),
	AP_INIT_TAKE2("FlickrCacheTimeout", flickr_set_cache_timeout,
				NULL, RSRC_CONF, "User name and Cache Expire timeout\
								for flickr response"),
#endif
	AP_INIT_TAKE1("FlickrUser", flickr_set_user, NULL, RSRC_CONF,
				"Username for the flickr account/URL query"),
	AP_INIT_TAKE2("FlickrKey", flickr_set_var,
				(void *)APR_OFFSETOF(api_key_secret, api_key),
				RSRC_CONF, "Username and key for the flickr user"),
	AP_INIT_TAKE2("FlickrSecret", flickr_set_var,
				(void *)APR_OFFSETOF(api_key_secret, secret),
				RSRC_CONF, "Username and secret for the account"),
	AP_INIT_TAKE2("FlickrAuth", flickr_set_var,
				(void *)APR_OFFSETOF(api_key_secret, auth_token),
				RSRC_CONF, "Username and Auth token"),
	AP_INIT_TAKE2("FlickrUserPrivacy", flickr_set_user_privacy, NULL,
				RSRC_CONF, "Privacy Level for this user"),
	{NULL} 
};

/*
 * Since every API needs to generate the
 * secret hash, argument list etc.., macros
 * have been declared for that purpose and
 * should be used while writing the API.
 */


/*
 * Compute the length of the buffer needed
 * to hold the string to be hashed.
 */
#define	GENHASHSTRING(r,pg,ts,m) \
				do { \
					apr_table_do((void *)add_length, &ts, m, NULL);						\
					pg->raw_signature = apr_pcalloc(r->pool, ts.args_len + 1);	\
					*(pg->raw_signature + ts.args_len) = '\0';					\
					pg->offset_t = 0;											\
				} while(0);
/*
 * Flatten the signature string and
 * generate the MD5 hash from it.
 */
#define GENHASH(r,pg,m,h) \
				do { \
					apr_table_do((void *)flatten_table, pg, m, NULL);							\
					h = flickr_md5_gen(r->pool, flickr_signature_string(r->pool, pg));	\
				} while(0);

/*
 * Generate the argument list
 * from the argument's table.
 */
#define GENARGSTRING(r,pg,ts,m) \
				do { \
					pg->offset_t = 0;											\
					pg->iterations = ts.nr_iterations;							\
					pg->raw_args = apr_pcalloc(r->pool, SIG2ARG(ts) + 1);		\
					*(pg->raw_args + SIG2ARG(ts)) = '\0';						\
					apr_table_do((void *)flatten_table_for_args, pg, m, NULL);			\
				} while(0);



#define GETDATA(pg,a)	flickr_request_data(&pg->mem, a);
#define DATA(pg)		pg->mem.api_response

/*
 * cache the response
 */
#ifdef WITH_CACHING
#define CACHE(r,s,pg)	memcached_set(s->memc, r->unparsed_uri,			\
											strlen(r->unparsed_uri),	\
											DATA(pg),					\
											strlen(DATA(pg)),			\
											CACHEEXP(pg),				\
											(uint32_t)0)	
#endif
											

/* ----------------------------------------------------------- */
/*						API CALL ROUTINES					   */
/* Rules:													   */
/* 0. Use the above macros, they are handy.					   */
/* 1. If you need only 1 param from the uri					   */
/*    use my_uri from page_data directly.					   */
/* 2. Else call the param split routine to					   */
/*	  get the individual params.							   */
/* 3. Return one of the two flickr status					   */
/*	  constants defined in flick.h							   */	
/* ----------------------------------------------------------- */

/*
 * TODO: Move similar code in API's
 * to routines.
 */
#ifdef WITH_CACHING

static int
check_cache(request_rec *r, page_data *pg)
{
	uint32_t flags;
	size_t retval_length;

	memcached_return rc;

	pg->mem.api_response = memcached_get(svr_cfg->memc, r->unparsed_uri,
												strlen(r->unparsed_uri),
												&retval_length, &flags,
												&rc);

	if (rc == MEMCACHED_SUCCESS) {
		apr_pool_cleanup_register(r->pool, pg->mem.api_response,
									      (void *)free,
										  apr_pool_cleanup_null);
		return 1;
	}
	return 0;
}


#if APR_HAS_THREADS

static int
lock_cache(request_rec *r, page_data *pg)
{
	/*
	 * when we are here, we don't have the
	 * data cached, hence we try to acquire
	 * the lock (for memcached) and get data
	 * from Flickr.
	 */

	if ( (apr_thread_mutex_lock(svr_cfg->mutex) != APR_SUCCESS) ) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
					"Failed to aquire mutex...");

		return 0;
	}

	/*
	 * In case the data got pulled from flickr
	 * and cached by another request in between
	 * in call to the initial cache check and
	 * aquiring the lock.
	 */

	if (check_cache(r, pg)) {
		if ( (apr_thread_mutex_unlock(svr_cfg->mutex) != APR_SUCCESS) )
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
				"mod_flickr: Failed to release mutex...");
	}

	return 1;
}

#endif

#endif

/* get photos for the user. */
static int
flickr_get_my_photos(request_rec *r, page_data *pg)
{
	char *api, *hash;
	char *xtra_params[2];
	table_stat ts = {0,0};

#ifdef WITH_CACHING

	/*
	 * Only check cache if the cache
	 * ttl is greater than zero, thereby
	 * saving calls to locking routines.
	 */
	if (CACHEEXP(pg) >= 0 && check_cache(r, pg))
		return FLICKR_STATUS_OK;

#if APR_HAS_THREADS

	if (!lock_cache(r ,pg))
		return FLICKR_STATUS_ERR;

	if (DATA(pg))
		return FLICKR_STATUS_OK;

#endif

#endif

	apr_table_t *method_args = apr_table_make(r->pool, 5); 

	if (!flickr_get_xtra_params(r, pg, xtra_params, 2))
		return FLICKR_STATUS_ERR;

	/*
	 * Fill the table with the method
	 * arguments.
	 */
	ATSD(r->pool,method_args,"method","flickr.photos.search");
	ATSKD(r->pool,method_args,"page",xtra_params[0]);
	ATSKD(r->pool,method_args,"per_page",xtra_params[1]);
	ATSKD(r->pool,method_args,"privacy_filter", apr_itoa(r->pool,
													pg->creds->privacy));
	ATS(method_args,svr_cfg->user_id,svr_cfg->who);

	GENHASHSTRING(r, pg, ts, method_args);
	GENHASH(r, pg, method_args, hash);
	GENARGSTRING(r, pg, ts, method_args);

	api = flickr_auth_string(r->pool, hash, pg);

#ifdef DEBUG
	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
				"API: %s", api);
#endif

	GETDATA(pg, api);

	if (DATA(pg)) {
#ifdef WITH_CACHING
	if (CACHEEXP(pg) >= 0) {
		CACHE(r,svr_cfg,pg);
#if APR_HAS_THREADS
		/* Unlock the Mutex. */
		if ( (apr_thread_mutex_unlock(svr_cfg->mutex) != APR_SUCCESS) )
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
						"mod_flickr: failed to release mutex...");
#endif
	}
#endif
		apr_pool_cleanup_register(r->pool, pg->mem.api_response,
									      (void *)free,
										  apr_pool_cleanup_null);

		return FLICKR_STATUS_OK;
	}

	return FLICKR_STATUS_ERR;
}

/*
 * get users photosets.
 */
static int
flickr_get_my_sets(request_rec *r, page_data *pg)
{
	char *api, *hash;
	table_stat ts = {0,0};

#ifdef WITH_CACHING
    if (CACHEEXP(pg) >= 0 && check_cache(r, pg))
        return FLICKR_STATUS_OK;

#if APR_HAS_THREADS
    if (!lock_cache(r ,pg))
        return FLICKR_STATUS_ERR;

    if (DATA(pg))
        return FLICKR_STATUS_OK;

#endif

#endif


	apr_table_t *method_args = apr_table_make(r->pool, 1); 

	ATSD(r->pool,method_args,"method","flickr.photosets.getList");
	GENHASHSTRING(r, pg, ts, method_args);
	GENHASH(r, pg, method_args, hash);
	GENARGSTRING(r, pg, ts, method_args);

	api = flickr_auth_string(r->pool, hash, pg);

#ifdef DEBUG
	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
				"API: %s", api);
#endif

	GETDATA(pg, api);

	if (DATA(pg)) {
#ifdef WITH_CACHING
    if (CACHEEXP(pg) >= 0) {
        CACHE(r,svr_cfg,pg);
#if APR_HAS_THREADS
        if ( (apr_thread_mutex_unlock(svr_cfg->mutex) != APR_SUCCESS) )
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                        "mod_flickr: failed to release mutex...");
#endif
    }
#endif
		apr_pool_cleanup_register(r->pool, pg->mem.api_response,
									      (void *)free,
										  apr_pool_cleanup_null);

		return FLICKR_STATUS_OK;
	}

	return FLICKR_STATUS_ERR;
}

static int
flickr_get_recent_photos(request_rec *r, page_data *pg)
{
	char *api, *hash;
	char *xtra_params[2];
	table_stat ts = {0,0};

	apr_table_t *method_args = apr_table_make(r->pool, 3); 

	if (!flickr_get_xtra_params(r, pg, xtra_params, 2))
		return FLICKR_STATUS_ERR;

	ATSD(r->pool,method_args,"method","flickr.photos.getRecent");
	ATSKD(r->pool,method_args,"page",xtra_params[0]);
	ATSKD(r->pool,method_args,"per_page",xtra_params[1]);

	GENHASHSTRING(r, pg, ts, method_args);
	GENHASH(r, pg, method_args, hash);
	GENARGSTRING(r, pg, ts, method_args);

	api = flickr_auth_string(r->pool, hash, pg);

#ifdef DEBUG
	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
				"API: %s", api);
#endif

	GETDATA(pg, api);

	if (DATA(pg)) {
		apr_pool_cleanup_register(r->pool, pg->mem.api_response,
									      (void *)free,
										  apr_pool_cleanup_null);

		return FLICKR_STATUS_OK;
	}

	return FLICKR_STATUS_ERR;
}

static int
flickr_get_photos_in_set(request_rec *r, page_data *pg)
{
	char *api, *hash;
	char *xtra_params[3];
	table_stat ts = {0,0};

	apr_table_t *method_args = apr_table_make(r->pool, 5); 

	if (!flickr_get_xtra_params(r, pg, xtra_params, 3))
		return FLICKR_STATUS_ERR;

	ATSKD(r->pool,method_args,"media",xtra_params[2]);
	ATSD(r->pool,method_args,"method","flickr.photosets.getPhotos");
	ATSKD(r->pool,method_args,"page",xtra_params[1]);
	ATSKD(r->pool,method_args,"photoset_id",xtra_params[0]);
	ATSKD(r->pool,method_args,"privacy_filter", apr_itoa(r->pool,
														pg->creds->privacy));

	GENHASHSTRING(r, pg, ts, method_args);
	GENHASH(r, pg, method_args, hash);
	GENARGSTRING(r, pg, ts, method_args);

	api = flickr_auth_string(r->pool, hash, pg);

#ifdef DEBUG
	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
				"API: %s", api);
#endif

	GETDATA(pg, api);

	if (DATA(pg)) {
		apr_pool_cleanup_register(r->pool, pg->mem.api_response,
									      (void *)free,
										  apr_pool_cleanup_null);

		return FLICKR_STATUS_OK;
	}

	return FLICKR_STATUS_ERR;
}

static int
flickr_get_comment_for_photo(request_rec *r, page_data *pg)
{
    char *api, *hash;
    char *xtra_params[1];
    table_stat ts = {0,0};

    apr_table_t *method_args = apr_table_make(r->pool, 2);

    if (!flickr_get_xtra_params(r, pg, xtra_params, 1))
        return FLICKR_STATUS_ERR;

	ATSD(r->pool,method_args,"method","flickr.photos.comments.getList");
	ATSKD(r->pool, method_args, "photo_id", xtra_params[0]);

    GENHASHSTRING(r, pg, ts, method_args);
    GENHASH(r, pg, method_args, hash);
    GENARGSTRING(r, pg, ts, method_args);

    api = flickr_auth_string(r->pool, hash, pg);

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                "API: %s", api); 
#endif

    GETDATA(pg, api);

    if (DATA(pg)) {
        apr_pool_cleanup_register(r->pool, pg->mem.api_response,
                                          (void *)free,
                                          apr_pool_cleanup_null);

        return FLICKR_STATUS_OK;
    }

    return FLICKR_STATUS_ERR;
}

/* ----------------------------------------------------------- */

/*
 * Flickr URL handler
 */
static int
flickr_handler(request_rec *r)
{
	if (!r->handler || strcmp(r->handler, "flickr-handler") != 0)
		return DECLINED;

	if(r->method_number != M_GET)
		return DECLINED;

	user_cred *uc = ap_get_module_config(r->server->module_config,
										&mod_flickr);

	if (!uc->on_off)
		return DECLINED;

	page_data *pg = apr_pcalloc(r->pool, sizeof(page_data));

	if (!parse_request(r, pg, uc)) {
#ifdef DEBUG
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
					"User/api name invalid!!!");
#endif
		return DECLINED;
	}

	int (*fn) (request_rec *, page_data *);

	if ( (fn = APIGET(svr_cfg->api_call_table, APINAM(pg))) ) {

		if ((*fn) (r, pg)) {
			ap_set_content_type(r, "application/xml");
			ap_rputs(DATA(pg), r);
			return OK;
		} else {
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
						"API call for [%s] failed to get data !!!",
						APINAM(pg));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	} else {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
					"API entry for call: [%s] missing !!!",
					APINAM(pg));
		return HTTP_NOT_FOUND;
	}
}

/*
 * child init hook
 */
static void
flickr_child_init(apr_pool_t *pchild, server_rec *s)
{
	svr_cfg = apr_pcalloc(pchild, sizeof(svr_constants));

	svr_cfg->user_id 			= DUP(pchild, "user_id");
	svr_cfg->who				= DUP(pchild, "me"); 

	/* initialize the API call table. */
	svr_cfg->api_call_table = apr_hash_make(pchild);

#ifdef WITH_CACHING
	user_cred *uc = ap_get_module_config(s->module_config,
											&mod_flickr);

	char *host, *port;
	int i = 0,
		nelts = (uc->memc_svr)->nelts,
		elt_size = (uc->memc_svr)->elt_size;

	memcached_return rc;

	for (; i < nelts; i++) {
		host = *((char **)((uc->memc_svr)->elts + (i * elt_size)));

		if ( (port = ap_strchr(host, ':')) ) {
			*port = '\0';
			port++;
		}

		if (!i) {
			svr_cfg->servers = memcached_server_list_append(NULL,
												host,
												(port ? atoi(port) : 11211),
												&rc);

			continue;
		}

		svr_cfg->servers = memcached_server_list_append(svr_cfg->servers,
												host,
												(port ? atoi(port) : 11211),
												&rc);
	}
	
	svr_cfg->memc = memcached_create(NULL);
	rc = memcached_server_push(svr_cfg->memc, svr_cfg->servers);

#if APR_HAS_THREADS
	apr_status_t rv;

	rv = apr_thread_mutex_create(&svr_cfg->mutex, APR_THREAD_MUTEX_DEFAULT,
													pchild);

	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
					"mod_flickr: Unable to create mutex !!!");
	}
#endif

	apr_pool_cleanup_register(pchild, svr_cfg->servers,
									  (void *)memcached_server_free,
									  apr_pool_cleanup_null);
	apr_pool_cleanup_register(pchild, svr_cfg->memc,
									  (void *)memcached_free,
									  apr_pool_cleanup_null);

#endif

	/* API call entries. */
	{
		APIENTRY("getMyPhotos", 	flickr_get_my_photos);
		APIENTRY("getMySets",		flickr_get_my_sets);
		APIENTRY("getRecentPhotos", flickr_get_recent_photos);
		APIENTRY("getPhotosInSet",	flickr_get_photos_in_set);
		APIENTRY("getPhotoComment",	flickr_get_comment_for_photo);
	}
}

static void
register_hooks(apr_pool_t *p)
{
	ap_hook_handler(flickr_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(flickr_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA mod_flickr = {
	STANDARD20_MODULE_STUFF,
	NULL,						/* per dir. config		    */
	NULL,						/* merge per dir. config    */
	create_per_server_config,   /* per server config		*/
	NULL,						/* merge per server config	*/
	module_cmds,				/* module's commands table	*/
	register_hooks				/* module's hook table		*/
};



