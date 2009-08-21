#ifndef __FLICK_H
#define	__FLICK_H

/*
 * Constants for number of display and
 * number of photos to query Flickr.
 */
#define FLICKR_NR_DISPLAY_PHOTOS		10
#define FLICKR_NR_PHOTOS_PER_CALL		FLICKR_NR_DISPLAY_PHOTOS * 3


/* Flickr related URL format's. */
#define	FLICKR_AUTH_STRING				"http://api.flickr.com/services/rest/?api_key=%s&auth_token=%s&api_sig=%s&%s"
#define FLICKR_SIGNATURE_STRING			"%sapi_key%sauth_token%s%s"

/*
 * Flickr API calls.
 */
#define	FLICKR_PHOTOS_SEARCH			"flickr.photos.search"

typedef struct {
	int args_len;
	int nr_iterations;
} table_stat;

#define SIG2ARG(s) \
	s.args_len + (s.nr_iterations * 2) - 1

/*
 * For user credentials.
 * 0. Auth Token
 * 1. API Key
 * 2. Key Secret
 */
typedef struct {
	short on_off;
	apr_hash_t	*user;
} user_cred;

typedef struct {
	char *auth_token;
	char *api_key;
	char *secret;
} api_key_secret;

/*
 * following is used by the request
 * handler.
 */

typedef struct {
	char *api_response;		/* 'api_response' is not controlled by apache's */
	apr_size_t size;		/* MM pool. So we need to de-allocate it using	*/
} mem_chunk;				/* free()										*/


typedef struct {
	char *page;
	char *user;
	mem_chunk mem;			
	char *raw_args;
	char *raw_signature;
	int offset_t;
	int iterations;
	api_key_secret *creds;  
} page_data;


/* macros for accessing page data */
#define	SECRET(pg)	pg->creds->secret
#define	APIKEY(pg)	pg->creds->api_key
#define	AUTHTKN(pg)	pg->creds->auth_token
#define	RAWSIGN(pg)	pg->raw_signature
#define SIGOFFT(pg) RAWSIGN(pg) + pg->offset_t
#define RAWARGS(pg) pg->raw_args
#define ARGOFFT(pg)	RAWARGS(pg) + pg->offset_t

#endif



