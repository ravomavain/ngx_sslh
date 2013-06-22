#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

struct ngx_http_sslh_srv_conf_s {
	ngx_str_t socket;
};

typedef struct ngx_http_sslh_srv_conf_s ngx_http_sslh_srv_conf_t;

static ngx_int_t ngx_http_sslh_add_variable(ngx_conf_t *cf);
static ngx_int_t ngx_http_variable_sslh_remote_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static void* ngx_http_sslh_create_srv_conf(ngx_conf_t *cf);
static char* ngx_http_sslh_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_sslh_commands[] = {
	{ ngx_string("sslh_socket"),
	  NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_sslh_srv_conf_t, socket),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_sslh_module_ctx = {
	ngx_http_sslh_add_variable,          /* preconfiguration */
	NULL,                                /* postconfiguration */

	NULL,                                /* create main configuration */
	NULL,                                /* init main configuration */

	ngx_http_sslh_create_srv_conf,       /* create server configuration */
	ngx_http_sslh_merge_srv_conf,        /* merge server configuration */

	NULL,                                /* create location configuration */
	NULL,                                /* merge location configuration */
};

ngx_module_t ngx_http_sslh_module = {
	NGX_MODULE_V1,
	&ngx_http_sslh_module_ctx,          /* module context */
	ngx_http_sslh_commands,             /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t  ngx_http_sslh_vars[] = {
	{ ngx_string("sslh_remote_addr"), NULL,
	  ngx_http_variable_sslh_remote_addr,
	  0, 0, 0 },
	
	{ ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_http_sslh_add_variable(ngx_conf_t *cf) {
	ngx_http_variable_t  *var, *v;

	for (v = ngx_http_sslh_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}

static void* ngx_http_sslh_create_srv_conf(ngx_conf_t *cf) {
	ngx_http_sslh_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sslh_srv_conf_t));

	return conf;
}

static char* ngx_http_sslh_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_sslh_srv_conf_t *prev = parent;
	ngx_http_sslh_srv_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->socket, prev->socket, NULL);

	return NGX_CONF_OK;
}


static uint32_t ngx_http_sslh_port_to_ip(uint16_t port, ngx_str_t sock) {
	int s, len;
	uint32_t ip;

	struct sockaddr_un remote;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return 0;
	}

	remote.sun_family = AF_UNIX;
	ngx_memcpy(remote.sun_path, sock.data, sock.len);
	len = sock.len + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		return 0;
	}

	if (write(s, &port, sizeof port) == -1) {
		return 0;
	}

	if (read(s, &ip, sizeof ip) <= 0)
		return 0;

	close(s);
	
	return ip;
}

static ngx_int_t ngx_http_variable_sslh_remote_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_addr_t                 addr;
	struct sockaddr_in        *sin;
	struct in_addr             ip;
	uint16_t                   port;
	char                       val[INET_ADDRSTRLEN];
	size_t                     len;
	ngx_http_sslh_srv_conf_t  *cfg;

	cfg = ngx_http_get_module_srv_conf(r, ngx_http_sslh_module);

	addr.sockaddr = r->connection->sockaddr;
	addr.socklen = r->connection->socklen;

	if (addr.sockaddr->sa_family != AF_INET) {
		v->len = r->connection->addr_text.len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = r->connection->addr_text.data;
		return NGX_OK;
	}

	sin = (struct sockaddr_in *) addr.sockaddr;

	port = sin->sin_port;

	ip.s_addr =  ngx_http_sslh_port_to_ip(port, cfg->socket);

	if (ip.s_addr == 0)
	{
		v->len = r->connection->addr_text.len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = r->connection->addr_text.data;
		return NGX_OK;
	}

	inet_ntop(AF_INET, &ip, val, INET_ADDRSTRLEN);
	len = ngx_strlen(val);

	v->data = ngx_pnalloc(r->pool, len);
	if (v->data == NULL) {
		v->len = r->connection->addr_text.len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = r->connection->addr_text.data;
		return NGX_OK;
	}

	ngx_memcpy(v->data, val, len);

	v->len = len;
	v->valid = 1;
	v->no_cacheable = 1;
	v->not_found = 0;

	return NGX_OK;
}

