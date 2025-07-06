#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef struct proxy_conn
{
	struct bufferevent *client_bev;
	struct bufferevent *server_bev;
	struct evbuffer *request_buffer;
	char host[256];
	int port;
	int connected;
	int ssl;
} proxy_conn_t;

// 에러 및 종료 처리
void close_connection(proxy_conn_t *conn)
{
	if (conn->client_bev)
		bufferevent_free(conn->client_bev);
	if (conn->server_bev)
		bufferevent_free(conn->server_bev);
	if (conn->request_buffer)
		evbuffer_free(conn->request_buffer);

	free(conn);
}

// 서버 → 클라이언트 데이터 중계
void server_read_cb(struct bufferevent *bev, void *ctx)
{
	proxy_conn_t *conn = ctx;
	evbuffer_add_buffer(bufferevent_get_output(conn->client_bev),
						bufferevent_get_input(bev));
}

void event_cb(struct bufferevent *bev, short events, void *ctx)
{
	(void)bev;
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
	{
		close_connection((proxy_conn_t *)ctx);
	}
}

// DNS + 서버 연결 시도
void connect_to_server(proxy_conn_t *conn, const char *hostname, int port)
{
	struct addrinfo hints, *res;
	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(hostname, port_str, &hints, &res) != 0)
	{
		fprintf(stderr, "DNS lookup failed for host: %s\n", hostname);
		close_connection(conn);
		return;
	}

	conn->server_bev = bufferevent_socket_new(bufferevent_get_base(conn->client_bev), -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(conn->server_bev, server_read_cb, NULL, event_cb, conn);
	bufferevent_enable(conn->server_bev, EV_READ | EV_WRITE);
	bufferevent_socket_connect(conn->server_bev, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	// 서버와 연결 완료되면 지금까지 받은 요청을 전달
	bufferevent_write_buffer(conn->server_bev, conn->request_buffer);
	evbuffer_drain(conn->request_buffer, evbuffer_get_length(conn->request_buffer));
	conn->connected = 1;
}

// 클라이언트 → 서버 데이터 처리
void client_read_cb(struct bufferevent *bev, void *ctx)
{
	proxy_conn_t *conn = ctx;
	struct evbuffer *input = bufferevent_get_input(bev);

	if (!conn->connected)
	{
		evbuffer_add_buffer(conn->request_buffer, input);
		size_t len = evbuffer_get_length(conn->request_buffer);
		unsigned char *data = evbuffer_pullup(conn->request_buffer, len);
		char *header_end = strstr((char *)data, "\r\n\r\n");
		if (!header_end)
			return;

		// 메소드 파싱
		char method[8];
		sscanf((char *)data, "%7s", method);

		// CONNECT 처리
		if (strcmp(method, "CONNECT") == 0)
		{
			sscanf((char *)data, "CONNECT %255[^:]%*[:]%d", conn->host, &conn->port);
			if (conn->port == 0)
				conn->port = 443;

			printf("[HTTPS] %s:%d\n", conn->host, conn->port);

			// 서버와 연결
			struct addrinfo hints, *res;
			char port_str[6];
			snprintf(port_str, sizeof(port_str), "%d", conn->port);

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;

			if (getaddrinfo(conn->host, port_str, &hints, &res) != 0)
			{
				fprintf(stderr, "DNS failed\n");
				close_connection(conn);
				return;
			}

			conn->server_bev = bufferevent_socket_new(bufferevent_get_base(bev), -1, BEV_OPT_CLOSE_ON_FREE);
			bufferevent_setcb(conn->server_bev, server_read_cb, NULL, event_cb, conn);
			bufferevent_enable(conn->server_bev, EV_READ | EV_WRITE);

			if (bufferevent_socket_connect(conn->server_bev, res->ai_addr, res->ai_addrlen) < 0)
			{
				fprintf(stderr, "Connection to server failed\n");
				freeaddrinfo(res);
				close_connection(conn);
				return;
			}

			freeaddrinfo(res);
			conn->connected = 1;
			conn->ssl = 1;

			// 클라이언트에 200 응답 보내고, 이제부터는 raw 터널링 시작
			bufferevent_write(conn->client_bev, "HTTP/1.1 200 Connection established\r\n\r\n", 39);
			evbuffer_drain(conn->request_buffer, len);
		}
		else
		{

			// Host 헤더 파싱
			char *host_header = strstr((char *)data, "Host:");
			if (!host_header)
			{
				fprintf(stderr, "No Host header found\n");
				close_connection(conn);
				return;
			}
			host_header += 5; // skip "Host:"
			while (*host_header == ' ')
				host_header++;

			sscanf(host_header, "%255s", conn->host);

			// 포트 포함되었는지 확인
			char *colon = strchr(conn->host, ':');
			if (colon)
			{
				*colon = '\0';
				conn->port = atoi(colon + 1);
			}
			else
			{
				conn->port = 80;
			}

			printf("[HTTP ] %s:%d\n", conn->host, conn->port);

			connect_to_server(conn, conn->host, conn->port);
		}
	}
	else
	{
		// 이미 연결되었으면 중계
		evbuffer_add_buffer(bufferevent_get_output(conn->server_bev), input);
	}
}

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *addr, int socklen, void *ctx)
{
	(void)listener;
	(void)addr;
	(void)socklen;
	struct event_base *base = ctx;

	proxy_conn_t *conn = calloc(1, sizeof(proxy_conn_t));
	conn->client_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	conn->request_buffer = evbuffer_new();
	conn->connected = 0;

	bufferevent_setcb(conn->client_bev, client_read_cb, NULL, event_cb, conn);
	bufferevent_enable(conn->client_bev, EV_READ | EV_WRITE);
}

int main(int argc, char **argv)
{
	struct event_base *base;
	struct evconnlistener *listener;
	struct sockaddr_in sin;
	int LISTEN_PORT = 8888;

	if (argc > 1)
	{
		LISTEN_PORT = atoi(argv[1]);
		if (LISTEN_PORT <= 0 || LISTEN_PORT > 65535)
		{
			fprintf(stderr, "Invalid port number: %s\n", argv[1]);
			return 1;
		}
	}

	base = event_base_new();

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(LISTEN_PORT);

	listener = evconnlistener_new_bind(base, accept_cb, base,
									   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
									   (struct sockaddr *)&sin, sizeof(sin));

	printf("HTTP proxy listening on port %d...\n", LISTEN_PORT);
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);
	return 0;
}
