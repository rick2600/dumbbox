#include <stdint.h>

#define READ  0
#define WRITE 1

#define DUMBBOX_OPEN 1

#define FETCH_INT32(req, off) *(int32_t *)((void *)&((req).buffer)+(off))

typedef enum {STATUS_DENIED, STATUS_OK, STATUS_ERR} status_t;

typedef struct {
    enum {T_INT, T_STRING} type;
    uint32_t offset; 
    size_t size;   
} param_info_t;

typedef struct {
    uint32_t command;
    uint32_t params_count;
    param_info_t param0;
    param_info_t param1;
    param_info_t param2;
    char buffer[1024];    
} dumbbox_request_t;

typedef struct {
    status_t status;
    int32_t ret;
} dumbbox_response_t;

/*
typedef struct {
    int32_t request[2];
    int32_t response[2];
} channel_t;
*/

// setup functions
void dumbbox_enter(void);
void dumbbox_setup(void (*target)(void));
void dumbbox_broker(void);

// priv functions
int32_t dumbbox_priv_open(const char *pathname, int32_t flags);
void dumbbox_send_response(status_t status, int32_t ret);
int32_t dumbbox_sendfd(int32_t socket, int32_t fd);
void dumbbox_process_request(void);
int32_t dumbbox_is_safepath(const char *pathname);


// unpriv functions
int32_t dumbbox_unpriv_open(const char *pathname, int32_t flags);
void dumbbox_send_request_si(uint32_t command, const char *s0, int32_t i0);
ssize_t dumbbox_get_response(void);
int32_t dumbbox_recvfd(int32_t socket);
