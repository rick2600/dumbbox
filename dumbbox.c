#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include "dumbbox.h"

/* Credits to https://gist.github.com/nazgee/2396992 for fd passing code */


//channel_t channel;
int32_t channel_request[2];
int32_t channel_response[2];

dumbbox_request_t request;
dumbbox_response_t response;


void dumbbox_enter(void) {

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

    if (seccomp_load(ctx) < 0) {
        perror("enter_sandox");
        exit(EXIT_FAILURE);
    }
}


void dumbbox_setup(void (*target)(void)) {

    pid_t pid;
    
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, channel_request)) {
        perror("channel.request") ;
        exit(EXIT_FAILURE);
    }
    
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, channel_response)) {
        perror("channel.response") ;
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }    

    if (pid == 0) {
        close(channel_request[READ]);
        close(channel_response[WRITE]);
        dumbbox_enter();              
        //printf("CHILD\n");
        target();
    }
    else {
        close(channel_response[READ]);    
        close(channel_request[WRITE]);
        //printf("PARENT\n");
        dumbbox_broker();
    }
}

/* ============================== PRIVILEGED CODE ============================== */
void dumbbox_broker(void) {

    struct iovec iov;
    struct msghdr msg;
    ssize_t len;
    
    printf("Broker: running\n");
    
    iov.iov_base = &request;
    iov.iov_len = sizeof(request);

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = 0;
    msg.msg_controllen = 0;    

    while(1) {        
        len = recvmsg(channel_request[READ], &msg, 0);
        if (len > 0)
            dumbbox_process_request();    
    }    
}


void dumbbox_process_request(void) {

    int32_t i0;
    char *s0;
    
    switch (request.command) {
        case DUMBBOX_OPEN: {
            s0 = (char *)&request.buffer;
            i0 = FETCH_INT32(request, request.param[1].offset);
            dumbbox_priv_open(s0, i0);         
        }
        break;
    }
}


int32_t dumbbox_priv_open(const char *pathname, int32_t flags) {
    
    int32_t fd;    

    if (!dumbbox_is_safepath(pathname)) {
        printf("Broker: access denied to '%s'!\n", pathname);
        dumbbox_send_response(STATUS_DENIED, -1);
        return -1;
    }

    fd = open(pathname, flags);
    if (fd < 0) {
        dumbbox_send_response(STATUS_ERR, fd);
        return -1;
    } 
    else {
        dumbbox_send_response(STATUS_OK, fd);
        dumbbox_sendfd(channel_response[WRITE], fd);
        close(fd);
    }
    return fd;
}


int32_t dumbbox_is_safepath(const char *pathname) {
    
    if (strlen(pathname) <= 5) // len('/tmp/') = 5
        return 0;

    if (strstr(pathname, ".."))
       return 0;

    if (strstr(pathname, "/tmp/") != pathname)
       return 0;   

    return 1;     
}


void dumbbox_send_response(status_t status, int32_t ret) {

    struct msghdr msg;
    struct iovec iov;

    memset(&response, 0, sizeof(response));
    response.status = status;
    response.ret = ret;
    
    iov.iov_base = &response;
    iov.iov_len = sizeof(response);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = 0;
    msg.msg_controllen = 0;

    ret = sendmsg(channel_response[WRITE], &msg, 0);
    if (ret == -1) {
        perror("sendmsg");
        exit(EXIT_FAILURE);
    }
}


int32_t dumbbox_sendfd(int32_t socket, int32_t fd) {

    int32_t ret;
    char dummy = '$';
    char cmsgbuf[CMSG_SPACE(sizeof(int32_t))];    
    struct msghdr msg;
    struct iovec iov;

    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = CMSG_LEN(sizeof(int32_t));

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int32_t));

    *(int32_t*) CMSG_DATA(cmsg) = fd;

    ret = sendmsg(socket, &msg, 0);

    if (ret == -1) {
        perror("sendmsg");
    }

    return ret;
}

/* ============================== UNPRIVILEGED CODE ============================== */
int32_t dumbbox_unpriv_open(const char *pathname, int32_t flags) {

    int32_t ret;

    dumbbox_send_request_si(DUMBBOX_OPEN, pathname, flags);
    ret = dumbbox_get_response();
    
    if (ret != -1) {
        if (response.status == STATUS_OK)
            ret = dumbbox_recvfd(channel_response[READ]);
        else if (response.status == STATUS_ERR)
            ret = response.ret;
    }
    return ret;

}


void dumbbox_write_string(const char *value) {

    uint32_t params_count = request.params_count;
    char *s = ((char *)request.buffer) + request.next_offset;

    request.param[params_count].type = T_STRING;
    request.param[params_count].offset = request.next_offset;
    request.param[params_count].size = strlen(value) + 1;
    strcpy(s, value);
    
    request.next_offset += request.param[params_count].size;
    request.params_count++;
}


void dumbbox_write_int(int32_t value) {

    uint32_t params_count = request.params_count;

    request.param[params_count].type = T_INT;
    request.param[params_count].offset = request.next_offset;
    request.param[params_count].size = sizeof(int32_t);
    *((int32_t *)(((void *)&request.buffer)+request.next_offset)) = value;

    request.next_offset += request.param[params_count].size;
    request.params_count++;  
}


void dumbbox_send_request_si(uint32_t command, const char *s, int32_t i) {

    struct msghdr msg;
    struct iovec iov;
    int32_t ret;

    iov.iov_base = &request;
    iov.iov_len = sizeof(request);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = 0;
    msg.msg_controllen = 0;    

    memset(&request, 0, sizeof(request));
    request.command = command;
    dumbbox_write_string(s);
    dumbbox_write_int(i);

    ret = sendmsg(channel_request[WRITE], &msg, 0);
    if (ret == -1) {
        perror("sendmsg");
        exit(EXIT_FAILURE);
    }
}


ssize_t dumbbox_get_response(void) {

    struct iovec iov;
    struct msghdr msg;
    ssize_t len;
        
    iov.iov_base = &response;
    iov.iov_len = sizeof(response);

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = 0;
    msg.msg_controllen = 0;    
     
    len = recvmsg(channel_response[READ], &msg, 0);

    if (len < 0) {
        perror("recvmsg failed with");
        return -1;
    }

    if (len == 0) {
        fprintf(stderr, "recvmsg failed no data");
        return -1;
    }
    return len;
}


int32_t dumbbox_recvfd(int32_t socket) {

    ssize_t len;
    int32_t fd;
    char buf[1];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char cms[CMSG_SPACE(sizeof(int32_t))];

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = (caddr_t) cms;
    msg.msg_controllen = sizeof cms;

    len = recvmsg(socket, &msg, 0);

    if (len < 0) {
        perror("recvmsg failed with");
        return -1;
    }

    if (len == 0) {
        fprintf(stderr, "recvmsg failed no data");
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    memmove(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}
