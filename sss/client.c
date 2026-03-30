

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "common.h"

static void send_msg(int fd, const Message *m) {
    if (write(fd, m, sizeof *m) != sizeof *m) {
        perror("[Client] write");
        exit(1);
    }
}

static void recv_msg(int fd, Message *m) {
    if (read(fd, m, sizeof *m) != sizeof *m) {
        perror("[Client] read");
        exit(1);
    }
}



int main(void) {
    puts("Shamir's Secret Sharing (CLIENT)\n");

   
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof addr.sun_path - 1);

    printf("[Client] Connecting to server at %s …\n", SOCKET_PATH);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("[Client] connect — is the server running?");
        exit(1);
    }
    puts("[Client] Connected!\n");

   
    Message msg;
    recv_msg(fd, &msg);

    if (msg.type != MSG_SHARE) {
        fprintf(stderr, "[Client] Unexpected message type %d\n", msg.type);
        exit(1);
    }

    int my_id = msg.client_id;
    int my_x  = msg.x;
    int my_y  = msg.y;

    printf("[Client %d] Received share: x = %d,  y = %d\n\n", my_id, my_x, my_y);
    printf("[Client %d] Waiting for server to request the share…\n", my_id);

   
    recv_msg(fd, &msg);

    if (msg.type == MSG_SHARE_REQUEST) {
        printf("[Client %d] Server requested my share — sending (%d, %d)…\n",
               my_id, my_x, my_y);

        Message reply = {
            .type      = MSG_SHARE_REPLY,
            .client_id = my_id,
            .x         = my_x,
            .y         = my_y,
        };
        send_msg(fd, &reply);

       
        recv_msg(fd, &msg);
    }
   

    if (msg.type == MSG_RESULT) {
        printf("\n[Client %d] ══ Server recovered secret = %d ══\n",
               my_id, msg.secret);
    }

    close(fd);
    return 0;
}