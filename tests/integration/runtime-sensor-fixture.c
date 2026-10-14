/* Owned synthetic process only; no credential material or remote traffic. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int file = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (file < 0) return 3;
    char bytes[16];
    if (read(file, bytes, sizeof(bytes)) <= 0) {close(file); return 4;}
    close(file);
    long port = strtol(argv[2], NULL, 10);
    if (port <= 0 || port > 65535) return 5;
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0) return 6;
    struct sockaddr_in target = {0};
    target.sin_family = AF_INET;
    target.sin_port = htons((unsigned short)port);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(client, (struct sockaddr *)&target, sizeof(target)) != 0) {close(client); return 7;}
    close(client);
    return 0;
}
