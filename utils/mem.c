#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <string.h>

int main(int argc, char** argv){
  if(!strcmp(argv[1], "0"))
    syscall(__NR_mmap, 0x2f005000, 0x1000, 3, 0x32, -1, 0);
  if(!strcmp(argv[1], "1"))
    syscall(__NR_mmap, 0x2f004000, 0x1000, 3, 0x32, -1, 0);

  return 0;
}
