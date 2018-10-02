#include <stdio.h>

int main(){
  system("~/input/field2 trace aa > /dev/null 2> /dev/null");
  system("cat field.out");

  return 0;
}
