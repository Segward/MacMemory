#include "Routine.h"

int main() {

    pid_t Pid;
    GetPidByName("Finder", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    ProcessInformation Pi;
    GetProcessInformation(Task, &Pi);

    printf("Regions: %zu\n", Pi.RegionCount);

    printf("Unprotected: %zu\n", Pi.UnprotectedCount);

    printf("Base Address: %p\n", (void*)Pi.BaseAddress.Address);

    return 0;
}