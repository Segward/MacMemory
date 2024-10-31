#include "Routine.h"

int main() {

    pid_t Pid;
    GetPidByName("Finder", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    ProcessInformation Pi;
    GetProcessInformation(Task, &Pi);

    printf("%zu\n", Pi.RegionCount);

    return 0;
}