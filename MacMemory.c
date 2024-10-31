#include "Routine.h"

int main() {

    pid_t Pid;
    GetPidByName("Finder", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    MemoryProcessInformation Mpi;
    GetMemoryProcessInformation(Task, &Mpi);

    printf("%zu\n", Mpi.RegionCount);

    return 0;
}