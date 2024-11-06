#include "Routine.h"
#include <unistd.h>

int main() {
    pid_t Pid;
    GetPidByName("Calculator", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    ProcessInformation Pi;
    GetProcessInformation(Task, &Pi);

    MemoryPages Pages;
    GetMemoryPages(Task, &Pi, &Pages);

    EnumeratePageTableEntries(Task, &Pages);

    return 0;
}