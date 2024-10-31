#include "Routine.h"
#include <unistd.h>

int main() {

    pid_t Pid;
    GetPidByName("Calculator", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    ProcessInformation Pi;
    GetProcessInformation(Task, &Pi);

    printf("Regions: %zu\n", Pi.RegionCount);
    printf("Unprotected: %zu\n", Pi.UnprotectedCount);
    printf("Base Address: %p\n", (void*)Pi.BaseAddress.Address);

    thread_act_array_t Threads;
    mach_msg_type_number_t ThreadCount;
    GetProcessThreads(Task, &Threads, &ThreadCount);

    printf("Threads: %d\n", ThreadCount);

    thread_act_t MainThread = Threads[0];
    SuspendProcessThread(MainThread);
    
    printf("Thread %u Suspended\n", MainThread);

    usleep(1000000);
    ResumeProcessThread(MainThread);

    printf("Thread %u Resumed\n", MainThread);

    FreeProcessInformation(&Pi);
    FreeThreadArray(&Threads, ThreadCount);

    return 0;
}