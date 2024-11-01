#include "Routine.h"
#include <unistd.h>

int main() {
    pid_t Pid;
    GetPidByName("RobloxPlayer", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    ProcessInformation64 Pi;
    GetProcessInformation64(Task, &Pi);

    thread_act_array_t Threads;
    mach_msg_type_number_t ThreadCount;
    GetProcessThreads(Task, &Threads, &ThreadCount);

    printf("Thread count: %d\n", ThreadCount);

    thread_act_t Thread = Threads[0];

    SuspendProcessThread(Thread);

    arm_thread_state64_t State;
    GetThreadState64(Thread, &State);

    printf("X0: 0x%llx\n", State.__x[0]);
    printf("X1: 0x%llx\n", State.__x[1]);
    printf("X2: 0x%llx\n", State.__x[2]);
    printf("X3: 0x%llx\n", State.__x[3]);

    State.__x[0] = 0x0;
    State.__x[1] = 0x1;
    State.__x[2] = 0x2;
    State.__x[3] = 0x3;

    SetThreadState(Thread, ARM_THREAD_STATE64, (thread_act_t* )&State, ARM_THREAD_STATE64_COUNT);

    ResumeProcessThread(Thread);

    usleep(50000);

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("X0: 0x%llx\n", State.__x[0]);
    printf("X1: 0x%llx\n", State.__x[1]);
    printf("X2: 0x%llx\n", State.__x[2]);
    printf("X3: 0x%llx\n", State.__x[3]);

    ResumeProcessThread(Thread);

    usleep(1000000);

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("X0: 0x%llx\n", State.__x[0]);
    printf("X1: 0x%llx\n", State.__x[1]);
    printf("X2: 0x%llx\n", State.__x[2]);
    printf("X3: 0x%llx\n", State.__x[3]);

    ResumeProcessThread(Thread);

    FreeProcessInformation64(&Pi);

    return 0;
}