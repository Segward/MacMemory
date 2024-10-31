#include "Routine.h"

int main() {
    pid_t Pid;
    GetPidByName("RobloxPlayer", &Pid);

    task_t Task;
    GetTaskForPid(Pid, &Task);

    ProcessInformation Pi;
    GetProcessInformation(Task, &Pi);

    cpu_type_t CpuType;
    GetProcessArchitecture(Task, &CpuType);

    if (CpuType == CPU_TYPE_ARM) {
        printf("ARM architecture\n");
    } else if (CpuType == CPU_TYPE_ARM64) {
        printf("ARM64 architecture\n");
    }

    thread_act_array_t Threads;
    mach_msg_type_number_t ThreadCount;
    GetProcessThreads(Task, &Threads, &ThreadCount);

    thread_act_t Thread = Threads[0];

    SuspendProcessThread(Thread);

    arm_thread_state64_t State;
    GetThreadState64(Thread, &State);

    printf("X0: 0x%llx\n", State.__x[0]);
    State.__x[0] = 0x0;

    SetThreadState(Thread, ARM_THREAD_STATE64, (thread_act_t* )&State, ARM_THREAD_STATE64_COUNT);

    GetThreadState64(Thread, &State);

    printf("X0: 0x%llx\n", State.__x[0]);
    
    ResumeProcessThread(Thread);
    
    FreeProcessInformation(&Pi);

    return 0;
}