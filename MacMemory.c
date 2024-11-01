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

    thread_act_t Thread = Threads[1];

    SuspendProcessThread(Thread);

    arm_thread_state64_t State;
    GetThreadState64(Thread, &State);

    uint64_t OriginalPc = State.__pc;

    unsigned char ShellCode[] = {
        0x50, 0x00, 0x00, 0x58,         // ldr x16, [pc, #8]
        0x00, 0x02, 0x1f, 0xd6,         // br x16
        (OriginalPc >> 0) & 0xFF,       // address byte 1
        (OriginalPc >> 8) & 0xFF,       // address byte 2
        (OriginalPc >> 16) & 0xFF,      // address byte 3
        (OriginalPc >> 24) & 0xFF,      // address byte 4
        (OriginalPc >> 32) & 0xFF,      // address byte 5
        (OriginalPc >> 40) & 0xFF,      // address byte 6
        (OriginalPc >> 48) & 0xFF,      // address byte 7
        (OriginalPc >> 56) & 0xFF       // address byte 8
    };

    mach_vm_address_t Address;
    AllocateRemoteMemory(Task, &Address, sizeof(ShellCode));

    WriteProcessMemory(Task, Address, ShellCode, sizeof(ShellCode));
    
    vm_prot_t OldProtection;
    GetMemoryProtection64(Task, Address, &OldProtection);

    printf("Old protection: %d\n", OldProtection);

    vm_prot_t NewProtection = VM_PROT_READ | VM_PROT_EXECUTE;
    SetMemoryProtection(Task, Address, sizeof(ShellCode), NewProtection);

    printf("New protection: %d\n", NewProtection);

    printf("__pc: 0x%llx\n", State.__pc);
    State.__pc = Address;

    SetThreadState(Thread, ARM_THREAD_STATE64, (thread_act_t* )&State, ARM_THREAD_STATE64_COUNT);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);
    
    ResumeProcessThread(Thread);
    
    FreeProcessInformation64(&Pi);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    usleep(100000); 

    SuspendProcessThread(Thread);

    GetThreadState64(Thread, &State);

    printf("__pc: 0x%llx\n", State.__pc);

    ResumeProcessThread(Thread);

    return 0;
}