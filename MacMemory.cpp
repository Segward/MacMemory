#include <iostream>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

pid_t GetPidByName(const char* ProcessName) {
    int Mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t Miblen = 4;

    pid_t Pid = -1;
    size_t Size;

    if (sysctl(Mib, Miblen, NULL, &Size, NULL, 0) == -1) {
        std::cerr << "Error: Could not get size of buffer " << std::endl;
        return -1;
    }

    unsigned char* Buffer = new unsigned char[Size];
    if (sysctl(Mib, Miblen, Buffer, &Size, NULL, 0) == -1) {
        std::cerr << "Error: Could not allocate buffer " << std::endl;
        return -1;
    }

    struct kinfo_proc* Kprocs = reinterpret_cast<struct kinfo_proc*>(Buffer.data());
    int ProcessCount = Size / sizeof(struct kinfo_proc);

    for (int i = 0; i < ProcessCount ; ++i) {
        Pid = strcmp(Kprocs[i].kp_proc.p_comm, ProcessName) == 0 ? Kprocs[i].kp_proc.p_pid : -1;
        if (Pid != -1)
            break;
    }

    delete[] Buffer;

    return Pid;
}

mach_vm_address_t GetBaseAddress(task_t Task) {
    mach_vm_address_t Address = 0;
    mach_vm_size_t Size = 0;
    vm_region_basic_info_data_64_t Info;
    mach_msg_type_number_t InfoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t ObjectName;

    kern_return_t Kr = mach_vm_region(Task, &Address, &Size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&Info, &InfoCount, &ObjectName);
    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        return -1;
    }

    return Address;
}

void ReadProcessMemory(task_t Task, mach_vm_address_t Address, size_t Size) {
    mach_vm_size_t DataCount = Size;
    unsigned char* Buffer = new unsigned char[Size];
    kern_return_t Kr = mach_vm_read_overwrite(Task, Address, Size, Buffer, &DataCount);

    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        delete[] Buffer;
        return;
    }

    for (size_t i = 0; i < DataCount; ++i) {
        std::cout << std::hex << (int)Buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;

    delete[] Buffer;
}

int main() {
    const char* ProcessName = "Calculator";
    pid_t Pid = GetPidByName(ProcessName);

    if (Pid == -1) {
        std::cerr << "Error: Process not found" << std::endl;
        return -1;
    }

    if (Pid == -1) {
        std::cerr << "Error: Process not found" << std::endl;
        return -1;
    }

    task_t Task;
    kern_return_t Kr = task_for_pid(mach_task_self(), Pid, &Task);

    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        return -1;
    }

    mach_vm_address_t BaseAddress = GetBaseAddress(Task);
    if (BaseAddress == 0) {
        std::cerr << "Error: Could not get base address" << std::endl;
        return -1;
    }

    size_t Size = 4096; 
    ReadProcessMemory(Task, BaseAddress, Size);

    return 0;
}