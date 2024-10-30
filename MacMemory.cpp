#include <iostream>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <vector>
#include <cstring> // For memcmp

struct MemoryRegion {
    mach_vm_address_t Address;
    mach_vm_size_t Size;
};

pid_t GetPidByName(const char* ProcessName) {
    int Mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t Miblen = 4;

    pid_t Pid = -1;
    size_t Size;

    if (sysctl(Mib, Miblen, NULL, &Size, NULL, 0) == -1) {
        std::cerr << "Error: Could not get size of buffer " << std::endl;
        return -1;
    }

    std::vector<unsigned char> Buffer(Size);
    if (sysctl(Mib, Miblen, Buffer.data(), &Size, NULL, 0) == -1) {
        std::cerr << "Error: Could not allocate buffer " << std::endl;
        return -1;
    }

    struct kinfo_proc* Kprocs = reinterpret_cast<struct kinfo_proc*>(Buffer.data());
    int ProcessCount = Size / sizeof(struct kinfo_proc);

    for (int I = 0; I < ProcessCount ; ++I) {
        Pid = strcmp(Kprocs[I].kp_proc.p_comm, ProcessName) == 0 ? Kprocs[I].kp_proc.p_pid : -1;
        if (Pid != -1)
            break;
    }

    return Pid;
}

bool WriteProcessMemory(task_t Task, mach_vm_address_t Address, unsigned char* Buffer, size_t Size) {
    mach_vm_size_t DataCount = Size;
    kern_return_t Kr = mach_vm_write(Task, Address, 
        reinterpret_cast<vm_offset_t>(Buffer), Size);

    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        return false;
    }

    return true;
}

std::vector<unsigned char> ReadProcessMemory(task_t Task, mach_vm_address_t Address, size_t Size) {
    mach_vm_size_t DataCount = Size;
    std::vector<unsigned char> Buffer(Size);
    kern_return_t Kr = mach_vm_read_overwrite(Task, Address, Size, 
        reinterpret_cast<vm_address_t>(Buffer.data()), &DataCount);

    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        return std::vector<unsigned char>();
    }

    return Buffer;
}

std::vector<MemoryRegion> GetReadWriteRegions(task_t Task) {
    std::vector<MemoryRegion> Regions;
    mach_vm_address_t Address = 0;
    mach_vm_size_t Size = 0;
    vm_region_basic_info_data_64_t Info;
    mach_msg_type_number_t InfoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t ObjectName;

    while (true) {
        kern_return_t Kr = mach_vm_region(Task, &Address, &Size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&Info, &InfoCount, &ObjectName);
        if (Kr != KERN_SUCCESS) {
            break;
        }

        if ((Info.protection & VM_PROT_READ) && (Info.protection & VM_PROT_WRITE)) {
            MemoryRegion Region = { Address, Size };
            Regions.push_back(Region);
        }

        Address += Size;
    }

    return Regions;
}

std::vector<mach_vm_address_t> FindValueAddresses(task_t Task, const void* Value, size_t ValueSize,
        size_t BufferSize = 4096, std::vector<MemoryRegion> Regions = std::vector<MemoryRegion>()) {
    std::vector<mach_vm_address_t> FoundAddresses;
    for (size_t J = 0; J < Regions.size(); ++J) {
        mach_vm_address_t Address = Regions[J].Address;
        mach_vm_size_t RemainingSize = Regions[J].Size;

        while (RemainingSize > 0) {
            mach_vm_size_t ReadSize = (RemainingSize > BufferSize) ? BufferSize : RemainingSize;
            std::vector<unsigned char> Buffer = ReadProcessMemory(Task, Address, ReadSize);

            if (Buffer.empty()) {
                std::cerr << "Error: Could not read memory at address " << std::hex << Address << std::dec << std::endl;
                break;
            }

            for (size_t I = 0; I <= ReadSize - ValueSize; ++I) {
                if (memcmp(Buffer.data() + I, Value, ValueSize) == 0) {
                    FoundAddresses.push_back(Address + I);
                }
            }

            Address += ReadSize;
            RemainingSize -= ReadSize;
        }
    }

    return FoundAddresses;
}

mach_vm_address_t GetBaseAddress(task_t Task) {
    mach_vm_address_t Address = 0;
    mach_vm_size_t Size = 0;
    vm_region_basic_info_data_64_t Info;
    mach_msg_type_number_t InfoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t ObjectName;

    kern_return_t Kr = mach_vm_region(Task, &Address, &Size, 
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&Info, &InfoCount, &ObjectName);
    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        return -1;
    }

    return Address;
}

void* CompareValueAtAddress(task_t Task, mach_vm_address_t Address, size_t Size, const void* Value, size_t ValueSize) {
    std::vector<unsigned char> Buffer(ValueSize);
    mach_vm_size_t DataCount = ValueSize;
    kern_return_t Kr = mach_vm_read_overwrite(Task, Address, ValueSize, reinterpret_cast<vm_address_t>(Buffer.data()), &DataCount);

    if (Kr != KERN_SUCCESS) {
        std::cerr << "Error: " << mach_error_string(Kr) << std::endl;
        return nullptr;
    }

    void* FoundAddress = nullptr;
    if (memcmp(Buffer.data(), Value, ValueSize) == 0) {
        FoundAddress = reinterpret_cast<void*>(Address);
    }

    return FoundAddress;
}

void PrintBuffer(const std::vector<unsigned char>& Buffer) {
    for (size_t I = 0; I < Buffer.size(); ++I) {
        std::cout << std::hex << (int)Buffer[I] << " ";
    }
    std::cout << std::endl;
}

void PrintPointerVector(const std::vector<mach_vm_address_t>& Vector) {
    for (size_t I = 0; I < Vector.size(); ++I) {
        std::cout << std::hex << Vector[I] << std::dec << std::endl;
    }
}

int main() {
    const char* ProcessName = "Calculator";
    pid_t Pid = GetPidByName(ProcessName);

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

    std::vector<MemoryRegion> Regions = GetReadWriteRegions(Task);
    if (Regions.empty()) {
        std::cerr << "Error: Could not get memory regions" << std::endl;
        return -1;
    }


    size_t BufferSize = 4096;
    int ValueToSearch = 500;

    std::vector<mach_vm_address_t> FoundAddresses = FindValueAddresses(Task, 
        &ValueToSearch, sizeof(ValueToSearch), BufferSize, Regions);

    if (FoundAddresses.empty()) {
        std::cout << "Value not found" << std::endl;
        return -1;
    }

    std::cout << "Found " << FoundAddresses.size() << " addresses" << std::endl;

    return 0;
}