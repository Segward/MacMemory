#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach-o/dyld_images.h>

void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Error: malloc failed for size %zu\n", size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Error: realloc failed for size %zu\n", size);
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

typedef struct {
    mach_vm_address_t Address;                                          // start address of memory region
    mach_vm_size_t Size;                                                // size of memory region
    vm_region_basic_info_data_64_t Rbi;                                 // basic information about memory region
    mach_msg_type_number_t InfoCount;                                   // number of information
    mach_port_t ObjectName;                                             // object name
} MemoryRegion;

typedef struct {
    MemoryRegion* Regions;                                              // memory regions
    size_t RegionCount;                                                 // number of memory regions
    MemoryRegion* Unprotected;                                          // unprotected memory regions 
    size_t UnprotectedCount;                                            // number of unprotected memory regions
    MemoryRegion BaseAddress;                                           // base address of memory region
} ProcessInformation;

typedef struct {
    uint64_t Present : 1;                                               // Page present in memory
    uint64_t ReadWrite : 1;                                             // Read/write permission
    uint64_t UserSupervisor : 1;                                        // User/supervisor mode
    uint64_t PageWriteThrough : 1;                                      // Page-level write-through
    uint64_t PageCacheDisable : 1;                                      // Page-level cache disable
    uint64_t Accessed : 1;                                              // Accessed (set by CPU)
    uint64_t Dirty : 1;                                                 // Dirty (set by CPU)
    uint64_t PageSize : 1;                                              // Page size (0 = 4KB, 1 = 2MB/4MB)
    uint64_t Global : 1;                                                // Global page (not flushed by CR3)
    uint64_t Available : 3;                                             // Available for system programmer use
    uint64_t PageFrameNumber : 40;                                      // Page frame number (physical address)
    uint64_t Reserved : 11;                                             // Reserved bits
    uint64_t NoExecute : 1;                                             // No-execute bit
} PageTableEntry;

typedef struct {
    mach_vm_address_t Address;                                          // start address of page
    mach_vm_size_t Size;                                                // size of page
    mach_msg_type_number_t DataCount;                                   // number of data or entries
    vm_offset_t Data;                                                   // data
} RegionPage;

typedef struct {
    RegionPage* Pages;                                                  // pages
    size_t PageCount;                                                   // number of pages
} MemoryPages;

void FreeProcessInformation(ProcessInformation* Pi) {
    free(Pi->Regions);
    Pi->Regions = NULL;
    Pi->RegionCount = 0;
    free(Pi->Unprotected);
    Pi->Unprotected = NULL;
    Pi->UnprotectedCount = 0;
}

void EnumeratePids() {
    int Mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };             // sysctl parameters for getting process information
    size_t Miblen = 4;                                                  // number of parameters
    size_t Size;

    if (sysctl(Mib, Miblen, NULL, &Size, NULL, 0) == -1) {              // get size of buffer required to store process information
        printf("Error: Could not get size of buffer\n");
        exit(EXIT_FAILURE);
    }
    
    unsigned char* Buffer = (unsigned char*)malloc(Size);               // allocate buffer to store process information
    if (sysctl(Mib, Miblen, Buffer, &Size, NULL, 0) == -1) {            // get process information
        printf("Error: Could not allocate buffer\n");
        free(Buffer);
        exit(EXIT_FAILURE);
    }

    struct kinfo_proc* Kprocs = (struct kinfo_proc*)Buffer;             // cast buffer to process information
    int ProcessCount = Size / sizeof(struct kinfo_proc);

    for (int I = 0; I < ProcessCount; ++I) {
        printf("pid: %d, name: %s\n", Kprocs[I].kp_proc.p_pid, Kprocs[I].kp_proc.p_comm);
    }

    free(Buffer);
}

void GetPidByName(const char* ProcessName, pid_t* Pid) {
    int Mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };             // sysctl parameters for getting process information
    size_t Miblen = 4;                                                  // number of parameters
    size_t Size;

    if (sysctl(Mib, Miblen, NULL, &Size, NULL, 0) == -1) {              // get size of buffer required to store process information
        printf("Error: Could not get size of buffer\n");
        exit(EXIT_FAILURE);
    }
    
    unsigned char* Buffer = (unsigned char*)malloc(Size);               // allocate buffer to store process information
    if (sysctl(Mib, Miblen, Buffer, &Size, NULL, 0) == -1) {            // get process information
        printf("Error: Could not allocate buffer\n");
        free(Buffer);
        exit(EXIT_FAILURE);
    }

    struct kinfo_proc* Kprocs = (struct kinfo_proc*)Buffer;             // cast buffer to process information
    int ProcessCount = Size / sizeof(struct kinfo_proc);

    for (int I = 0; I < ProcessCount; ++I) {
        *Pid = strcmp(Kprocs[I].kp_proc.p_comm, ProcessName) == 0 
            ? Kprocs[I].kp_proc.p_pid : -1;

        if (*Pid != -1)
            break;
    }

    free(Buffer);
}

void GetTaskForPid(pid_t Pid, task_t* Task) {
    if (Pid == -1) {
        printf("Error: Invalid pid\n");
        exit(EXIT_FAILURE);
    }

    if (task_for_pid(mach_task_self(), Pid, Task) != KERN_SUCCESS) {
        printf("Error: Could not get task for pid\n");
        *Task = MACH_PORT_NULL;
    }
}

void GetProcessInformation(task_t Task, ProcessInformation* Pi) {
    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    Pi->RegionCount = 0;
    Pi->Regions = NULL;
    
    MemoryRegion BaseRegion;
    BaseRegion.Address = 0;
    BaseRegion.Size = 0;
    BaseRegion.InfoCount = VM_REGION_BASIC_INFO_COUNT_64;

    while (true) {
        kern_return_t Kr = mach_vm_region( 
            Task, 
            &BaseRegion.Address, 
            &BaseRegion.Size, 
            VM_REGION_BASIC_INFO_64, 
            (vm_region_info_t)&BaseRegion.Rbi, 
            &BaseRegion.InfoCount, 
            &BaseRegion.ObjectName);

        if (Kr != KERN_SUCCESS) {
            break;
        }

        MemoryRegion* NewRegion = (MemoryRegion*)safe_realloc(
            Pi->Regions,
            (Pi->RegionCount + 1) * sizeof(MemoryRegion));

        if (NewRegion == NULL) {
            printf("Error: realloc failed\n");
            free(Pi->Regions);
            Pi->Regions = NULL;
            Pi->RegionCount = 0;
            return;
        }

        Pi->Regions = NewRegion;
        Pi->Regions[Pi->RegionCount] = (MemoryRegion) { 
            BaseRegion.Address, 
            BaseRegion.Size, 
            BaseRegion.Rbi, 
            BaseRegion.InfoCount, 
            BaseRegion.ObjectName 
        };

        Pi->RegionCount++;
        BaseRegion.Address += BaseRegion.Size;
    }

    if (Pi->RegionCount == 0) {
        printf("Error: Could not get memory regions\n");
        free(Pi->Regions);
        Pi->Regions = NULL;
        Pi->RegionCount = 0;
        exit(EXIT_FAILURE);
    }

    Pi->BaseAddress = Pi->Regions[0];
    Pi->UnprotectedCount = 0;
    Pi->Unprotected = NULL;

    for (size_t I = 0; I < Pi->RegionCount; ++I) {
        if (!(Pi->Regions[I].Rbi.protection & VM_PROT_READ) 
            && !(Pi->Regions[I].Rbi.protection & VM_PROT_WRITE)) {
            continue;
        }

        MemoryRegion* NewRegion = (MemoryRegion*)safe_realloc(
            Pi->Unprotected,
            (Pi->UnprotectedCount + 1) * sizeof(MemoryRegion));

        if (NewRegion == NULL) {
            printf("Error: realloc failed\n");
            free(Pi->Unprotected);
            Pi->Unprotected = NULL;
            Pi->UnprotectedCount = 0;
            return;
        }

        Pi->Unprotected = NewRegion;
        Pi->Unprotected[Pi->UnprotectedCount] = Pi->Regions[I];
        Pi->UnprotectedCount++;
    }
}

void ReadProcessMemory(
        task_t Task, 
        mach_vm_address_t Address, 
        void* Buffer, 
        size_t Size) {
            
    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    if (mach_vm_read_overwrite(
            Task, 
            Address, 
            Size, 
            (mach_vm_address_t)Buffer, 
            (mach_vm_size_t*) &Size) != KERN_SUCCESS) {

        printf("Error: Could not read memory\n");
        exit(EXIT_FAILURE);
    }
}

void WriteProcessMemory(
        task_t Task, 
        mach_vm_address_t Address, 
        void* Buffer, 
        size_t Size) {

    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    if (mach_vm_write(
            Task, 
            Address, 
            (vm_offset_t)Buffer, 
            Size) != KERN_SUCCESS) {

        printf("Error: Could not write memory\n");
        exit(EXIT_FAILURE);
    }
}

void AllocateRemoteMemory(
        task_t Task, 
        mach_vm_address_t* Address, 
        mach_vm_size_t Size) {

    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    if (mach_vm_allocate(
        Task, 
        Address, 
        Size, 
        VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {

        printf("Error: Could not allocate memory\n");
        exit(EXIT_FAILURE);
    }
}

void DelallocateRemoteMemory(
        task_t Task, 
        mach_vm_address_t Address, 
        mach_vm_size_t Size) {

    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    if (mach_vm_deallocate(Task, Address, Size) != KERN_SUCCESS) {
        printf("Error: Could not deallocate memory\n");
        exit(EXIT_FAILURE);
    }
}

void GetProcessThreads(
        task_t Task, 
        thread_act_array_t* Threads, 
        mach_msg_type_number_t* ThreadCount) {

    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    if (task_threads(Task, Threads, ThreadCount) != KERN_SUCCESS) {
        printf("Error: Could not get threads\n");
        exit(EXIT_FAILURE);
    }
}

void SuspendProcessThread(thread_act_t Thread) {
    if (Thread == MACH_PORT_NULL) {
        printf("Error: Invalid thread\n");
        exit(EXIT_FAILURE);
    }

    if (thread_suspend(Thread) != KERN_SUCCESS) {
        printf("Error: Could not suspend thread\n");
        exit(EXIT_FAILURE);
    }
}

void ResumeProcessThread(thread_act_t Thread) {
    if (Thread == MACH_PORT_NULL) {
        printf("Error: Invalid thread\n");
        exit(EXIT_FAILURE);
    }

    if (thread_resume(Thread) != KERN_SUCCESS) {
        printf("Error: Could not resume thread\n");
        exit(EXIT_FAILURE);
    }
}

void GetThreadState(thread_act_t Thread, arm_thread_state64_t *State) {
    if (Thread == MACH_PORT_NULL) {
        printf("Error: Invalid thread\n");
        exit(EXIT_FAILURE);
    }

    mach_msg_type_number_t StateCount = ARM_THREAD_STATE64_COUNT;

    kern_return_t kr = thread_get_state(
        Thread, 
        ARM_THREAD_STATE64, 
        (thread_state_t)State, 
        &StateCount);

    if (kr != KERN_SUCCESS) {
        printf("Error: Could not get thread state. Error code: %d\n", kr);
        exit(EXIT_FAILURE);
    }
}

void SetThreadState(
        thread_act_t Thread, 
        thread_state_flavor_t Flavor, 
        thread_state_t State, 
        mach_msg_type_number_t StateCount) {

    if (Thread == MACH_PORT_NULL) {
        printf("Error: Invalid thread\n");
        exit(EXIT_FAILURE);
    }

    if (thread_set_state(
            Thread, 
            Flavor, 
            State, 
            StateCount) != KERN_SUCCESS) {

        printf("Error: Could not set thread state\n");
        exit(EXIT_FAILURE);
    }
}

void GetMemoryProtection(
        task_t Task, 
        mach_vm_address_t Address, 
        vm_prot_t* Protection) {

    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    MemoryRegion BaseRegion;
    BaseRegion.Address = Address;
    BaseRegion.Size = 0;
    BaseRegion.InfoCount = VM_REGION_BASIC_INFO_COUNT_64;

    kern_return_t Kr = mach_vm_region( 
        Task, 
        &BaseRegion.Address, 
        &BaseRegion.Size, 
        VM_REGION_BASIC_INFO_64, 
        (vm_region_info_t)&BaseRegion.Rbi, 
        &BaseRegion.InfoCount, 
        &BaseRegion.ObjectName);

    if (Kr != KERN_SUCCESS) {
        printf("Error: Could not get memory region\n");
        exit(EXIT_FAILURE);
    }

    *Protection = BaseRegion.Rbi.protection;
}

void SetMemoryProtection(
        task_t Task, 
        mach_vm_address_t Address, 
        size_t Size, 
        vm_prot_t Protection) {

    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    kern_return_t Kr = mach_vm_protect(Task, Address, Size, 0, Protection);
    if (Kr != KERN_SUCCESS) {
        printf("Error: Could not set memory protection. Error code: %d\n", Kr);
        exit(EXIT_FAILURE);
    }
}

void GetMemoryPages(task_t Task, ProcessInformation* Pi, MemoryPages* Pages) {
    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    Pages->Pages = NULL;
    Pages->PageCount = 0;

    for (size_t I = 0; I < Pi->RegionCount; ++I) {
        MemoryRegion* Region = &Pi->Regions[I];

        RegionPage BasePage;
        BasePage.Address = Region->Address;
        BasePage.Size = vm_page_size;

        while (BasePage.Address < Region->Address + Region->Size) {
            
            mach_vm_size_t DataSize = BasePage.Size;
            kern_return_t Kr = mach_vm_read(Task, BasePage.Address, BasePage.Size, &BasePage.Data, &BasePage.DataCount);

            if (Kr != KERN_SUCCESS) {
                printf("Error: Could not read memory. Error code: %d\n", Kr);
                BasePage.Address += BasePage.Size;
                break;
            }

            RegionPage* NewPage = (RegionPage*)safe_realloc(
                Pages->Pages,
                (Pages->PageCount + 1) * sizeof(RegionPage));

            if (NewPage == NULL) {
                printf("Error: realloc failed\n");
                free(Pages->Pages);
                Pages->Pages = NULL;
                Pages->PageCount = 0;
                return;
            }

            Pages->Pages = NewPage;
            Pages->Pages[Pages->PageCount] = (RegionPage) { 
                BasePage.Address, 
                BasePage.Size, 
                BasePage.DataCount,
                BasePage.Data
            };

            Pages->PageCount++;
            BasePage.Address += BasePage.Size;
        }
    }
} 

void EnumeratePageTableEntries(task_t Task, MemoryPages* Pages) {
    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    for (size_t I = 0; I < Pages->PageCount; ++I) {

        RegionPage* Page = &Pages->Pages[I];

        for (size_t J = 0; J < Page->DataCount; ++J) {

            PageTableEntry* Entry = (PageTableEntry*)(Page->Data + J * sizeof(PageTableEntry));

            if (!Entry->ReadWrite) {
                continue;
            }

            printf("Page: %zu\n Entry: %zu\n Present: %d\n ReadWrite: %d\n UserSupervisor: %d\n PageWriteThrough: %d\n PageCacheDisable: %d\n Accessed: %d\n Dirty: %d\n PageSize: %d\n Global: %d\n Available: %d\n PageFrameNumber: 0x%llx\n Reserved: %d\n NoExecute: %d\n\n", 
                I, 
                J, 
                Entry->Present, 
                Entry->ReadWrite, 
                Entry->UserSupervisor, 
                Entry->PageWriteThrough, 
                Entry->PageCacheDisable, 
                Entry->Accessed, 
                Entry->Dirty, 
                Entry->PageSize, 
                Entry->Global, 
                Entry->Available, 
                Entry->PageFrameNumber, 
                Entry->Reserved, 
                Entry->NoExecute);
        }
    }
}