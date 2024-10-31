#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <string.h>

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
    mach_vm_address_t Address;
    mach_vm_size_t Size;
    vm_region_basic_info_data_64_t Rbi;
    mach_msg_type_number_t InfoCount;
    mach_port_t ObjectName;
} MemoryRegion;

typedef struct {
    MemoryRegion* Regions;
    size_t RegionCount;
    MemoryRegion* UnprotectedRegions;
    size_t UnprotectedCount;
    MemoryRegion BaseAddress;
    unsigned char* Buffer;
    size_t BufferSize;
} MemoryProcessInformation;

void GetPidByName(const char* ProcessName, pid_t* Pid) {
    int Mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t Miblen = 4;
    size_t Size;

    if (sysctl(Mib, Miblen, NULL, &Size, NULL, 0) == -1) {
        printf("Error: Could not get size of buffer\n");
        exit(EXIT_FAILURE);
    }
    
    unsigned char* Buffer = (unsigned char*)malloc(Size);
    if (sysctl(Mib, Miblen, Buffer, &Size, NULL, 0) == -1) {
        printf("Error: Could not allocate buffer\n");
        free(Buffer);
        exit(EXIT_FAILURE);
    }

    struct kinfo_proc* Kprocs = (struct kinfo_proc*)Buffer;
    int ProcessCount = Size / sizeof(struct kinfo_proc);

    for (int I = 0; I < ProcessCount; ++I) {
        *Pid = strcmp(Kprocs[I].kp_proc.p_comm, ProcessName) == 0 ? Kprocs[I].kp_proc.p_pid : -1;
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

void GetMemoryProcessInformation(task_t Task, MemoryProcessInformation* Mpi) {
    if (Task == MACH_PORT_NULL) {
        printf("Error: Invalid task\n");
        exit(EXIT_FAILURE);
    }

    Mpi->RegionCount = 0;
    Mpi->Regions = NULL;
    MemoryRegion BaseRegion;

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

        MemoryRegion* NewRegion = (MemoryRegion*)safe_realloc(Mpi->Regions, (Mpi->RegionCount + 1) * sizeof(MemoryRegion));
        if (NewRegion == NULL) {
            printf("Error: realloc failed\n");
            free(Mpi->Regions);
            Mpi->Regions = NULL;
            Mpi->RegionCount = 0;
            return;
        }

        Mpi->Regions = NewRegion;
        Mpi->Regions[Mpi->RegionCount] = (MemoryRegion){ 
            BaseRegion.Address, 
            BaseRegion.Size, 
            BaseRegion.Rbi, 
            BaseRegion.InfoCount, 
            BaseRegion.ObjectName };

        Mpi->RegionCount++;
        BaseRegion.Address += BaseRegion.Size;
    }
}

