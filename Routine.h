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
    MemoryRegion* Unprotected;
    size_t UnprotectedCount;
    MemoryRegion BaseAddress;
} ProcessInformation;

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

        MemoryRegion* NewRegion = (MemoryRegion*)safe_realloc(Pi->Regions, (Pi->RegionCount + 1) * sizeof(MemoryRegion));
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
        if ((Pi->Regions[I].Rbi.protection & VM_PROT_READ) && (Pi->Regions[I].Rbi.protection & VM_PROT_WRITE)) {
            MemoryRegion* NewRegion = (MemoryRegion*)safe_realloc(Pi->Unprotected, (Pi->UnprotectedCount + 1) * sizeof(MemoryRegion));
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
}
