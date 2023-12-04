#include <stdio.h>
#include <windows.h>
#include "nt.h"
#include "minhook/MinHook.h"
#include <stdint.h>
#include <intrin.h>
#include <nmmintrin.h>

typedef struct {
    struct section_t* next;
    PVOID base;
    SIZE_T size;
    uint32_t checksum;
}section_t;

volatile LONG g_lock = 0;
section_t g_sections = { NULL };
HANDLE g_thread = NULL;

void AquireLock() { 
    while (InterlockedExchange(&g_lock, 1) == 1) {
        YieldProcessor();
    }
}

void ReleaseLock() {
    InterlockedExchange(&g_lock, 0);
}

void InsertSection(PVOID base, SIZE_T size) {
    AquireLock();
    section_t* current = &g_sections;
    while (current->next != NULL) {
        current = (section_t*)current->next;
    }

    section_t* new_section = (section_t*)malloc(sizeof(section_t));
    if (new_section == NULL) {
        printf("Failed to allocate memory for new section\n");
        ReleaseLock();
        return;
    }

    new_section->next = NULL;
    new_section->base = base;
    new_section->size = size;
    new_section->checksum = 0;
    current->next = (struct section_t*)new_section;
    ReleaseLock();
}

void RemoveSection(PVOID Base) {
    AquireLock();

    section_t* current = &g_sections;
    while (current->next != NULL) {
        section_t* next = (section_t*)current->next;
        if (next->base == Base) {
            current->next = next->next;
            free(next);
            break;
        }
        
        current = next;
    }

    ReleaseLock();
}

ZwMapViewOfSection_t o_ZwMapViewOfSection = NULL;
NTSTATUS Hk_ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, 
        PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
        
    NTSTATUS status = o_ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, 
                                            ViewSize, InheritDisposition, AllocationType, Win32Protect);
    if (!NT_SUCCESS(status)) {
        printf("ZwMapViewOfSection failed with status 0x%08lX\n", status);
        return status;
    }

    if (BaseAddress == NULL || ViewSize == NULL) {
        printf("BaseAddress or ViewSize is NULL\n");
        return status;
    }
    
    InsertSection(*BaseAddress, *ViewSize);
    return status;
}

ZwUnmapViewOfSection_t o_ZwUnmapViewOfSection = NULL;
NTSTATUS Hk_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    RemoveSection(BaseAddress);
    return o_ZwUnmapViewOfSection(ProcessHandle, BaseAddress);
}

ExitProcess_t o_ExitProcess = NULL;
void Hk_ExitProcess(UINT uExitCode) {
    printf("ExitProcess called (%d) leaving in 5 seconds...\n", uExitCode);
    
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    Sleep(5000);

    TerminateThread(g_thread, 0);
    CloseHandle(g_thread);

    return o_ExitProcess(uExitCode);
}

void SectionWatcher() {
    while (TRUE) {
        AquireLock();
        section_t* current = &g_sections;
        while (current->next != NULL) {
            current = (section_t*)current->next;

            void* data = malloc(current->size);
            if (data == NULL) { // WTF?
                printf("Failed to allocate memory for section data\n");
                continue;
            }

            // ReadProcessMemory is used here because sometimes the memory is not readable with memcpy (idk why)
            if (!ReadProcessMemory(GetCurrentProcess(), current->base, data, current->size, NULL)) {
                ReleaseLock();
                RemoveSection(current->base);
                AquireLock();
                
                // printf("Failed to read section data\n");
                free(data);
                continue;
            }

            // Whitelist EAC buffers
            typedef struct {
                uint32_t Unk0;
                uint32_t Unk1;
                uint32_t Unk2;
                uint32_t Unk3;
                uint32_t ProcessId;
                uint32_t Unk4;
                uint32_t DataSize;
                uint8_t Data[1];
            } StreamBuffer_t;

            // sanity checks
            StreamBuffer_t* buffer = (StreamBuffer_t*)data;
            if ((char)buffer->Data[0] != 'M' || (char)buffer->Data[1] != 'Z') {
                free(data);
                continue;
            }
            else if (buffer->DataSize > current->size - sizeof(StreamBuffer_t)) {
                free(data);
                continue;
            }

            // incase the buffer gets modified while dumping
            uint32_t checksum = 0;
            for (uint32_t i = 0; i < buffer->DataSize; ++i) {
                checksum += _mm_crc32_u8(checksum, buffer->Data[i]);
            }

            if (checksum != current->checksum) {
                current->checksum = checksum;

                char filename[19];
                sprintf(filename, "dumps/%x.bin", current->checksum);

                FILE* file = fopen(filename, "wb");
                if (file == NULL) {
                    printf("Failed to open file %s\n", filename);
                    free(data);
                    continue;
                }

                fwrite(buffer->Data, 1, buffer->DataSize, file);
                fclose(file);
            
                printf("Dumped to %s\n", filename);
            }

            free(data);
        }
        ReleaseLock();
        Sleep(100);
    }
}

void InstallHooks() {
    if (MH_Initialize() != MH_OK) {
        printf("Failed to initialize MinHook\n");
        return;
    }

    if (MH_CreateHookApi(L"ntdll.dll", "ZwUnmapViewOfSection", Hk_ZwUnmapViewOfSection, (PVOID*)&o_ZwUnmapViewOfSection) != MH_OK) {
        printf("Failed to create hook for ZwUnmapViewOfSection\n");
        return;
    }

    if (MH_CreateHookApi(L"ntdll.dll", "ZwMapViewOfSection", Hk_ZwMapViewOfSection, (PVOID*)&o_ZwMapViewOfSection) != MH_OK) {
        printf("Failed to create hook for ZwMapViewOfSection\n");
        return;
    }

    if (MH_CreateHookApi(L"kernel32.dll", "ExitProcess", Hk_ExitProcess, (PVOID*)&o_ExitProcess) != MH_OK) {
        printf("Failed to create hook for ExitProcess\n");
        return;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        printf("Failed to enable hooks\n");
        return;
    }
    
    printf("Hooks installed\n");

    g_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SectionWatcher, NULL, 0, NULL);
    if (g_thread == NULL) {
        printf("Failed to create thread\n");
        return;
    }

    printf("Thread created\n");
}