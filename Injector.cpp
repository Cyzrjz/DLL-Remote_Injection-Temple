#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#define PROCESS_NAME   L"TargetApp.exe"
#define DLL_NAME	"AntiCapture.dll" //这是相对于目标程序的dll路径

VOID ShowError(const char* err)
{
	printf("%s 失败：%u", err, GetLastError());
}

DWORD GetPid(const WCHAR* pProName) 
{
	//创建系统进程快照
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	if (hSnap == INVALID_HANDLE_VALUE)
	{
		ShowError("CreateToolhelp32Snapshot");
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnap, &pe))
	{
		do 
		{
			//忽略大小写比较
			if (_wcsicmp(pe.szExeFile,pProName) == 0)
			{
				printf("PID为%d\n", pe.th32ProcessID);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnap, &pe));
	}
	return 0;
}

BOOL inject(DWORD dwPid,const CHAR dllName[])
{
	HANDLE hProcess = NULL;
	HMODULE hKernel32 = NULL;
	SIZE_T dwSize = NULL;
	LPVOID DLL_address = NULL;
	FARPROC hLoadLibraryA = NULL;
	HANDLE hRemoteThread = NULL;

	//打开注入进程，获取进程句柄
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		ShowError("OpenProcess");
		return 0;
	}

	//在注入进程中申请空间
	dwSize = strlen(dllName) + 1;
	DLL_address = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (DLL_address == NULL)
	{
		ShowError("VirtualAllocEx");
		return 0;
	}

	//将DLL路径写入进程
	if (!WriteProcessMemory(hProcess, DLL_address, dllName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		return 0;
	}

	//获取模块的地址
	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL)
	{
		ShowError("GetModuleHandleA");
		return 0;
	}

	//获取LoadLibraryA函数地址
	hLoadLibraryA = GetProcAddress(hKernel32,"LoadLibraryA");
	if (hLoadLibraryA == NULL)
	{
		ShowError("GetProcAddress");
		return 0;
	}

	//创建远程线程进行DLL注入
	hRemoteThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)hLoadLibraryA,
		DLL_address,
		0,NULL
		);


	if (hRemoteThread == NULL)
	{
		ShowError("CreateRemoteThread");
		return 0;
	}

	if (hKernel32) FreeLibrary(hKernel32);
	if (hProcess) CloseHandle(hProcess);
	if (hRemoteThread) CloseHandle(hRemoteThread);
	return 1;

}

int main() 
{
	DWORD pid = GetPid(PROCESS_NAME);
	if (pid == 0)
	{
		printf("获取PID失败\n");
		system("pause");
		return 0;
	}
	if (inject(pid, DLL_NAME))
	{
		printf("注入成功\n");
	}
	return 0;
}
