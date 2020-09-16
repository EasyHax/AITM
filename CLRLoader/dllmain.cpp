#include <windows.h>
#include <metahost.h>

#pragma comment(lib, "mscoree.lib") 

DWORD WINAPI LoadCLR( LPVOID lpvParam ) {

    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICLRRuntimeHost* pClrRuntimeHost = NULL;

    if ( SUCCEEDED( CLRCreateInstance( CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost ) ) ) {
        if ( SUCCEEDED( pMetaHost->GetRuntime( L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo ) ) ) {
            if ( SUCCEEDED( pRuntimeInfo->GetInterface( CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&pClrRuntimeHost ) ) ) {
                if ( SUCCEEDED( pClrRuntimeHost->Start() ) ) {
                    if ( SUCCEEDED( pClrRuntimeHost->ExecuteInDefaultAppDomain( L"Payload.dll", L"Payload", L"DllMain", nullptr, nullptr ) ) ) {
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ulReason, LPVOID lpReserved )
{
    if ( ulReason == DLL_PROCESS_ATTACH )
        CreateThread( nullptr, NULL, LoadCLR, nullptr, NULL, nullptr );

    return TRUE;
}

