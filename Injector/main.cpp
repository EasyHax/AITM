#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <stdlib.h>
#include <string>

unsigned long process_by_name( const wchar_t* process_name )
{
    auto p32 = PROCESSENTRY32{ sizeof( PROCESSENTRY32 ) };
    auto t32 = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );

    if ( Process32First( t32, &p32 ) == TRUE )
    {
        while ( Process32Next( t32, &p32 ) == TRUE )
        {
            if ( !wcscmp( p32.szExeFile, process_name ) ) {

                return p32.th32ProcessID;
            }
        }
    }

    return NULL;
}

bool inject( unsigned long process_id, const char* dll_name ) 
{
	if ( auto hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id ) ) {
		
        if ( auto pAddr = VirtualAllocEx( hProcess, NULL, strlen(dll_name) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE ) ) {
			
            if ( WriteProcessMemory( hProcess, pAddr, dll_name, strlen( dll_name ) + 1, NULL ) ) {

                auto lpStartAddr = (LPTHREAD_START_ROUTINE)GetProcAddress( LoadLibrary( L"kernel32" ), "LoadLibraryA" );

				if ( CreateRemoteThread( hProcess, NULL, NULL, lpStartAddr, pAddr, NULL, NULL ) ) {
					return true;
				}
			}
		}

		return false;
	}
}

int main( void ) {

    auto pid = process_by_name( L"Target.exe" );

    if ( !pid )
        return -1;

    inject( pid, "CLRLoader.dll" );

    return 0;
}
