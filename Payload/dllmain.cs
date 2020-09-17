using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Data;

class Payload
{
    [UnmanagedFunctionPointer( CallingConvention.Cdecl )]
    delegate void d_print_ebp();

    public static IntPtr ebp_addr;

    public unsafe static int DllMain( string param )
    {
                                                    /* SIGNATURE OF PRINT_EBP() FUNCTION INSIDE TARGET.EXE */
        var target_sign = "55 8B EC 81 EC ? ? ? ? 53 56 57 8D BD ? ? ? ? B9 ? ? ? ? B8 ? ? ? ? F3 AB A1 ? ? ? ? 33 C5 89 45 FC 89 6D F4";
        var target_addr = Memory.PatternScan(
            Process.GetCurrentProcess().MainModule.BaseAddress,
            Process.GetCurrentProcess().MainModule.ModuleMemorySize,
            target_sign );

        if ( target_addr == IntPtr.Zero )
            return -1;

        var hook_addr = Marshal.GetFunctionPointerForDelegate<d_print_ebp>( hk_print_ebp );

        Console.WriteLine( hook_addr );
        Console.WriteLine( target_addr );

        ebp_addr = Marshal.AllocHGlobal( sizeof( int ) );
        *(int*)ebp_addr = 0;

        var ebp = BitConverter.GetBytes( (int)ebp_addr );

        var shellcode = new byte[]
        {
            0x83, 0xec, 0x08,                                         // sub    esp, 0x8
            0xc7, 0x44, 0x24, 0x04, ebp[0], ebp[1], ebp[2], ebp[3],   // mov    DWORD PTR [esp+0x4], b_ebp
            0x8b, 0x44, 0x24, 0x04,                                   // mov    eax,DWORD PTR [esp+0x4]
            0x89, 0x28,                                               // mov    DWORD PTR [eax],ebp
            0x83, 0xc4, 0x08                                          // add    esp,0x8
        };

        var aitm = new AITM( target_addr, shellcode, hook_addr );
        Console.WriteLine( "[*] AITM Placed" );

        System.Threading.Thread.Sleep( 5000 );
        aitm.Release();

        Console.WriteLine( "[*] AITM Released" );

        while ( true )
            System.Threading.Thread.Sleep( 5 );
    }

    public unsafe static void hk_print_ebp()
    {
        Console.WriteLine( "[+] ebp register : {0}", *(int*)ebp_addr - 240 );
        Console.WriteLine( "print_ebp hooked!" );
    }
}

class Memory
{
    unsafe public static IntPtr PatternScan( IntPtr addr, int length, string signature )
    {

        var split = signature.Split(' ');
        var lPattern = new List<int>();

        foreach ( var s in split )
        {
            if ( s.Contains( "?" ) )
            {
                lPattern.Add( -1 );
                continue;
            }
            lPattern.Add( Convert.ToInt32( s, 16 ) );
        }

        var pattern = lPattern.ToArray();

        for ( var i = addr.ToInt32(); i < addr.ToInt32() + length; i++ )
        {
            var b = *(byte*)i;
            if ( b == pattern[0] )
                for ( int j = 0; j < pattern.Length; j++ )
                {
                    b = *(byte*)(i + j);
                    if ( b == pattern[j] || pattern[j] == -1 )
                    {
                        if ( j == pattern.Length - 1 )
                        {
                            return (IntPtr)i;
                        }
                    }
                    else
                        break;
                }
        }

        return IntPtr.Zero;
    }
}