using System;
using System.Linq;
using System.Runtime.InteropServices;

class AITM
{
    EzyHook hook;

    public unsafe AITM( IntPtr target_addr, byte[] shellcode, IntPtr hook_addr )
    {
        shellcode = shellcode.Concat( new byte[] {
            0xe9, 0x00, 0x00, 0x00, 0x00     // jmp    hook_addr
        } ).ToArray();

        fixed ( byte* ptr = shellcode )
        {
            var rel = (int)hook_addr - ((int)ptr + shellcode.Length) - 5;
            var jmp = BitConverter.GetBytes( rel );

            shellcode[shellcode.Length - 4] = jmp[0];
            shellcode[shellcode.Length - 3] = jmp[1];
            shellcode[shellcode.Length - 2] = jmp[2];
            shellcode[shellcode.Length - 1] = jmp[3];

            EzyHook.VirtualProtect( (IntPtr)ptr, shellcode.Length, 0x40, out _ );
            hook = new EzyHook( target_addr, (IntPtr)ptr );
        }
    }

    public void Release()
    {
        hook.UnHook();
    }
}

class EzyHook
{
    [DllImport( "kernel32.dll" )]
    public static extern bool VirtualProtect( IntPtr lpAddress, int dwSize, int lpflNewProtect, out int lpflOldProtect );

    public byte[] old_bytes = new byte[5];
    bool is_hooked = false;

    IntPtr target_addr, hook_addr;

    public unsafe EzyHook( IntPtr target_addr, IntPtr hook_addr )
    {
        VirtualProtect( target_addr, 5, 0x40, out var flag );
        Marshal.Copy( target_addr, old_bytes, 0, 5 );

        *(int*)target_addr = 0xE9;
        *(int*)(target_addr + 1) = (int)hook_addr - (int)target_addr - 5;

        VirtualProtect( target_addr, 5, flag, out _ );

        this.target_addr = target_addr;
        this.hook_addr = hook_addr;
        is_hooked = true;
    }

    public unsafe void Hook()
    {
        if ( is_hooked )
            return;

        VirtualProtect( target_addr, 5, 0x40, out var flag );
        Marshal.Copy( target_addr, old_bytes, 0, 5 );

        *(int*)target_addr = 0xE9;
        *(int*)(target_addr + 1) = (int)hook_addr - (int)target_addr - 5;

        VirtualProtect( target_addr, 5, flag, out _ );

        is_hooked = true;
    }

    public unsafe void UnHook()
    {
        if ( !is_hooked )
            return;

        VirtualProtect( target_addr, 5, 0x40, out var flag );
        Marshal.Copy( old_bytes, 0, target_addr, 5 );
        VirtualProtect( target_addr, 5, flag, out _ );

        is_hooked = false;
    }
}
