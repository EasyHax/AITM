# AITM
Assembly In The Middle

![](https://i.imgur.com/GZjbW2s.png)

An utility to detour a native function toward a managed function, while executing shellcode in between.

## EXAMPLE

Here the Payload project is used to retrieve the address of the EBP register of the native process, using the AITM class.

## HOW TO USE
```cs
var aitm = new AITM( IntPtr target_addr, byte[] shellcode, IntPtr hook_addr )
```

Hooks the function at target_addr, executes the shellcode, jumps to hook_addr.
- *target_addr : the address of the function to hook*
- *shellcode : the shellcode / opcodes to execute*
- *hook_addr : the address of the function to callback*

```cs
aitm.Release()
```

Unhook the target function and put it in its original state.

## HOW IT WORKS

```css
:Target    - Native executable containing the function to hook
:Injector  - Injector used to inject and execute the CLRLoader library into the Target
:CLRLoader - Library used to load the CLR and loading our payload library into the Target
:Payload   - Managed library performing the attack on the Target
```

* __Toggle ON__ :
  * Replace the 5 first bytes of the target function with a JMP instruction towards
the address of the shellcode.
  * Add a JMP instruction at the end of the shellcode towards the address of the
callback function.
* __Toggle OFF__ :
  * Replace the 5 first bytes of the target function with the original bytes.
  
## TODO

* Ensure registers are saved.
* Call original function without Release() the AITM instance.
* Support x64.
