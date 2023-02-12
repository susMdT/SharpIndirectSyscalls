using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Linq;


namespace SharpIndirectSyscalls
{
    public class dll
    {
        public IntPtr dllLocation;
        int exportRva, ordinalBase, numberOfNames, functionsRva, namesRva, ordinalsRva;

        //For ntdll
        public Dictionary<int, SysInfo> UnsortedSyscalls = new Dictionary<int, SysInfo>();
        public Dictionary<int, SysInfo> SortedSyscalls = new Dictionary<int, SysInfo>();
        public Dictionary<IntPtr, string> SysInstructs = new Dictionary<IntPtr, string>();
        public Dictionary<string, IntPtr> dictOfExports = new Dictionary<string, IntPtr>(); 

        IntPtr pCove;

        public struct SysInfo : IComparable<SysInfo>
        {
            public string funcName;
            public IntPtr funcAddr;
            public int CompareTo(SysInfo other)
            {
                return this.funcAddr.ToInt64().CompareTo(other.funcAddr.ToInt64());
            }
        }
        public dll()
        {

            if (IntPtr.Size != 8)
            {
                Console.WriteLine("[!] This only works for x64!");
                Environment.Exit(0);
            }

            //Find ntdll in memory
            this.dllLocation = Process.GetCurrentProcess().Modules.OfType<ProcessModule>().FirstOrDefault(module => module.ModuleName == "ntdll.dll").BaseAddress;

            //Dinvoke magic to parse some very important properties
            var peHeader = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + 0x3C));
            var optHeader = this.dllLocation.ToInt64() + peHeader + 0x18;
            var magic = Marshal.ReadInt16((IntPtr)optHeader);
            long pExport = 0;
            if (magic == 0x010b) pExport = optHeader + 0x60;
            else pExport = optHeader + 0x70;
            this.exportRva = Marshal.ReadInt32((IntPtr)pExport);
            this.ordinalBase = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x10));
            this.numberOfNames = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x18));
            this.functionsRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x1C));
            this.namesRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x20));
            this.ordinalsRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x24));

            getSyscallIds();
            getExports();
            getSyscallInstructionAddresses();
            GenerateRWXMemorySegment();

        }

        /// <summary>
        /// Using ElephantSe4l method and CHATGPT for sorting, find the syscall ID via the order of the functions in memory
        /// </summary>
        public void getSyscallIds()
        {
            IntPtr functionPtr = IntPtr.Zero;
            int ntCounter = 0;
            for (var i = 0; i < this.numberOfNames; i++) //Find all the NtFunctions and their memory addresses
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(this.dllLocation.ToInt64() + Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                if (functionName.StartsWith("Nt") && !functionName.StartsWith("Ntdll"))
                {
                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(this.dllLocation.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                    var functionRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)this.dllLocation + functionRva);
                    SysInfo temp = new SysInfo();
                    temp.funcAddr = functionPtr;
                    temp.funcName = functionName;
                    this.UnsortedSyscalls.Add(ntCounter, temp);
                    ntCounter++;
                }
            }
            //bro what the fuck GPT
            SortedSyscalls = UnsortedSyscalls.OrderBy(x => x.Value).ToDictionary(x => x.Key, x => x.Value).Select((x, i) => new { i, x }).ToDictionary(x => x.i, x => x.x.Value);
            
        }

        // Sacrificing this method to microsoft
        public static UInt32 Gate() { return (uint)5; }
        /// <summary>
        /// Jit the Gate
        /// 1. Follow JMP to find machine code of JITTED method and designate it for our syscall writing
        /// </summary>
        public void GenerateRWXMemorySegment()
        {
            // Find and JIT the method?
            MethodInfo method = typeof(dll).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(method.MethodHandle);
            // Get the address of the function to find JITted machine code or figure out if JIT went weird
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            if (Marshal.ReadByte(pMethod) != 0xe9)
            {
                Console.WriteLine("Invalid stub, gonna assume the managed method address is the method table entry");
                pCove = pMethod;
                return;
            }
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr64 = 0;

            addr64 = (UInt64)pMethod + (UInt64)offset;
            while (addr64 % 16 != 0)
                addr64++;
            pCove = (IntPtr)addr64;
            return;
        }
        public byte[] generateStub(short id)
        {
            Random rand = new Random();
            List<IntPtr> keyList = this.SysInstructs.Select(x => x.Key).ToList();
            IntPtr randomAssSyscallInstruction = keyList[rand.Next(keyList.Count)];

            byte[] bruh = BitConverter.GetBytes((long)randomAssSyscallInstruction);
            byte[] stub = new byte[21]
            {
                0x4C, 0x8B, 0xD1,               			                                            // mov r10, rcx
	            0xB8, (byte)id, (byte) (id >> 8), 0x00, 0x00,    	              	                    // mov eax, syscall number
	            0x49, 0xBB, bruh[0], bruh[1], bruh[2], bruh[3], bruh[4], bruh[5], bruh[6], bruh[7],     // movabs r11,syscall address
	            0x41, 0xFF, 0xE3 				       	                                                // jmp r11
            };
            return stub;
        }
        //Utility Functions
        public void getExports()
        {
            for (var i = 0; i < this.numberOfNames; i++) //Find all the exports
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(this.dllLocation.ToInt64() + Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                var functionOrdinal = Marshal.ReadInt16((IntPtr)(this.dllLocation.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                var functionRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                IntPtr functionPtr = (IntPtr)((long)this.dllLocation + functionRva);
                dictOfExports.Add(functionName, functionPtr);
            }
        }

        /// <summary>
        /// Jam a syscall into the codecove, make a delegate to it, and invoke. Each syscall overwrites each other, so less sussy? 
        /// The syscall will JMP back to the real syscall in ntdll so kernel callbacks make it seem like the syscalls are legit
        /// </summary>
        /// <typeparam name="T">Delegate to be used as function prototype for the syscall</typeparam>
        /// <param name="name">Name of NtFunction who's syscall we're nabbing</param>
        /// <param name="arr">Object arr of args. Each item may get modified depending on if original Nt func passed by ref or not, so initialize accordingly</param>
        /// <returns>An object which can be casted to what the delegate should normally return</returns>
        public object indirectSyscallInvoke<T>(string name, object[] arr) where T : Delegate
        {
  
            short syscallId = -1;
            syscallId = (short)this.SortedSyscalls.FirstOrDefault(item => item.Value.funcName == name).Key;
            if (syscallId == -1)
            {
                Console.WriteLine("Syscallid for {0} not found!", name);
                return null;
            }
            byte[] stub = generateStub(syscallId);
            Marshal.Copy(stub, 0, pCove, stub.Length);
            var retValue = Marshal.GetDelegateForFunctionPointer(pCove, typeof(T)).DynamicInvoke(arr);

            return retValue;
        }
        public void getSyscallInstructionAddresses()
        {
            IntPtr syscallInstructAddr = IntPtr.Zero;
            byte[] syscallInstructionCompare = new byte[2] { 0x00, 0x00 };
            int currentDictionaryIndex = 0;
            foreach (var item in this.SortedSyscalls)
            {
                if (item.Key == this.SortedSyscalls.Count - 1) break;
                for (int i = 0; i < ((long)this.SortedSyscalls[currentDictionaryIndex + 1].funcAddr - (long)item.Value.funcAddr); i++)
                {
                    syscallInstructionCompare[0] = Marshal.ReadByte(IntPtr.Add(item.Value.funcAddr, i));
                    syscallInstructionCompare[1] = Marshal.ReadByte(IntPtr.Add(item.Value.funcAddr, i + 1));
                    if (syscallInstructionCompare[0] == 0x0f && syscallInstructionCompare[1] == 0x05)
                    {
                        syscallInstructAddr = IntPtr.Add(item.Value.funcAddr, i);
                        break;
                    }
                }
                currentDictionaryIndex++;
                if (syscallInstructAddr != IntPtr.Zero)
                {
                    this.SysInstructs.Add(syscallInstructAddr, item.Value.funcName);
                    syscallInstructAddr = IntPtr.Zero;
                }
            }
        }
    }
}
