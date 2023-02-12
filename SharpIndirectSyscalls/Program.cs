using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpIndirectSyscalls
{
    internal class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref UInt32 NumberOfBytesWritten
        );

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        static void Main(string[] args)
        {
            LoadLibrary("C:\\Users\\Administrator\\Desktop\\Dev\\Course\\nirvana\\x64\\Release\\syscall-detect.dll");

            dll ntdll = new dll();

            object[] allocArgs = { (IntPtr)(-1), IntPtr.Zero, IntPtr.Zero, (IntPtr)4096, (uint)0x3000, (uint)0x40 };
            ntdll.indirectSyscallInvoke<NtAllocateVirtualMemory>("NtAllocateVirtualMemory", allocArgs);
            Console.WriteLine("Allocated to 0x{0:X}", (long)(IntPtr)allocArgs[1]);
            
            object[] writeArgs = { (IntPtr)(-1), (IntPtr)allocArgs[1], GCHandle.Alloc(new byte[] { 0x41 }, GCHandleType.Pinned).AddrOfPinnedObject(), (uint)1, (uint)0 };
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<NtWriteVirtualMemory>("NtWriteVirtualMemory", writeArgs);
            if (ntstatus == 0) Console.WriteLine("Memory was written, go take a read");
            Console.ReadKey();

        }
    }
}
