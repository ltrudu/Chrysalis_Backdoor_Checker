using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ChrysalisChecker;

/// <summary>
/// Chrysalis Backdoor IOC Checker
/// Based on Rapid7 research: https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
/// </summary>
class Program
{
    #region Indicators of Compromise

    /// <summary>SHA-256 hashes of known malicious files</summary>
    private static readonly Dictionary<string, string> MaliciousHashes = new()
    {
        ["a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9"] = "update.exe",
        ["8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e"] = "[NSIS].nsi",
        ["2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924"] = "BluetoothService.exe",
        ["77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e"] = "BluetoothService",
        ["3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad"] = "log.dll",
        ["9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600"] = "u.bat",
        ["f4d829739f2d6ba7e3ede83dad428a0ceda1a703ec582fc73a4eee3df3704629a"] = "conf.c",
        ["4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906"] = "libtcc.dll",
        ["0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd"] = "Loader 1",
        ["e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda"] = "Loader 2",
        ["b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3"] = "ConsoleApplication2.exe",
        ["fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"] = "Loader 4",
        // Shellcode hashes
        ["4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8"] = "Shellcode 1",
        ["078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5"] = "Shellcode 2",
        ["7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd"] = "Shellcode 3",
    };

    /// <summary>Malicious file names to search for</summary>
    private static readonly HashSet<string> MaliciousFilenames = new(StringComparer.OrdinalIgnoreCase)
    {
        "BluetoothService.exe",
        "log.dll",
        "libtcc.dll",
        "update.exe",
        "u.bat",
        "conf.c",
        "ConsoleApplication2.exe",
    };

    /// <summary>C2 domains</summary>
    private static readonly HashSet<string> C2Domains = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.skycloudcenter.com",
        "api.wiresguard.com",
    };

    /// <summary>C2 IP addresses</summary>
    private static readonly HashSet<string> C2IPs = new()
    {
        "95.179.213.0",
        "61.4.102.97",
        "59.110.7.32",
        "124.222.137.114",
    };

    /// <summary>Suspicious paths used by the malware</summary>
    private static readonly string[] SuspiciousPaths =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Bluetooth"),
        @"C:\ProgramData\USOShared",
    };

    /// <summary>Mutex name used by the backdoor</summary>
    private const string MutexName = @"Global\Jdhfv_1.0.1";

    /// <summary>Extensions to skip during full scan</summary>
    private static readonly HashSet<string> SkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".iso", ".wim", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".msi", ".cab",
        ".psd", ".ai", ".indd",
        ".bak", ".old", ".tmp",
    };

    /// <summary>Directories to skip during scan</summary>
    private static readonly HashSet<string> SkipDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "$recycle.bin",
        "system volume information",
        "windows.old",
        "recovery",
    };

    /// <summary>Max file size to hash (50MB)</summary>
    private const long MaxFileSize = 50 * 1024 * 1024;

    #endregion

    #region Console Colors

    private static class Colors
    {
        public const string Red = "\u001b[91m";
        public const string Green = "\u001b[92m";
        public const string Yellow = "\u001b[93m";
        public const string Blue = "\u001b[94m";
        public const string Reset = "\u001b[0m";
        public const string Bold = "\u001b[1m";
    }

    #endregion

    #region Native Methods

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenMutex(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint MUTEX_ALL_ACCESS = 0x1F0001;

    #endregion

    private static bool _checkAll;
    private static string[] _drives = { "C", "D" };

    static int Main(string[] args)
    {
        try
        {
            ParseArguments(args);
            int findingsCount = RunAllChecks();

            Console.WriteLine("\nPress Enter to exit...");
            Console.ReadLine();

            return findingsCount > 0 ? 1 : 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n{Colors.Red}[!] Unexpected error: {ex.Message}{Colors.Reset}");
            return 1;
        }
    }

    private static void ParseArguments(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i].ToLower();

            if (arg == "-checkall" || arg == "--checkall")
            {
                _checkAll = true;
            }
            else if ((arg == "-drives" || arg == "--drives") && i + 1 < args.Length)
            {
                var drives = new List<string>();
                for (int j = i + 1; j < args.Length; j++)
                {
                    if (args[j].StartsWith("-")) break;
                    drives.Add(args[j].TrimEnd(':', '\\'));
                }
                if (drives.Count > 0)
                {
                    _drives = drives.ToArray();
                }
            }
            else if (arg == "-h" || arg == "--help" || arg == "-?")
            {
                PrintHelp();
                Environment.Exit(0);
            }
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine(@"
Chrysalis Backdoor IOC Checker

Usage:
  ChrysalisChecker.exe              Quick scan (default paths only)
  ChrysalisChecker.exe -checkall    Full scan of C: and D: drives
  ChrysalisChecker.exe -checkall -drives C E F   Scan specific drives

Options:
  -checkall     Perform full hash scan of all files on specified drives
  -drives       Drives to scan when using -checkall (default: C D)
  -h, --help    Show this help message

Based on Rapid7 research:
https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
");
    }

    private static void PrintBanner()
    {
        Console.WriteLine($@"
{Colors.Blue}+======================================================================+
|     Chrysalis Backdoor IOC Checker                                   |
|     Based on Rapid7 Threat Research                                  |
+======================================================================+{Colors.Reset}
");
    }

    private static bool IsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static int RunAllChecks()
    {
        PrintBanner();

        // Show scan mode
        if (_checkAll)
        {
            var existingDrives = _drives.Where(d => Directory.Exists($"{d}:\\")).ToArray();
            Console.WriteLine($"{Colors.Bold}[*] FULL SCAN MODE - Scanning drives: {string.Join(", ", existingDrives.Select(d => $"{d}:\\"))}{Colors.Reset}");
            Console.WriteLine($"{Colors.Yellow}    WARNING: This will scan ALL files and may take hours!{Colors.Reset}\n");
        }
        else
        {
            Console.WriteLine($"{Colors.Bold}[*] QUICK SCAN MODE - Scanning common paths only{Colors.Reset}");
            Console.WriteLine("    Use -checkall for comprehensive drive scan\n");
        }

        // Check for admin privileges
        if (IsAdmin())
        {
            Console.WriteLine($"{Colors.Green}[+] Running with administrator privileges{Colors.Reset}");
        }
        else
        {
            Console.WriteLine($"{Colors.Yellow}[!] Running without administrator privileges - some checks may be limited{Colors.Reset}");
            Console.WriteLine("    Consider running as Administrator for complete scan\n");
        }

        var allFindings = new List<string>();

        // Run all checks
        var (mutexFound, mutexMsg) = CheckMutex();
        if (mutexFound)
        {
            allFindings.Add(mutexMsg);
        }
        else
        {
            Console.WriteLine($"  [OK] {mutexMsg}");
        }

        allFindings.AddRange(CheckSuspiciousPaths());
        allFindings.AddRange(CheckNetworkConnections());
        allFindings.AddRange(CheckDnsResolution());
        allFindings.AddRange(CheckRegistry());
        allFindings.AddRange(CheckServices());
        allFindings.AddRange(CheckProcesses());
        allFindings.AddRange(CheckHostsFile());

        // File hash scanning
        if (_checkAll)
        {
            var searchPaths = _drives
                .Where(d => Directory.Exists($"{d}:\\"))
                .Select(d => $"{d}:\\")
                .ToArray();
            allFindings.AddRange(CheckFileHashes(searchPaths, checkAllHashes: true));
        }
        else
        {
            allFindings.AddRange(CheckFileHashes(null, checkAllHashes: false));
        }

        // Print summary
        PrintSummary(allFindings);

        return allFindings.Count;
    }

    private static void PrintSummary(List<string> allFindings)
    {
        Console.WriteLine($"\n{Colors.Bold}{new string('=', 70)}{Colors.Reset}");
        Console.WriteLine($"{Colors.Bold}SCAN SUMMARY{Colors.Reset}");
        Console.WriteLine(new string('=', 70));

        if (allFindings.Count > 0)
        {
            Console.WriteLine($"\n{Colors.Red}[!] POTENTIAL INDICATORS FOUND:{Colors.Reset}\n");
            foreach (var finding in allFindings)
            {
                if (finding.StartsWith("ALERT") || finding.StartsWith("MALICIOUS"))
                {
                    Console.WriteLine($"  {Colors.Red}[!] {finding}{Colors.Reset}");
                }
                else if (finding.StartsWith("SUSPICIOUS"))
                {
                    Console.WriteLine($"  {Colors.Yellow}[?] {finding}{Colors.Reset}");
                }
                else if (finding.StartsWith("WARNING"))
                {
                    Console.WriteLine($"  {Colors.Yellow}[!] {finding}{Colors.Reset}");
                }
                else
                {
                    Console.WriteLine($"  [*] {finding}");
                }
            }

            Console.WriteLine($"\n{Colors.Yellow}[!] Review the findings above carefully.{Colors.Reset}");
            Console.WriteLine($"{Colors.Yellow}    If you suspect compromise, consider:{Colors.Reset}");
            Console.WriteLine("    1. Disconnecting from the network");
            Console.WriteLine("    2. Running a full antivirus scan");
            Console.WriteLine("    3. Consulting with a security professional");
            Console.WriteLine("    4. Preserving evidence for forensic analysis");

            if (!_checkAll)
            {
                Console.WriteLine($"\n{Colors.Blue}[i] For a more thorough scan, run with these options:{Colors.Reset}");
                Console.WriteLine("    ChrysalisChecker.exe -checkall");
                Console.WriteLine("    ChrysalisChecker.exe -checkall -drives C D E");
                Console.WriteLine("    This will check ALL file hashes on the specified drives.");
            }
        }
        else
        {
            Console.WriteLine($"\n{Colors.Green}[+] NO INDICATORS OF COMPROMISE DETECTED{Colors.Reset}");
            Console.WriteLine("    Your system appears clean based on known Chrysalis IOCs.");
            Console.WriteLine("    Note: This does not guarantee absence of other malware.");

            if (!_checkAll)
            {
                Console.WriteLine($"\n{Colors.Blue}[i] This was a quick scan. For comprehensive detection, run:{Colors.Reset}");
                Console.WriteLine("    ChrysalisChecker.exe -checkall");
                Console.WriteLine("    ChrysalisChecker.exe -checkall -drives C D E");
            }
        }

        Console.WriteLine($"\n{new string('=', 70)}\n");
    }

    #region Check Methods

    private static (bool found, string message) CheckMutex()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking for Chrysalis mutex...{Colors.Reset}");

        try
        {
            IntPtr handle = OpenMutex(MUTEX_ALL_ACCESS, false, MutexName);
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                return (true, $"FOUND: Mutex '{MutexName}' exists!");
            }
            return (false, $"Mutex '{MutexName}' not found (clean)");
        }
        catch (Exception ex)
        {
            return (false, $"Could not check mutex: {ex.Message}");
        }
    }

    private static List<string> CheckSuspiciousPaths()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking for suspicious paths...{Colors.Reset}");

        var findings = new List<string>();

        foreach (var path in SuspiciousPaths)
        {
            if (Directory.Exists(path))
            {
                try
                {
                    var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
                    if (files.Length > 0)
                    {
                        findings.Add($"SUSPICIOUS: Directory '{path}' exists with {files.Length} file(s)");
                        foreach (var file in files.Take(10))
                        {
                            findings.Add($"  - {file}");
                        }
                    }
                    else
                    {
                        findings.Add($"INFO: Directory '{path}' exists but is empty");
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    findings.Add($"WARNING: Cannot access '{path}' (permission denied)");
                }
            }
            else
            {
                Console.WriteLine($"  [OK] {path} - not found");
            }
        }

        return findings;
    }

    private static List<string> CheckNetworkConnections()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking network connections for C2 indicators...{Colors.Reset}");

        var findings = new List<string>();

        try
        {
            var psi = new ProcessStartInfo("netstat", "-an")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(30000);

                foreach (var ip in C2IPs)
                {
                    if (output.Contains(ip))
                    {
                        findings.Add($"ALERT: Active connection to C2 IP: {ip}");
                    }
                }
            }

            // Check DNS cache
            try
            {
                var dnsPsi = new ProcessStartInfo("ipconfig", "/displaydns")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var dnsProcess = Process.Start(dnsPsi);
                if (dnsProcess != null)
                {
                    string dnsOutput = dnsProcess.StandardOutput.ReadToEnd().ToLower();
                    dnsProcess.WaitForExit(30000);

                    foreach (var domain in C2Domains)
                    {
                        if (dnsOutput.Contains(domain.ToLower()))
                        {
                            findings.Add($"ALERT: C2 domain found in DNS cache: {domain}");
                        }
                    }
                }
            }
            catch
            {
                findings.Add("WARNING: DNS cache check failed");
            }
        }
        catch (Exception ex)
        {
            findings.Add($"WARNING: Could not check network connections: {ex.Message}");
        }

        if (findings.Count == 0)
        {
            Console.WriteLine("  [OK] No connections to known C2 infrastructure detected");
        }

        return findings;
    }

    private static List<string> CheckDnsResolution()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking C2 domain resolution...{Colors.Reset}");

        var findings = new List<string>();

        foreach (var domain in C2Domains)
        {
            try
            {
                var addresses = Dns.GetHostAddresses(domain);
                if (addresses.Length > 0)
                {
                    findings.Add($"WARNING: C2 domain '{domain}' resolves to {addresses[0]}");
                }
            }
            catch (SocketException)
            {
                Console.WriteLine($"  [OK] {domain} - does not resolve");
            }
            catch (Exception ex)
            {
                findings.Add($"INFO: Could not check {domain}: {ex.Message}");
            }
        }

        return findings;
    }

    private static List<string> CheckRegistry()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking registry for persistence...{Colors.Reset}");

        var findings = new List<string>();

        var registryChecks = new (RegistryKey hive, string subkey)[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        };

        string[] suspiciousKeywords = { "bluetooth", "bluet", "log.dll", "libtcc", "chrysalis" };

        foreach (var (hive, subkey) in registryChecks)
        {
            try
            {
                using var key = hive.OpenSubKey(subkey);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? "";
                        var valueNameLower = valueName.ToLower();
                        var valueLower = value.ToLower();

                        foreach (var keyword in suspiciousKeywords)
                        {
                            if (valueNameLower.Contains(keyword) || valueLower.Contains(keyword))
                            {
                                findings.Add($"SUSPICIOUS REGISTRY: {subkey}\\{valueName} = {value}");
                                break;
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                findings.Add($"WARNING: Cannot access registry key: {subkey}");
            }
            catch (Exception ex)
            {
                findings.Add($"INFO: Error checking {subkey}: {ex.Message}");
            }
        }

        if (findings.Count == 0)
        {
            Console.WriteLine("  [OK] No suspicious registry entries found");
        }

        return findings;
    }

    private static List<string> CheckServices()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking Windows services...{Colors.Reset}");

        var findings = new List<string>();

        try
        {
            var psi = new ProcessStartInfo("sc", "query type= service state= all")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                string output = process.StandardOutput.ReadToEnd().ToLower();
                process.WaitForExit(30000);

                string[] suspiciousNames = { "bluetoothservice", "bluetooth_service", "btservice" };
                foreach (var name in suspiciousNames)
                {
                    if (output.Contains(name))
                    {
                        findings.Add($"SUSPICIOUS SERVICE: Found service matching '{name}'");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            findings.Add($"WARNING: Could not check services: {ex.Message}");
        }

        if (findings.Count == 0)
        {
            Console.WriteLine("  [OK] No suspicious services found");
        }

        return findings;
    }

    private static List<string> CheckProcesses()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking running processes...{Colors.Reset}");

        var findings = new List<string>();

        try
        {
            var processes = Process.GetProcesses();
            string[] suspiciousProcesses = { "bluetoothservice", "consoleapplication2", "update" };

            foreach (var proc in processes)
            {
                try
                {
                    string procName = proc.ProcessName.ToLower();
                    foreach (var suspicious in suspiciousProcesses)
                    {
                        if (procName.Contains(suspicious))
                        {
                            findings.Add($"SUSPICIOUS PROCESS: '{proc.ProcessName}' is running (PID: {proc.Id})");
                        }
                    }
                }
                catch
                {
                    // Skip processes we can't access
                }
            }
        }
        catch (Exception ex)
        {
            findings.Add($"WARNING: Could not check processes: {ex.Message}");
        }

        if (findings.Count == 0)
        {
            Console.WriteLine("  [OK] No suspicious processes found");
        }

        return findings;
    }

    private static List<string> CheckHostsFile()
    {
        Console.WriteLine($"\n{Colors.Bold}[*] Checking hosts file...{Colors.Reset}");

        var findings = new List<string>();
        string hostsPath = @"C:\Windows\System32\drivers\etc\hosts";

        try
        {
            string content = File.ReadAllText(hostsPath).ToLower();

            foreach (var domain in C2Domains)
            {
                if (content.Contains(domain.ToLower()))
                {
                    findings.Add($"SUSPICIOUS: C2 domain '{domain}' found in hosts file");
                }
            }
        }
        catch (Exception ex)
        {
            findings.Add($"WARNING: Could not check hosts file: {ex.Message}");
        }

        if (findings.Count == 0)
        {
            Console.WriteLine("  [OK] No C2 domains in hosts file");
        }

        return findings;
    }

    private static List<string> CheckFileHashes(string[]? searchPaths, bool checkAllHashes)
    {
        if (checkAllHashes)
        {
            Console.WriteLine($"\n{Colors.Bold}[*] FULL HASH SCAN - Scanning ALL files for malicious hashes...{Colors.Reset}");
            Console.WriteLine($"    {Colors.Yellow}This will take a long time. Press Ctrl+C to abort.{Colors.Reset}");
        }
        else
        {
            Console.WriteLine($"\n{Colors.Bold}[*] Scanning files for malicious hashes...{Colors.Reset}");
        }

        searchPaths ??= new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        var findings = new ConcurrentBag<string>();
        long scanned = 0;
        long hashed = 0;
        var startTime = DateTime.Now;
        var lastProgressTime = DateTime.Now;
        var lockObj = new object();

        foreach (var searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath))
                continue;

            Console.WriteLine($"  Scanning: {searchPath}");

            long pathScanned = 0;
            long pathHashed = 0;
            int dirsVisited = 0;

            try
            {
                var options = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = false,
                };

                var dirsToProcess = new Queue<string>();
                dirsToProcess.Enqueue(searchPath);

                while (dirsToProcess.Count > 0)
                {
                    var currentDir = dirsToProcess.Dequeue();
                    dirsVisited++;

                    // Show progress every 2 seconds
                    var now = DateTime.Now;
                    if ((now - lastProgressTime).TotalSeconds >= 2)
                    {
                        string displayPath = currentDir.Length > 60
                            ? "..." + currentDir.Substring(currentDir.Length - 57)
                            : currentDir;
                        Console.WriteLine($"    Enumerating: {dirsVisited:N0} dirs, {pathScanned:N0} files scanned, " +
                                        $"{pathHashed:N0} hashed | {displayPath}");
                        lastProgressTime = now;
                    }

                    // Add subdirectories
                    try
                    {
                        foreach (var subDir in Directory.GetDirectories(currentDir))
                        {
                            var dirName = Path.GetFileName(subDir);
                            if (!SkipDirectories.Contains(dirName))
                            {
                                dirsToProcess.Enqueue(subDir);
                            }
                        }
                    }
                    catch { }

                    // Process files in current directory
                    string[] files;
                    try
                    {
                        files = Directory.GetFiles(currentDir);
                    }
                    catch
                    {
                        continue;
                    }

                    // Process files in parallel batches
                    Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 8 }, filePath =>
                    {
                        try
                        {
                            var fileName = Path.GetFileName(filePath);
                            Interlocked.Increment(ref pathScanned);

                            // Check suspicious filenames
                            if (MaliciousFilenames.Contains(fileName))
                            {
                                findings.Add($"SUSPICIOUS FILENAME: {filePath}");
                                var hash = CalculateSha256(filePath);
                                if (!string.IsNullOrEmpty(hash))
                                {
                                    Interlocked.Increment(ref pathHashed);
                                    if (MaliciousHashes.TryGetValue(hash, out var malwareName))
                                    {
                                        findings.Add($"  MALICIOUS HASH MATCH: {malwareName}");
                                        Console.WriteLine($"    {Colors.Red}>>> FOUND: MALICIOUS HASH MATCH: {malwareName} at {filePath}{Colors.Reset}");
                                    }
                                }
                            }
                            else if (checkAllHashes)
                            {
                                var ext = Path.GetExtension(filePath);
                                if (!SkipExtensions.Contains(ext))
                                {
                                    try
                                    {
                                        var fileInfo = new FileInfo(filePath);
                                        if (fileInfo.Length > 0 && fileInfo.Length <= MaxFileSize)
                                        {
                                            var hash = CalculateSha256(filePath);
                                            if (!string.IsNullOrEmpty(hash))
                                            {
                                                Interlocked.Increment(ref pathHashed);
                                                if (MaliciousHashes.TryGetValue(hash, out var malwareName))
                                                {
                                                    findings.Add($"MALICIOUS HASH MATCH: {filePath}");
                                                    findings.Add($"  Identified as: {malwareName}");
                                                    Console.WriteLine($"    {Colors.Red}>>> FOUND: {malwareName} at {filePath}{Colors.Reset}");
                                                }
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch { }
                    });
                }

                Console.WriteLine($"    Completed {searchPath}: {pathScanned:N0} files, {pathHashed:N0} hashed");
                Interlocked.Add(ref scanned, pathScanned);
                Interlocked.Add(ref hashed, pathHashed);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Error scanning {searchPath}: {ex.Message}");
            }
        }

        var elapsed = DateTime.Now - startTime;
        Console.WriteLine($"  Total files scanned: {scanned:N0}");
        Console.WriteLine($"  Total files hashed: {hashed:N0}");
        Console.WriteLine($"  Scan duration: {elapsed.TotalSeconds:F1} seconds");

        return findings.ToList();
    }

    private static string CalculateSha256(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
        catch
        {
            return string.Empty;
        }
    }

    #endregion
}
