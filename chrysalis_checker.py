#!/usr/bin/env python3
"""
Chrysalis Backdoor Indicator of Compromise (IOC) Checker
Based on Rapid7 research: https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/

This script checks for indicators of the Chrysalis backdoor on Windows systems.
Run with administrator privileges for complete checks.

Usage:
    python chrysalis_checker.py              # Quick scan (default paths only)
    python chrysalis_checker.py -checkall    # Full scan of C: and D: drives
"""

import os
import hashlib
import subprocess
import socket
import winreg
import ctypes
import argparse
import time
import sys
from pathlib import Path
from typing import List, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ============================================================================
# INDICATORS OF COMPROMISE
# ============================================================================

# SHA-256 hashes of known malicious files
MALICIOUS_HASHES = {
    "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9": "update.exe",
    "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e": "[NSIS].nsi",
    "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924": "BluetoothService.exe",
    "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e": "BluetoothService",
    "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad": "log.dll",
    "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600": "u.bat",
    "f4d829739f2d6ba7e3ede83dad428a0ceda1a703ec582fc73a4eee3df3704629a": "conf.c",
    "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906": "libtcc.dll",
    "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd": "Loader 1",
    "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda": "Loader 2",
    "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3": "ConsoleApplication2.exe",
    "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a": "Loader 4",
    # Shellcode hashes
    "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8": "Shellcode 1",
    "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5": "Shellcode 2",
    "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd": "Shellcode 3",
}

# Malicious file names to search for
MALICIOUS_FILENAMES = {
    "BluetoothService.exe",
    "log.dll",
    "libtcc.dll",
    "update.exe",
    "u.bat",
    "conf.c",
    "ConsoleApplication2.exe",
}

# C2 domains
C2_DOMAINS = {
    "api.skycloudcenter.com",
    "api.wiresguard.com",
}

# C2 IP addresses
C2_IPS = {
    "95.179.213.0",
    "61.4.102.97",
    "59.110.7.32",
    "124.222.137.114",
}

# Suspicious paths used by the malware
SUSPICIOUS_PATHS = [
    os.path.expandvars(r"%AppData%\Bluetooth"),
    r"C:\ProgramData\USOShared",
]

# Mutex name used by the backdoor
MUTEX_NAME = r"Global\Jdhfv_1.0.1"


class Colors:
    """ANSI color codes for terminal output"""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_banner():
    """Print the script banner"""
    print(f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════════╗
║     Chrysalis Backdoor IOC Checker                                ║
║     Based on Rapid7 Threat Research                               ║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def is_admin() -> bool:
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def calculate_sha256(filepath: str) -> str:
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, PermissionError):
        return ""


def check_mutex() -> Tuple[bool, str]:
    """Check if the Chrysalis mutex exists"""
    print(f"\n{Colors.BOLD}[*] Checking for Chrysalis mutex...{Colors.RESET}")

    try:
        # Try to open the mutex
        kernel32 = ctypes.windll.kernel32
        MUTEX_ALL_ACCESS = 0x1F0001

        handle = kernel32.OpenMutexW(MUTEX_ALL_ACCESS, False, MUTEX_NAME)
        if handle:
            kernel32.CloseHandle(handle)
            return True, f"FOUND: Mutex '{MUTEX_NAME}' exists!"
        return False, f"Mutex '{MUTEX_NAME}' not found (clean)"
    except Exception as e:
        return False, f"Could not check mutex: {e}"


def check_suspicious_paths() -> List[str]:
    """Check for suspicious directories used by Chrysalis"""
    print(f"\n{Colors.BOLD}[*] Checking for suspicious paths...{Colors.RESET}")

    findings = []
    for path in SUSPICIOUS_PATHS:
        if os.path.exists(path):
            # Check if directory contains files
            try:
                files = list(Path(path).rglob("*"))
                if files:
                    findings.append(f"SUSPICIOUS: Directory '{path}' exists with {len(files)} file(s)")
                    for f in files[:10]:  # Show first 10 files
                        findings.append(f"  - {f}")
                else:
                    findings.append(f"INFO: Directory '{path}' exists but is empty")
            except PermissionError:
                findings.append(f"WARNING: Cannot access '{path}' (permission denied)")
        else:
            print(f"  [OK] {path} - not found")

    return findings


def check_file_hashes(search_paths: List[str] = None, check_all_hashes: bool = False) -> List[str]:
    """Scan files and compare hashes against known malicious hashes

    Args:
        search_paths: List of paths to scan. If None, uses default paths.
        check_all_hashes: If True, calculates hash for EVERY file (slow but thorough).
                         If False, only hashes files with suspicious names.
    """
    if check_all_hashes:
        print(f"\n{Colors.BOLD}[*] FULL HASH SCAN - Scanning ALL files for malicious hashes...{Colors.RESET}")
        print(f"    {Colors.YELLOW}This will take a long time. Press Ctrl+C to abort.{Colors.RESET}")
    else:
        print(f"\n{Colors.BOLD}[*] Scanning files for malicious hashes...{Colors.RESET}")

    if search_paths is None:
        search_paths = [
            os.path.expandvars(r"%AppData%"),
            os.path.expandvars(r"%LocalAppData%"),
            os.path.expandvars(r"%ProgramData%"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%SystemRoot%\Temp"),
        ]

    findings = []
    findings_lock = Lock()
    scanned = 0
    hashed = 0
    scanned_lock = Lock()
    start_time = time.time()

    # File extensions to skip when doing full hash scan (large/binary files unlikely to be malware payloads)
    SKIP_EXTENSIONS = {
        '.iso', '.wim', '.vhd', '.vhdx', '.vmdk', '.ova', '.ovf',
        '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        '.msi', '.cab',
        '.psd', '.ai', '.indd',
        '.bak', '.old', '.tmp',
    }

    # Max file size to hash (50MB) - larger files are unlikely to be the backdoor
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def process_file(filepath: str, filename: str) -> Tuple[int, int, List[str]]:
        """Process a single file, return (scanned_count, hashed_count, findings)"""
        local_findings = []
        was_hashed = 0

        try:
            # Always check for suspicious filenames
            if filename in MALICIOUS_FILENAMES:
                local_findings.append(f"SUSPICIOUS FILENAME: {filepath}")
                file_hash = calculate_sha256(filepath)
                was_hashed = 1
                if file_hash and file_hash in MALICIOUS_HASHES:
                    local_findings.append(f"  MALICIOUS HASH MATCH: {MALICIOUS_HASHES[file_hash]}")

            # If full scan, hash everything (with size/extension filters)
            elif check_all_hashes:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SKIP_EXTENSIONS:
                    try:
                        file_size = os.path.getsize(filepath)
                        if file_size <= MAX_FILE_SIZE and file_size > 0:
                            file_hash = calculate_sha256(filepath)
                            was_hashed = 1
                            if file_hash and file_hash in MALICIOUS_HASHES:
                                local_findings.append(f"MALICIOUS HASH MATCH: {filepath}")
                                local_findings.append(f"  Identified as: {MALICIOUS_HASHES[file_hash]}")
                    except (OSError, IOError):
                        pass

        except (PermissionError, OSError):
            pass

        return (1, was_hashed, local_findings)

    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue

        print(f"  Scanning: {search_path}")
        path_scanned = 0
        path_hashed = 0
        dirs_visited = 0
        last_progress_time = time.time()
        current_dir = ""

        try:
            # Process files in batches as we find them (streaming approach)
            BATCH_SIZE = 500
            file_batch = []

            with ThreadPoolExecutor(max_workers=8) as executor:
                for root, dirs, files in os.walk(search_path):
                    # Skip certain system directories to speed up scan
                    dirs[:] = [d for d in dirs if d.lower() not in {
                        '$recycle.bin', 'system volume information',
                        'windows.old', 'recovery'
                    }]

                    dirs_visited += 1
                    current_dir = root

                    # Show enumeration progress every 2 seconds
                    now = time.time()
                    if now - last_progress_time >= 2:
                        elapsed = now - start_time
                        # Truncate path for display
                        display_path = current_dir
                        if len(display_path) > 60:
                            display_path = "..." + display_path[-57:]
                        print(f"    Enumerating: {dirs_visited:,} dirs, {path_scanned:,} files scanned, "
                              f"{path_hashed:,} hashed | {display_path}")
                        last_progress_time = now

                    for filename in files:
                        filepath = os.path.join(root, filename)
                        file_batch.append((filepath, filename))

                        # Process batch when full
                        if len(file_batch) >= BATCH_SIZE:
                            futures = [executor.submit(process_file, fp, fn) for fp, fn in file_batch]
                            for future in as_completed(futures):
                                try:
                                    scan_count, hash_count, file_findings = future.result()
                                    path_scanned += scan_count
                                    path_hashed += hash_count
                                    if file_findings:
                                        with findings_lock:
                                            findings.extend(file_findings)
                                            # Print findings immediately
                                            for f in file_findings:
                                                print(f"    {Colors.RED}>>> FOUND: {f}{Colors.RESET}")
                                except Exception:
                                    pass
                            file_batch = []

                # Process remaining files in batch
                if file_batch:
                    futures = [executor.submit(process_file, fp, fn) for fp, fn in file_batch]
                    for future in as_completed(futures):
                        try:
                            scan_count, hash_count, file_findings = future.result()
                            path_scanned += scan_count
                            path_hashed += hash_count
                            if file_findings:
                                with findings_lock:
                                    findings.extend(file_findings)
                                    for f in file_findings:
                                        print(f"    {Colors.RED}>>> FOUND: {f}{Colors.RESET}")
                        except Exception:
                            pass

        except PermissionError:
            continue
        except Exception as e:
            print(f"    Error scanning {search_path}: {e}")
            continue

        print(f"    Completed {search_path}: {path_scanned:,} files, {path_hashed:,} hashed")
        scanned += path_scanned
        hashed += path_hashed

    elapsed = time.time() - start_time
    print(f"  Total files scanned: {scanned:,}")
    print(f"  Total files hashed: {hashed:,}")
    print(f"  Scan duration: {elapsed:.1f} seconds")

    return findings


def check_network_connections() -> List[str]:
    """Check active network connections for C2 indicators"""
    print(f"\n{Colors.BOLD}[*] Checking network connections for C2 indicators...{Colors.RESET}")

    findings = []

    try:
        # Use netstat to get connections
        result = subprocess.run(
            ["netstat", "-an"],
            capture_output=True,
            text=True,
            timeout=30
        )

        connections = result.stdout.lower()

        for ip in C2_IPS:
            if ip in connections:
                findings.append(f"ALERT: Active connection to C2 IP: {ip}")

        # Check DNS cache for C2 domains
        try:
            dns_result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=30
            )

            dns_cache = dns_result.stdout.lower()
            for domain in C2_DOMAINS:
                if domain.lower() in dns_cache:
                    findings.append(f"ALERT: C2 domain found in DNS cache: {domain}")

        except subprocess.TimeoutExpired:
            findings.append("WARNING: DNS cache check timed out")

    except subprocess.TimeoutExpired:
        findings.append("WARNING: Network check timed out")
    except Exception as e:
        findings.append(f"WARNING: Could not check network connections: {e}")

    if not findings:
        print(f"  [OK] No connections to known C2 infrastructure detected")

    return findings


def check_dns_resolution() -> List[str]:
    """Check if C2 domains resolve (could indicate compromise)"""
    print(f"\n{Colors.BOLD}[*] Checking C2 domain resolution...{Colors.RESET}")

    findings = []

    for domain in C2_DOMAINS:
        try:
            ip = socket.gethostbyname(domain)
            findings.append(f"WARNING: C2 domain '{domain}' resolves to {ip}")
        except socket.gaierror:
            print(f"  [OK] {domain} - does not resolve")
        except Exception as e:
            findings.append(f"INFO: Could not check {domain}: {e}")

    return findings


def check_registry() -> List[str]:
    """Check registry for persistence indicators"""
    print(f"\n{Colors.BOLD}[*] Checking registry for persistence...{Colors.RESET}")

    findings = []

    # Registry paths commonly used for persistence
    registry_checks = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
    ]

    suspicious_keywords = ["bluetooth", "bluet", "log.dll", "libtcc", "chrysalis"]

    for hive, subkey in registry_checks:
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)

            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        value_str = str(value).lower()
                        name_lower = name.lower()

                        for keyword in suspicious_keywords:
                            if keyword in value_str or keyword in name_lower:
                                findings.append(f"SUSPICIOUS REGISTRY: {subkey}\\{name} = {value}")
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

        except PermissionError:
            findings.append(f"WARNING: Cannot access registry key: {subkey}")
        except FileNotFoundError:
            pass
        except Exception as e:
            findings.append(f"INFO: Error checking {subkey}: {e}")

    if not findings:
        print(f"  [OK] No suspicious registry entries found")

    return findings


def check_services() -> List[str]:
    """Check for suspicious services"""
    print(f"\n{Colors.BOLD}[*] Checking Windows services...{Colors.RESET}")

    findings = []

    try:
        result = subprocess.run(
            ["sc", "query", "type=", "service", "state=", "all"],
            capture_output=True,
            text=True,
            timeout=30
        )

        services_output = result.stdout.lower()

        suspicious_names = ["bluetoothservice", "bluetooth_service", "btservice"]
        for name in suspicious_names:
            if name in services_output:
                findings.append(f"SUSPICIOUS SERVICE: Found service matching '{name}'")

    except Exception as e:
        findings.append(f"WARNING: Could not check services: {e}")

    if not findings:
        print(f"  [OK] No suspicious services found")

    return findings


def check_processes() -> List[str]:
    """Check running processes for indicators"""
    print(f"\n{Colors.BOLD}[*] Checking running processes...{Colors.RESET}")

    findings = []

    try:
        result = subprocess.run(
            ["tasklist", "/v"],
            capture_output=True,
            text=True,
            timeout=30
        )

        processes = result.stdout.lower()

        suspicious_processes = [
            "bluetoothservice.exe",
            "consoleapplication2.exe",
            "update.exe"  # This is common, but flag for review
        ]

        for proc in suspicious_processes:
            if proc in processes:
                findings.append(f"SUSPICIOUS PROCESS: '{proc}' is running")

    except Exception as e:
        findings.append(f"WARNING: Could not check processes: {e}")

    if not findings:
        print(f"  [OK] No suspicious processes found")

    return findings


def check_hosts_file() -> List[str]:
    """Check hosts file for C2-related entries"""
    print(f"\n{Colors.BOLD}[*] Checking hosts file...{Colors.RESET}")

    findings = []
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

    try:
        with open(hosts_path, 'r') as f:
            content = f.read().lower()

        for domain in C2_DOMAINS:
            if domain.lower() in content:
                findings.append(f"SUSPICIOUS: C2 domain '{domain}' found in hosts file")

    except Exception as e:
        findings.append(f"WARNING: Could not check hosts file: {e}")

    if not findings:
        print(f"  [OK] No C2 domains in hosts file")

    return findings


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Chrysalis Backdoor IOC Checker - Detect indicators of the Lotus Blossom backdoor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python chrysalis_checker.py              # Quick scan (default paths)
  python chrysalis_checker.py -checkall    # Full scan of C: and D: drives
  python chrysalis_checker.py -checkall -drives C E F  # Scan specific drives

Based on Rapid7 research:
https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
        """
    )

    parser.add_argument(
        '-checkall', '--checkall',
        action='store_true',
        help='Perform full hash scan of all files on drives C: and D: (slow but thorough)'
    )

    parser.add_argument(
        '-drives', '--drives',
        nargs='+',
        default=['C', 'D'],
        help='Drives to scan when using -checkall (default: C D)'
    )

    return parser.parse_args()


def main():
    """Main function to run all checks"""
    args = parse_arguments()

    print_banner()

    # Show scan mode
    if args.checkall:
        drives = [f"{d}:\\" for d in args.drives if os.path.exists(f"{d}:\\")]
        print(f"{Colors.BOLD}[*] FULL SCAN MODE - Scanning drives: {', '.join(drives)}{Colors.RESET}")
        print(f"{Colors.YELLOW}    WARNING: This will scan ALL files and may take hours!{Colors.RESET}\n")
    else:
        print(f"{Colors.BOLD}[*] QUICK SCAN MODE - Scanning common paths only{Colors.RESET}")
        print(f"    Use -checkall for comprehensive drive scan\n")

    # Check for admin privileges
    if is_admin():
        print(f"{Colors.GREEN}[+] Running with administrator privileges{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Running without administrator privileges - some checks may be limited{Colors.RESET}")
        print(f"    Consider running as Administrator for complete scan\n")

    all_findings = []

    # Run all checks
    mutex_found, mutex_msg = check_mutex()
    if mutex_found:
        all_findings.append(mutex_msg)
    else:
        print(f"  [OK] {mutex_msg}")

    all_findings.extend(check_suspicious_paths())
    all_findings.extend(check_network_connections())
    all_findings.extend(check_dns_resolution())
    all_findings.extend(check_registry())
    all_findings.extend(check_services())
    all_findings.extend(check_processes())
    all_findings.extend(check_hosts_file())

    # File hash scanning - different modes
    if args.checkall:
        # Full drive scan
        search_paths = [f"{d}:\\" for d in args.drives if os.path.exists(f"{d}:\\")]
        all_findings.extend(check_file_hashes(search_paths=search_paths, check_all_hashes=True))
    else:
        # Quick scan - default paths only
        all_findings.extend(check_file_hashes(check_all_hashes=False))

    # Print summary
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
    print(f"{'='*70}")

    if all_findings:
        print(f"\n{Colors.RED}[!] POTENTIAL INDICATORS FOUND:{Colors.RESET}\n")
        for finding in all_findings:
            if finding.startswith("ALERT") or finding.startswith("MALICIOUS"):
                print(f"  {Colors.RED}[!] {finding}{Colors.RESET}")
            elif finding.startswith("SUSPICIOUS"):
                print(f"  {Colors.YELLOW}[?] {finding}{Colors.RESET}")
            elif finding.startswith("WARNING"):
                print(f"  {Colors.YELLOW}[!] {finding}{Colors.RESET}")
            else:
                print(f"  [*] {finding}")

        print(f"\n{Colors.YELLOW}[!] Review the findings above carefully.{Colors.RESET}")
        print(f"{Colors.YELLOW}    If you suspect compromise, consider:{Colors.RESET}")
        print(f"    1. Disconnecting from the network")
        print(f"    2. Running a full antivirus scan")
        print(f"    3. Consulting with a security professional")
        print(f"    4. Preserving evidence for forensic analysis")

        # Suggest full scan if this was a quick scan
        if not args.checkall:
            print(f"\n{Colors.BLUE}[i] For a more thorough scan, run with these options:{Colors.RESET}")
            print(f"    python chrysalis_checker.py -checkall")
            print(f"    python chrysalis_checker.py -checkall -drives C D E")
            print(f"    This will check ALL file hashes on the specified drives.")
    else:
        print(f"\n{Colors.GREEN}[+] NO INDICATORS OF COMPROMISE DETECTED{Colors.RESET}")
        print(f"    Your system appears clean based on known Chrysalis IOCs.")
        print(f"    Note: This does not guarantee absence of other malware.")

        # Suggest full scan if this was a quick scan
        if not args.checkall:
            print(f"\n{Colors.BLUE}[i] This was a quick scan. For comprehensive detection, run:{Colors.RESET}")
            print(f"    python chrysalis_checker.py -checkall")
            print(f"    python chrysalis_checker.py -checkall -drives C D E")

    print(f"\n{'='*70}\n")

    return len(all_findings)


if __name__ == "__main__":
    try:
        exit_code = main()
        input("Press Enter to exit...")
        exit(1 if exit_code > 0 else 0)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
        exit(1)
