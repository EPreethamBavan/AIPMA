import argparse
import ipaddress
import json
import subprocess
import sys
from collections import defaultdict

import requests


class VolatilityPluginRunner:
    """
    Class to handle running Volatility 3 plugins and processing their output.
    """

    def __init__(self):
        self.volatility_output_cache = {}
        self.current_file_path = None

    def run_volatility_plugin(self, plugin_name):
        if not self.current_file_path:
            print("Error: No memory image file specified.")
            return None
        if plugin_name in self.volatility_output_cache:
            return self.volatility_output_cache[plugin_name]

        print(f"Running Volatility plugin: {plugin_name}...")
        result = None
        try:
            command = [
                "vol",
                "-f",
                self.current_file_path,
                "--renderer",
                "json",
                plugin_name,
            ]
            creationflags = (
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                creationflags=creationflags,
            )
            if not result.stdout:
                raise ValueError("Volatility produced no output.")

            parsed_json = json.loads(result.stdout)
            self.volatility_output_cache[plugin_name] = parsed_json
            return parsed_json
        except FileNotFoundError:
            print(
                "Error: The 'vol' command was not found. Is Volatility 3 installed and in your PATH?"
            )
            return None
        except subprocess.CalledProcessError as e:
            print(
                f"Volatility failed with exit code {e.returncode}.\nStderr:\n{e.stderr}"
            )
            return None
        except (json.JSONDecodeError, ValueError) as e:
            print(
                f"Failed to parse Volatility output.\nError: {e}\nRaw Output:\n{result.stdout if result else 'No output'}"
            )
            return None

    def run_all_plugins(self, file_path):
        self.current_file_path = file_path
        plugin_map = {
            "Process List": "windows.pslist.PsList",
            "Network Connections": "windows.netscan.NetScan",
        }
        results = defaultdict(lambda: defaultdict(list))
        for option, plugin_name in plugin_map.items():
            data = self.run_volatility_plugin(plugin_name)
            if data:
                for row in data:
                    if "PID" in row:
                        results[row["PID"]][plugin_name].append(row)
        return results


def is_valid_ip(ip):
    """
    Validates if the input is a valid, globally routable IP address.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global and not ip_obj.is_multicast
    except ValueError:
        return False


def check_ip_abuseipdb(ip, api_key, confidence_threshold=90):
    """
    Checks an IP using AbuseIPDB. Returns a details dictionary if malicious,
    otherwise returns None.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        if score >= confidence_threshold:
            total_reports = data.get("totalReports", 0)
            isp = data.get("isp", "N/A")
            return {"score": score, "reports": total_reports, "isp": isp}

        return None
    except requests.RequestException as e:
        print(f"\nError querying AbuseIPDB for IP {ip}: {e}")
        return None


def analyze_parent_processes(results, pid_to_name, suspicious_pids):
    """
    Analyzes parent-child process relationships for anomalies, including checking for orphaned processes.
    """
    print("\nPerforming parent process verification analysis...")
    expected_parents = {
        "smss.exe": "System",
        "csrss.exe": "smss.exe",
        "wininit.exe": "smss.exe",
        "services.exe": "wininit.exe",
        "lsass.exe": "wininit.exe",
        "winlogon.exe": "smss.exe",
        "svchost.exe": "services.exe",
        "explorer.exe": "userinit.exe",
    }
    suspicious_parents = {
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    }

    for pid, proc_data in results.items():
        if "windows.pslist.PsList" in proc_data:
            proc_info = proc_data["windows.pslist.PsList"][0]
            name = proc_info.get("ImageFileName", "N/A")
            ppid = proc_info.get("PPID", "N/A")
            parent_name = pid_to_name.get(ppid)

            if ppid is not None and ppid != 0 and parent_name is None:
                parent_name_for_report = "Unknown (Parent PID not in list)"
                reason = f"Orphaned process. Parent with PID {ppid} is not in the process list."
                suspicious_pids[pid]["Info"] = {
                    "PID": pid,
                    "Name": name,
                    "PPID": ppid,
                    "Parent Name": parent_name_for_report,
                }
                suspicious_pids[pid]["Reasons"].append(reason)
            elif parent_name is None:
                parent_name = "N/A"

            if name in expected_parents and parent_name != expected_parents[name]:
                reason = f"Unexpected parent. Expected: '{expected_parents[name]}', Found: '{parent_name}'"
                suspicious_pids[pid]["Info"] = {
                    "PID": pid,
                    "Name": name,
                    "PPID": ppid,
                    "Parent Name": parent_name,
                }
                suspicious_pids[pid]["Reasons"].append(reason)

            if parent_name in suspicious_parents:
                reason = f"Spawned by a suspicious parent: '{parent_name}'"
                suspicious_pids[pid]["Info"] = {
                    "PID": pid,
                    "Name": name,
                    "PPID": ppid,
                    "Parent Name": parent_name,
                }
                suspicious_pids[pid]["Reasons"].append(reason)


def analyze_network_connections(results, pid_to_name, suspicious_pids, api_key):
    """Analyzes network connections for connections to malicious IPs using AbuseIPDB."""
    print("\nPerforming network destination analysis...")
    unique_foreign_ips = set()
    pid_to_foreign_ips = defaultdict(list)

    for pid, proc_data in results.items():
        if "windows.netscan.NetScan" in proc_data:
            for conn in proc_data["windows.netscan.NetScan"]:
                foreign_addr = conn.get("ForeignAddr")
                if not foreign_addr or foreign_addr == "*":
                    continue

                ip_part = ""
                if foreign_addr.startswith("["):
                    ip_part = foreign_addr.split("]")[0][1:]
                else:
                    ip_part = foreign_addr.rsplit(":", 1)[0]

                if is_valid_ip(ip_part):
                    unique_foreign_ips.add(ip_part)
                    pid_to_foreign_ips[pid].append(ip_part)

    if not unique_foreign_ips:
        print("No valid, routable foreign IPs found to query.")
        return

    total_ips = len(unique_foreign_ips)
    print(
        f"Found {total_ips} unique, routable IPs to query. Checking against AbuseIPDB..."
    )

    malicious_ip_details = {}
    checked_count = 0

    for ip in sorted(list(unique_foreign_ips)):
        checked_count += 1
        print(f"  -> Checking {checked_count}/{total_ips}: {ip.ljust(45)}", end="\r")

        details = check_ip_abuseipdb(ip, api_key)
        if details:
            print()
            print(
                f"[!] SUSPICIOUS IP FOUND: {ip} | Score: {details['score']} | Reports: {details['reports']} | ISP: {details['isp']}"
            )
            malicious_ip_details[ip] = details

    print(" " * 80, end="\r")
    print("IP reputation check complete.")

    suspicious_count = len(malicious_ip_details)
    print(f"  -> Summary: {suspicious_count}/{total_ips} suspicious IPs found.")

    if malicious_ip_details:
        for pid, ips in pid_to_foreign_ips.items():
            for ip in ips:
                if ip in malicious_ip_details:
                    details = malicious_ip_details[ip]
                    name = pid_to_name.get(pid, "N/A")
                    ppid = results[pid]["windows.pslist.PsList"][0].get("PPID", "N/A")
                    parent_name = pid_to_name.get(ppid, "Unknown")
                    reason = (
                        f"Connection to malicious IP: {ip} "
                        f"(Score: {details['score']}, Reports: {details['reports']})"
                    )
                    suspicious_pids[pid]["Info"] = {
                        "PID": pid,
                        "Name": name,
                        "PPID": ppid,
                        "Parent Name": parent_name,
                    }
                    suspicious_pids[pid]["Reasons"].append(reason)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a memory dump for suspicious processes and network activity using AbuseIPDB."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to the memory dump file."
    )
    parser.add_argument("-k", "--apikey", required=True, help="Your AbuseIPDB API key.")
    args = parser.parse_args()

    runner = VolatilityPluginRunner()
    results = runner.run_all_plugins(args.file)

    if not results:
        print("Could not retrieve any process data from the memory image. Exiting.")
        return

    pid_to_name = {
        pid: proc_data["windows.pslist.PsList"][0].get("ImageFileName", "N/A")
        for pid, proc_data in results.items()
        if "windows.pslist.PsList" in proc_data
    }
    pid_to_name[4] = "System"

    suspicious_pids = defaultdict(lambda: {"Info": {}, "Reasons": []})

    analyze_parent_processes(results, pid_to_name, suspicious_pids)
    analyze_network_connections(results, pid_to_name, suspicious_pids, args.apikey)

    print("\n--- Analysis Complete ---")
    print("\nSuspicious Processes Found:")
    if suspicious_pids:
        for pid, data in sorted(suspicious_pids.items()):
            if not data["Info"]:
                proc_data = results[pid]["windows.pslist.PsList"][0]
                name = proc_data.get("ImageFileName", "N/A")
                ppid = proc_data.get("PPID", "N/A")
                parent_name = pid_to_name.get(ppid, "Unknown")
                data["Info"] = {
                    "PID": pid,
                    "Name": name,
                    "PPID": ppid,
                    "Parent Name": parent_name,
                }
            print(json.dumps(data, indent=4))
    else:
        print("No suspicious processes detected based on the analyses.")


if __name__ == "__main__":
    main()
