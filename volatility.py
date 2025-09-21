import subprocess
import json
import sys
from collections import defaultdict
class VolatilityPluginRunner:
    """
    Class to handle running Volatility 3 plugins and processing their output.
    """
    def __init__(self):
        # Cache results to avoid re-running plugins
        self.volatility_output_cache = {}
        self.current_file_path = None

    def run_volatility_plugin(self, plugin_name):
        """
        Runs a Volatility 3 plugin and returns the parsed JSON output.
        """
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
                "-f", self.current_file_path,
                "--renderer", "json",
                plugin_name
            ]
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            result = subprocess.run(command, capture_output=True, text=True, check=True, creationflags=creationflags)
            
            if not result.stdout:
                raise ValueError("Volatility produced no output.")

            parsed_json = json.loads(result.stdout)
            self.volatility_output_cache[plugin_name] = parsed_json
            return parsed_json

        except FileNotFoundError:
            print("Error: The 'vol' command was not found. Is Volatility 3 installed and in your PATH?")
            return None
        except subprocess.CalledProcessError as e:
            error_msg = f"Volatility failed with exit code {e.returncode}.\nStderr:\n{e.stderr}"
            print(error_msg)
            return None
        except (json.JSONDecodeError, ValueError) as e:
            error_msg = f"Failed to parse Volatility output.\nError: {e}\nRaw Output:\n{result.stdout if result else 'No output'}"
            print(error_msg)
            return None

    def run_all_plugins(self, file_path):
        """
        Runs all three Volatility plugins and returns their results.
        """
        self.current_file_path = file_path
        plugin_map = {
            "Process List": "windows.pslist.PsList",
            "Network Connections": "windows.netscan.NetScan",
            "Commands": "windows.cmdline.CmdLine"
        }

        results = defaultdict(lambda : defaultdict(list))
        for option, plugin_name in plugin_map.items():
            data = self.run_volatility_plugin(plugin_name)
            if data:
                for i in data:
                  results[i['PID']][plugin_name].append(i)
        
        metadata = defaultdict(lambda : defaultdict(str))
        for i in results:
            if "windows.pslist.PsList" in results[i]:
                proc_info = results[i]["windows.pslist.PsList"][0]
                metadata[i]['Process Name'] = proc_info.get('ImageFileName', 'N/A')
                metadata[i]['PPID'] = proc_info.get('PPID', 'N/A')
                metadata[i]['Create Time'] = proc_info.get('CreateTime', 'N/A')
                metadata[i]['PID'] = proc_info.get('PID', 'N/A')
            if "windows.netscan.NetScan" in results[i]:
                net_info = results[i]["windows.netscan.NetScan"]
                metadata[i]['No of Network Connections'] = len(net_info)
            
        # for i in results:
        #     print(i)
        #     for j in results[i]:
        #        print(j) 
        #        for k in results[i][j]:
        #            print(k)

    
        return results,metadata

# if __name__ == "__main__":
#     runner = VolatilityPluginRunner()
#     # Example usage: replace with actual file path
#     file_path = r"C:\Users\preet\Downloads\Challenge_NotchItUp\Challenge.raw"
#     results = runner.run_all_plugins(file_path)
#     # for option, output in results.items():
#     #     print(f"\nResults for {option}:")
#     #     for line in output:
#     #         print(line)