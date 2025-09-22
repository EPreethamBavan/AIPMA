import re
from collections import Counter

class VolatilityQueryHandlers:
    def __init__(self, metadata, results):
        self.metadata = metadata
        self.results = results
        
    def handle_most_network_connections(self):
        """Finds all processes with the most network connections."""
        if not self.metadata:
            return "No process data available."

        # First, find the maximum number of connections any process has.
        max_connections = 0
        for meta in self.metadata.values():
            max_connections = max(max_connections, meta.get('No of Network Connections', 0))

        if max_connections == 0:
            return "No processes with active network connections were found."

        # Now, collect all processes that have that maximum number.
        top_processes = []
        for meta in self.metadata.values():
            if meta.get('No of Network Connections', 0) == max_connections:
                top_processes.append(meta)

        # Format the response based on how many top processes were found.
        if len(top_processes) == 1:
            proc = top_processes[0]
            name = proc.get('Process Name', 'N/A')
            pid = proc.get('PID', 'N/A')
            return f"The process with the most network connections is '{name}' (PID: {pid}) with {max_connections} connections."
        else:
            response_lines = [f"Found {len(top_processes)} processes sharing the maximum of {max_connections} network connections:"]
            for proc in top_processes:
                name = proc.get('Process Name', 'N/A')
                pid = proc.get('PID', 'N/A')
                response_lines.append(f"  - '{name}' (PID: {pid})")
            return "\n".join(response_lines)


    def retrieve_process_data(self, query: str):
        """
        Retrieves all data for a given PID.
        Returns a formatted string of context data on success, or None on failure.
        """
        match = re.search(r'\d+', query)
        if not match:
            return None # Or you could return a specific error message

        pid_str = match.group(0)
        pid_int = int(pid_str)
        
        if pid_int in self.metadata:
            process_metadata = self.metadata[pid_int]
            process_results = self.results.get(pid_int, {})
            
            context_lines = ["## Metadata Summary"]
            for key, value in process_metadata.items():
                context_lines.append(f"  - {key}: {value}")
            
            context_lines.append("\n## Detailed Plugin Data")
            if not process_results:
                context_lines.append("  - No detailed plugin data found for this PID.")
            else:
                for plugin_name, records in process_results.items():
                    context_lines.append(f"\n### {plugin_name}")
                    for record in records:
                        context_lines.append(f"  - {record}")

            return "\n".join(context_lines)
        else:
            return None # Signal that the PID was not found
        
    def handle_multiple_pids(self):
        """Finds which application names are running as multiple processes."""
        if not self.metadata:
            return "No process data available."
            
        process_names = [meta.get('Process Name', 'N/A') for meta in self.metadata.values()]
        name_counts = Counter(process_names)
        
        multi_instance_apps = [name for name, count in name_counts.items() if count > 1]
        
        if multi_instance_apps:
            return f"Applications running with multiple processes: {', '.join(multi_instance_apps)}."
        else:
            return "No applications were found running with multiple processes."