import json
import os
import subprocess
import sys
from datetime import datetime


def is_volatility_installed():
    """Checks if volatility3 is accessible."""
    try:
        command = "where" if sys.platform == "win32" else "which"
        subprocess.run([command, "vol"], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_file_metadata(file_path):
    """Get metadata of the selected memory image file."""
    stat = os.stat(file_path)
    size_mb = stat.st_size / (1024 * 1024)
    creation_time = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
    modification_time = datetime.fromtimestamp(stat.st_mtime).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    metadata_text = (
        f"<h2>Memory Image Loaded</h2>"
        f"<p><b>File Path:</b> {file_path}</p>"
        f"<p><b>Size:</b> {size_mb:.2f} MB</p>"
        f"<p><b>Creation Time:</b> {creation_time}</p>"
        f"<p><b>Last Modified:</b> {modification_time}</p><hr>"
        f"<p>Select 'View' from the options list on the left to inspect the image.</p>"
    )
    return metadata_text


def run_volatility_plugin(file_path, plugin_name, cache, append_callback=None):
    """
    Runs a Volatility 3 plugin and returns the parsed JSON output.
    :param file_path: Path to memory image file
    :param plugin_name: Volatility plugin name
    :param cache: dict to cache results
    :param append_callback: function to append text to UI (optional)
    """
    if not file_path:
        return None

    if plugin_name in cache:
        return cache[plugin_name]

    if append_callback:
        append_callback(f"<p>Running Volatility plugin: {plugin_name}...</p>")

    try:
        command = ["vol", "-f", file_path, "--renderer", "json", plugin_name]
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
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
        cache[plugin_name] = parsed_json
        return parsed_json

    except Exception as e:
        if append_callback:
            append_callback(
                f"<p style='color: red;'>Error running {plugin_name}: {e}</p>"
            )
        return None
