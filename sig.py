# signature_analyzer.py

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from volatility import VolatilityPluginRunner

# We need the 'magic' library for signature analysis
try:
    import magic
except ImportError:
    print("Error: The 'python-magic' library is not installed.", file=sys.stderr)
    print(
        "Please run: pip install python-magic-win64 (on Windows) or pip install python-magic (on Linux/macOS)",
        file=sys.stderr,
    )
    sys.exit(1)


# A mapping of common extensions to expected file signature descriptions.
EXT_TO_SIGNATURE = {
    ".exe": ["PE32 executable", "MS-DOS executable"],
    ".dll": ["PE32 executable", "MS-DOS executable"],
    ".sys": ["PE32 executable", "MS-DOS executable"],
    ".pdf": "PDF document",
    ".jpg": "JPEG image data",
    ".jpeg": "JPEG image data",
    ".png": "PNG image data",
    ".gif": "GIF image data",
    ".zip": "Zip archive data",
    ".txt": "ASCII text",
}


def analyze_bytes_for_mismatch(file_data: bytes, original_name: str) -> dict or None:
    """Helper to analyze bytes and return mismatch details, or None."""
    extension = os.path.splitext(original_name)[1].lower()
    if not file_data or extension not in EXT_TO_SIGNATURE:
        return None

    try:
        actual_type = magic.from_buffer(file_data)
        expected_types = EXT_TO_SIGNATURE[extension]
        if not isinstance(expected_types, list):
            expected_types = [expected_types]

        if not any(exp in actual_type for exp in expected_types):
            return {
                "filename": original_name,
                "expected": ", ".join(expected_types),
                "actual": actual_type.split(",")[0],
            }
    except Exception:
        return None
    return None


def perform_signature_analysis(runner: VolatilityPluginRunner, mem_file_path: str):
    """
    Uses the provided Volatility runner to perform signature analysis.
    Returns the mismatches and the counts of items checked.
    """
    print("\n--- Starting Signature Mismatch Analysis ---")
    all_mismatches = {"files": [], "processes": []}
    files_checked_count = 0
    procs_checked_count = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"[*] Using temporary directory for dumps: {temp_dir}")

        # --- Stage 1: Analyze Open Files ---
        print("\n[*] Stage 1: Analyzing signatures of open files...")
        runner.current_file_path = mem_file_path
        filescan_results = runner.run_volatility_plugin("windows.filescan.FileScan")

        if not filescan_results:
            print(
                "[!] No files found by filescan. This could indicate a profile mismatch. Skipping file analysis."
            )
        else:
            total_files_found = len(filescan_results)
            print(f"[*] Found {total_files_found} total open files.")
            checkable_files = [
                f
                for f in filescan_results
                if os.path.splitext(f.get("Name", ""))[1].lower() in EXT_TO_SIGNATURE
            ]
            files_checked_count = len(checkable_files)
            print(
                f"[*] Found {files_checked_count} open files with checkable extensions."
            )

            for i, file_obj in enumerate(checkable_files):
                file_name = file_obj.get("Name")
                virt_addr = file_obj.get("Offset")

                # --- THIS IS THE MODIFIED PART ---
                # \r moves to the start of the line.
                # \x1b[K clears from the cursor to the end of the line.
                clear_line = "\x1b[K"
                progress_text = (
                    f"  -> Checking [{i+1}/{files_checked_count}]: {file_name}"
                )
                print(f"\r{progress_text}{clear_line}", end="")
                # --------------------------------

                try:
                    dump_cmd = [
                        "vol",
                        "-q",
                        "-f",
                        mem_file_path,
                        "windows.dumpfiles",
                        f"--virtaddr={virt_addr}",
                        f"--dump-dir={temp_dir}",
                    ]
                    subprocess.run(dump_cmd, check=True, capture_output=True)
                    dumped_file = Path(temp_dir) / f"file.{hex(virt_addr)}.dat"
                    if dumped_file.exists() and dumped_file.stat().st_size > 0:
                        with open(dumped_file, "rb") as f:
                            mismatch = analyze_bytes_for_mismatch(f.read(), file_name)
                            if mismatch:
                                all_mismatches["files"].append(mismatch)
                except subprocess.CalledProcessError:
                    continue
            # Clear the final progress line before moving on
            print(f"\r{' ' * 80}\r", end="")

        # --- Stage 2: Analyze Running Processes ---
        print("\n[*] Stage 2: Analyzing signatures of running processes...")
        pslist_results = runner.run_volatility_plugin("windows.pslist.PsList")

        if not pslist_results:
            print(
                "[!] No processes found by pslist. This strongly suggests a profile mismatch. Skipping process analysis."
            )
        else:
            total_procs_found = len(pslist_results)
            print(f"[*] Found {total_procs_found} total running processes.")
            checkable_procs = [
                p
                for p in pslist_results
                if os.path.splitext(p.get("ImageFileName", ""))[1].lower()
                in EXT_TO_SIGNATURE
            ]
            procs_checked_count = len(checkable_procs)
            print(
                f"[*] Found {procs_checked_count} processes with checkable extensions."
            )

            for i, process in enumerate(checkable_procs):
                pid = process.get("PID")
                proc_name = process.get("ImageFileName")

                # --- THIS IS THE MODIFIED PART ---
                clear_line = "\x1b[K"
                progress_text = f"  -> Checking [{i+1}/{procs_checked_count}]: {proc_name} (PID: {pid})"
                print(f"\r{progress_text}{clear_line}", end="")
                # --------------------------------

                try:
                    dump_cmd = [
                        "vol",
                        "-q",
                        "-f",
                        mem_file_path,
                        "windows.procdump",
                        f"--pid={pid}",
                        f"--dump-dir={temp_dir}",
                    ]
                    subprocess.run(dump_cmd, check=True, capture_output=True)
                    dumped_file = Path(temp_dir) / f"executable.{pid}.exe"
                    if dumped_file.exists() and dumped_file.stat().st_size > 0:
                        with open(dumped_file, "rb") as f:
                            mismatch = analyze_bytes_for_mismatch(f.read(), proc_name)
                            if mismatch:
                                mismatch["pid"] = pid
                                all_mismatches["processes"].append(mismatch)
                except subprocess.CalledProcessError:
                    continue
            # Clear the final progress line before moving on
            print(f"\r{' ' * 80}\r", end="")

    return all_mismatches, files_checked_count, procs_checked_count


def print_report(results: dict, files_checked: int, procs_checked: int):
    """Formats and prints the final analysis report with summary."""
    print("\n\n" + "=" * 50)  # Added extra newline for better separation
    print("        Signature Analysis Final Report")
    print("=" * 50)

    suspicious_files_count = len(results["files"])
    if suspicious_files_count > 0:
        print(f"\n[!] Found {suspicious_files_count} File Signature Mismatches:")
        for item in results["files"]:
            print(
                f"  - File:     {item['filename']}\n    Expected: {item['expected']}\n    Actual:   {item['actual']}"
            )
    else:
        print("\n[*] No file signature mismatches were detected.")

    print(
        f"  -> Summary: {suspicious_files_count}/{files_checked} suspicious files found."
    )

    suspicious_procs_count = len(results["processes"])
    if suspicious_procs_count > 0:
        print(f"\n[!] Found {suspicious_procs_count} Process Signature Mismatches:")
        for item in results["processes"]:
            print(
                f"  - Process:  {item['filename']} (PID: {item['pid']})\n    Expected: {item['expected']}\n    Actual:   {item['actual']}"
            )
    else:
        print("\n[*] No process signature mismatches were detected.")

    print(
        f"  -> Summary: {suspicious_procs_count}/{procs_checked} suspicious processes found."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Signature Analysis tool for memory dumps. Uses volatility_runner.py."
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to the raw memory dump file (.raw, .vmem, etc.)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: Memory file not found at '{args.file}'", file=sys.stderr)
        sys.exit(1)

    vol_runner = VolatilityPluginRunner()
    analysis_results, files_total, procs_total = perform_signature_analysis(
        vol_runner, args.file
    )
    print_report(analysis_results, files_total, procs_total)
