# parallel_scanner.py
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from s3_scanner import get_all_scan_functions # We will create this function in the next step

def run_parallel_scans_blocking(**aws_creds):
    """
    Runs all scans in parallel using a thread pool.
    Returns a single list of all results only when everything is complete.
    """
    all_results = []
    scan_functions = get_all_scan_functions(**aws_creds)

    with ThreadPoolExecutor(max_workers=15) as executor:
        # Create a future for each scan function
        future_to_scan = {executor.submit(scan_func): name for name, scan_func in scan_functions}

        for future in as_completed(future_to_scan):
            try:
                result = future.result()
                all_results.extend(result)
            except Exception as e:
                scan_name = future_to_scan[future]
                print(f"ERROR in scan '{scan_name}': {e}")
                all_results.append({"service": "Scanner", "resource": scan_name, "status": "ERROR", "issue": f"Scan function failed: {str(e)}"})

    return all_results

def run_parallel_scans_progress(**aws_creds):
    """
    A generator that runs scans in parallel and yields progress
    updates as each scan function completes.
    """
    scan_functions = get_all_scan_functions(**aws_creds)

    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_scan = {executor.submit(scan_func): name for name, scan_func in scan_functions}

        for future in as_completed(future_to_scan):
            scan_name = future_to_scan[future]
            try:
                # Yield a progress update as soon as a scan is done
                yield {"status": "progress", "message": f"Completed: {scan_name}"}
            except Exception as e:
                print(f"ERROR in scan '{scan_name}': {e}")
                yield {"status": "error", "message": f"Error in {scan_name}: {str(e)}"}