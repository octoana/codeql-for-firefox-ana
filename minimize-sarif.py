#!/usr/bin/env python3
"""
Extract only results from SARIF files while maintaining valid SARIF structure.
Removes artifacts, conversion, invocations, and other non-essential data.
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, Any, List

# functions used to calculate size of SARIF subtrees
def sizeof(x):
    t = type(x)
    if t is dict:
        return sum(len(k) + sizeof(v) for k, v in x.items())
    if t is list:
        return sum(sizeof(v) for v in x)
    if t is str:
        return len(x)
    return 8  # numbers, bools, null

def walk(x, path="root"):
    if isinstance(x, dict):
        yield path, sizeof(x)
        for k,v in x.items():
            yield from walk(v, f"{path}.{k}")
    elif isinstance(x, list):
        yield path, sizeof(x)
        for i,v in enumerate(x):
            yield from walk(v, f"{path}[{i}]")

# Create minimal SARIF structure
def create_minimal_sarif(original_sarif: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a minimal valid SARIF file containing only results and required metadata.
    
    Args:
        original_sarif: Complete SARIF data structure
        
    Returns:
        Minimal valid SARIF with only results
    """
    
    # Start with minimal required SARIF structure
    minimal_sarif = {
        "version": original_sarif.get("version", "2.1.0"),
        "$schema": original_sarif.get("$schema", 
                                     "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"),
        "runs": []
    }
    
    # Process each run
    for run in original_sarif.get("runs", []):
        minimal_run = {}
        
        # Required: tool information (minimal)
        if "tool" in run:
            minimal_tool = {"driver": {}}
            
            # Keep only essential tool.driver fields
            if "driver" in run["tool"]:
                driver = run["tool"]["driver"]
                minimal_driver = {}
                
                # Required fields
                if "name" in driver:
                    minimal_driver["name"] = driver["name"]
                else:
                    minimal_driver["name"] = "Unknown Tool"  # Fallback
                
                # Optional but useful fields
                for field in ["version", "informationUri", "semanticVersion"]:
                    if field in driver:
                        minimal_driver[field] = driver[field]
                
                # Keep rules if they exist (needed for result rule references)
                if "rules" in driver:
                    minimal_driver["rules"] = driver["rules"]
                
                minimal_tool["driver"] = minimal_driver
            
            minimal_run["tool"] = minimal_tool
        else:
            # Fallback if no tool information
            minimal_run["tool"] = {"driver": {"name": "Unknown Tool"}}
        
        # Main content: results
        if "results" in run:
            minimal_run["results"] = run["results"]
        else:
            minimal_run["results"] = []
        
        # Optional: keep taxonomies if present (sometimes referenced in results)
        if "taxonomies" in run:
            minimal_run["taxonomies"] = run["taxonomies"]
        
        # Optional: keep threadFlowLocations if present
        if "threadFlowLocations" in run:
            minimal_run["threadFlowLocations"] = run["threadFlowLocations"]
        
        # Optional: keep graphs if present (sometimes used for data flow)
        if "graphs" in run:
            minimal_run["graphs"] = run["graphs"]
        
        # Optional: keep logical locations if present
        if "logicalLocations" in run:
            minimal_run["logicalLocations"] = run["logicalLocations"]
        
        minimal_sarif["runs"].append(minimal_run)
    
    return minimal_sarif

def calculate_size_reduction(original_size: int, minimal_size: int) -> Dict[str, Any]:
    """
    Calculate size reduction metrics.
    
    Args:
        original_size: Size of original file in bytes
        minimal_size: Size of minimal file in bytes
        
    Returns:
        Dictionary with size metrics
    """
    reduction_bytes = original_size - minimal_size
    reduction_percent = (reduction_bytes / original_size) * 100 if original_size > 0 else 0
    
    return {
        "original_size": original_size,
        "minimal_size": minimal_size,
        "reduction_bytes": reduction_bytes,
        "reduction_percent": reduction_percent,
        "original_size_mb": original_size / (1024 * 1024),
        "minimal_size_mb": minimal_size / (1024 * 1024),
        "reduction_mb": reduction_bytes / (1024 * 1024)
    }

def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"

def process_sarif_file(input_path: Path, output_path: Path = None, 
                      verbose: bool = False, sarif_size_subtrees: bool = False) -> None:
    """
    Process a SARIF file to extract only results.
    
    Args:
        input_path: Path to input SARIF file
        output_path: Path to output file (optional, auto-generated if not provided)
        verbose: Print detailed information
        sarif_size_subtrees: Include size information for SARIF subtrees
    """
    
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' does not exist.", file=sys.stderr)
        return
    
    # Auto-generate output path if not provided
    if output_path is None:
        output_path = input_path.parent / f"{input_path.stem}.minimal.sarif"
    
    try:
        # Read original SARIF
        #if verbose:
         #   print(f"Reading: {input_path}")
        
        with open(input_path, 'r', encoding='utf-8') as f:
            original_sarif = json.load(f)
        
        # Create minimal SARIF
        minimal_sarif = create_minimal_sarif(original_sarif)
        
        # Count results
        total_results = sum(len(run.get("results", [])) 
                          for run in minimal_sarif.get("runs", []))
        
        # Write minimal SARIF
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(minimal_sarif, f, indent=2, ensure_ascii=False)
        
        # Calculate size reduction
        original_size = input_path.stat().st_size
        minimal_size = output_path.stat().st_size
        metrics = calculate_size_reduction(original_size, minimal_size)
        
        # Report results
        print(f"\n✓ Processed: {input_path.name}")
        print(f"  Output: {output_path.name}")
        print(f"  Results extracted: {total_results:,}")
        print(f"  Original size: {format_size(metrics['original_size'])}")
        print(f"  Minimal size: {format_size(metrics['minimal_size'])}")
        print(f"  Reduction: {format_size(metrics['reduction_bytes'])} ({metrics['reduction_percent']:.1f}%)")
        
        if verbose:
            # Show what was removed
            original_runs = original_sarif.get("runs", [])
            if original_runs:
                run = original_runs[0]
                removed_keys = set(run.keys()) - set(minimal_sarif["runs"][0].keys())
                if removed_keys:
                    print(f"  Removed sections: {', '.join(sorted(removed_keys))}")
        
        # APS: Include SARIF subtree size information if requested via command line
        if sarif_size_subtrees:
            # Calculate the size of the SARIF subtrees
            print("  Processing SARIF subtree size information... ")

            sizes = sorted(walk(original_sarif), key=lambda kv: kv[1], reverse=True)
            for p, s in sizes[:50]:
                print(f"{s:10d}  {p}")

    
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{input_path}': {e}", file=sys.stderr)
    except Exception as e:
        print(f"Error processing '{input_path}': {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Extract only results from SARIF files while maintaining valid SARIF structure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process single file (auto-generates .minimal.sarif output)
  %(prog)s input.sarif
  
  # Process with custom output name
  %(prog)s input.sarif -o output.sarif
  
  # Process multiple files
  %(prog)s file1.sarif file2.sarif file3.sarif
  
  # Process with verbose output
  %(prog)s -v large-scan.sarif
  
  # Process all SARIF files in current directory
  %(prog)s *.sarif
        """
    )
    
    parser.add_argument(
        "input_files",
        nargs="+",
        type=Path,
        help="Input SARIF file(s) to process"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path (only valid with single input file)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information about processing"
    )
    
    parser.add_argument(
        "--sarif_size_subtrees",
        action="store_true",
        help="Include size information for SARIF subtrees"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.output and len(args.input_files) > 1:
        parser.error("Cannot specify --output with multiple input files")
    
    # Process files
    for input_file in args.input_files:
        process_sarif_file(
            input_file,
            args.output if len(args.input_files) == 1 else None,
            args.verbose,
            args.sarif_size_subtrees
        )

if __name__ == "__main__":
    main()
