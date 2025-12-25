#!/usr/bin/env python3
"""
ARACHNE Integrity Scanner
Walks the project tree, validates file existence and substance, and reports on the health of the weapon.
"""
import os
import sys
import ast
import json
from pathlib import Path
from typing import Dict, List, Tuple, Set, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class FileStatus(Enum):
    """Status of a file in the project."""
    EXISTS_FULL = "EXISTS (Substantial)"      # File exists and has meaningful code/content
    EXISTS_DUMMY = "EXISTS (Dummy/Empty)"     # File exists but is empty or placeholder
    MISSING = "MISSING"                       # File is not present
    DIRECTORY_OK = "DIRECTORY (OK)"           # Directory exists
    DIRECTORY_MISSING = "DIRECTORY (MISSING)" # Directory is missing

@dataclass
class FileReport:
    """Report for a single file."""
    expected_path: Path
    status: FileStatus
    size_bytes: int = 0
    line_count: int = 0
    code_line_count: int = 0  # Non-empty, non-comment lines (for Python)
    notes: str = ""

@dataclass
class ProjectReport:
    """Complete project integrity report."""
    files_checked: int = 0
    files_missing: List[FileReport] = field(default_factory=list)
    files_dummy: List[FileReport] = field(default_factory=list)
    dirs_missing: List[Path] = field(default_factory=list)
    all_reports: Dict[Path, FileReport] = field(default_factory=dict)

class IntegrityScanner:
    """
    The sentinel that walks our digital halls.
    """

    # Project tree definition - the blueprint we're checking against
    PROJECT_TREE = {
        "/": {
            "files": [
                "arachne_core.py",
                ".arachne_keys",
                "requirements.txt",
                "README.md"
            ],
            "dirs": {
                "config/": {
                    "files": [
                        "targets.json",
                        "notification_webhooks.json"
                    ],
                    "dirs": {
                        "wordlists/": {
                            "files": [
                                "api_params_custom.txt",
                                "directories_context.txt",
                                "mutations_base.txt"
                            ]
                        }
                    }
                },
                "modules/": {
                    "files": [
                        "__init__.py",
                        "silken_sentry.py",
                        "venom_fang.py",
                        "widows_bite.py",
                        "myrmidon.py",
                        "tapestry.py",
                        "correlation_engine.py",
                        "orb_weaver.py",
                        "signal_system.py"
                    ]
                },
                "data/": {
                    "files": [
                        "knowledge_graph.db"
                    ],
                    "dirs": {
                        "screenshot/": {},
                        "harvested_js/": {},
                        "loot/": {}
                    }
                },
                "utils/": {
                    "files": [
                        "__init__.py",
                        "crypto_vault.py",
                        "payload_genius.py",
                        "waf_buster.py",
                        "semantic_analyzer.py",
                        "async_http_client.py",
                        "polyglot_gen.py",          # Added from our creation
                        "temporal_analyzer.py"      # Added from our creation
                    ]
                },
                "integrations/": {
                    "files": [
                        "__init__.py",
                        "burp_parser.py",
                        "nuclei_runner.py",
                        "ffuf_wrapper.py",
                        "shodan_censys_client.py"
                    ]
                },
                "reports/": {
                    "files": [
                        "template.md",
                        "generator.py"
                    ],
                    "dirs": {
                        "archive/": {}
                    }
                },
                "tests/": {
                    "files": [
                        "__init__.py",
                        "test_venom_fang.py"
                    ]
                }
            }
        }
    }

    # Files that are allowed to be empty/dummy (like __init__.py can be empty)
    ALLOWED_DUMMIES = {
        '__init__.py',
        '.gitkeep',
        '.arachne_keys',  # Encrypted, might appear empty
        'knowledge_graph.db',  # Database file, binary
        'targets.json',  # Might be empty initially
        'notification_webhooks.json'  # Might be empty
    }

    # Directories that should exist but might be empty
    ALLOWED_EMPTY_DIRS = {
        'screenshot/',
        'harvested_js/',
        'loot/',
        'archive/'
    }

    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.report = ProjectReport()

    def _count_python_code_lines(self, filepath: Path) -> int:
        """Count non-empty, non-comment lines in a Python file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST to count actual code lines (excluding imports, comments, etc.)
            try:
                tree = ast.parse(content)
                # Count lines with actual statements
                code_lines = set()
                for node in ast.walk(tree):
                    if hasattr(node, 'lineno'):
                        code_lines.add(node.lineno)
                return len(code_lines)
            except SyntaxError:
                # If it's not valid Python, fall back to simple line count
                lines = [line.strip() for line in content.split('\n')]
                non_empty = [line for line in lines if line and not line.startswith('#')]
                return len(non_empty)
        except:
            return 0

    def _analyze_file(self, filepath: Path) -> FileReport:
        """Analyze a single file and return its status report."""
        rel_path = filepath.relative_to(self.project_root) if filepath.is_absolute() else filepath
        report = FileReport(expected_path=rel_path, status=FileStatus.MISSING)

        if not filepath.exists():
            return report

        # File exists
        size = filepath.stat().st_size
        
        # Check if it's a directory
        if filepath.is_dir():
            report.status = FileStatus.DIRECTORY_OK
            report.size_bytes = size
            report.notes = "Directory"
            return report

        # It's a file
        report.size_bytes = size
        
        # Count lines
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                report.line_count = len(lines)
                
                # For Python files, count code lines
                if filepath.suffix == '.py':
                    report.code_line_count = self._count_python_code_lines(filepath)
        except:
            report.line_count = 0
            report.code_line_count = 0

        # Determine if it's a dummy/empty file
        is_dummy = False
        
        # Check by filename (allowed dummies)
        if filepath.name in self.ALLOWED_DUMMIES:
            is_dummy = True
            report.notes = "Allowed dummy/placeholder"
        
        # Check by size and content
        elif size == 0:
            is_dummy = True
            report.notes = "Empty file (0 bytes)"
        
        # Check Python files for actual code
        elif filepath.suffix == '.py' and report.code_line_count <= 5:  # 5 lines or less of actual code
            is_dummy = True
            report.notes = f"Minimal code ({report.code_line_count} code lines)"
        
        # Check text files for content
        elif report.line_count <= 3 and size < 100:  # Very small files
            # Read first bit to see if it's just placeholder text
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    preview = f.read(200).lower()
                    if 'todo' in preview or 'placeholder' in preview or 'add content' in preview:
                        is_dummy = True
                        report.notes = "Contains placeholder text"
            except:
                pass

        if is_dummy:
            report.status = FileStatus.EXISTS_DUMMY
        else:
            report.status = FileStatus.EXISTS_FULL

        return report

    def _walk_tree(self, tree_node: Dict, current_path: Path) -> None:
        """Recursively walk the project tree definition and check each item."""
        # Check files at this level
        for filename in tree_node.get('files', []):
            filepath = current_path / filename
            report = self._analyze_file(filepath)
            self.report.all_reports[report.expected_path] = report
            self.report.files_checked += 1
            
            if report.status == FileStatus.MISSING:
                self.report.files_missing.append(report)
            elif report.status == FileStatus.EXISTS_DUMMY:
                self.report.files_dummy.append(report)

        # Check subdirectories
        for dirname, subtree in tree_node.get('dirs', {}).items():
            dirpath = current_path / dirname
            
            # Check if directory exists
            if not dirpath.exists():
                self.report.dirs_missing.append(dirpath.relative_to(self.project_root))
                # Still walk the subtree to report missing files within
                self._walk_tree(subtree, dirpath)
            else:
                # Directory exists, walk into it
                self._walk_tree(subtree, dirpath)

    def scan(self) -> ProjectReport:
        """Perform the complete integrity scan."""
        print(f"[*] ARACHNE Integrity Scan")
        print(f"[*] Project Root: {self.project_root}")
        print(f"[*] Scanning against defined project tree...\n")
        
        # Start scanning from the root
        self._walk_tree(self.PROJECT_TREE["/"], self.project_root)
        
        return self.report

    def print_report(self, report: ProjectReport) -> None:
        """Print a formatted report of the scan results."""
        # Summary
        print("\n" + "="*80)
        print("ARACHNE INTEGRITY SCAN REPORT")
        print("="*80)
        
        total_expected = len(report.all_reports)
        completion_pct = ((total_expected - len(report.files_missing)) / total_expected * 100) if total_expected > 0 else 0
        
        print(f"\n📊 SUMMARY")
        print(f"   Files Checked:        {report.files_checked}")
        print(f"   Files Substantial:    {total_expected - len(report.files_missing) - len(report.files_dummy)}")
        print(f"   Files Dummy/Empty:    {len(report.files_dummy)}")
        print(f"   Files Missing:        {len(report.files_missing)}")
        print(f"   Directories Missing:  {len(report.dirs_missing)}")
        print(f"   Project Completion:   {completion_pct:.1f}%")
        
        # Missing Files (Critical)
        if report.files_missing:
            print(f"\n❌ MISSING FILES (Critical)")
            print("   " + "-"*70)
            for file_report in sorted(report.files_missing, key=lambda x: str(x.expected_path)):
                print(f"   {file_report.expected_path}")
        
        # Dummy/Empty Files (Warning)
        if report.files_dummy:
            print(f"\n⚠️  DUMMY/EMPTY FILES (Needs Attention)")
            print("   " + "-"*70)
            for file_report in sorted(report.files_dummy, key=lambda x: str(x.expected_path)):
                size_kb = file_report.size_bytes / 1024 if file_report.size_bytes > 0 else 0
                print(f"   {file_report.expected_path}")
                print(f"      Size: {file_report.size_bytes} bytes ({size_kb:.1f} KB), "
                      f"Lines: {file_report.line_count}, Code Lines: {file_report.code_line_count}")
                if file_report.notes:
                    print(f"      Note: {file_report.notes}")
                print()
        
        # Missing Directories
        if report.dirs_missing:
            print(f"\n📁 MISSING DIRECTORIES")
            print("   " + "-"*70)
            for dirpath in sorted(report.dirs_missing):
                print(f"   {dirpath}/")
        
        # Detailed File Status (if verbose)
        print(f"\n📋 DETAILED FILE STATUS")
        print("   " + "-"*70)
        
        # Group by directory
        files_by_dir: Dict[str, List[FileReport]] = {}
        for report_item in report.all_reports.values():
            dir_path = str(report_item.expected_path.parent)
            files_by_dir.setdefault(dir_path, []).append(report_item)
        
        # Print each directory's files
        for dir_path in sorted(files_by_dir.keys()):
            print(f"\n   {dir_path}/" if dir_path != '.' else "\n   ./")
            for file_report in sorted(files_by_dir[dir_path], key=lambda x: x.expected_path.name):
                status_icon = {
                    FileStatus.EXISTS_FULL: "✅",
                    FileStatus.EXISTS_DUMMY: "⚠️ ",
                    FileStatus.MISSING: "❌",
                    FileStatus.DIRECTORY_OK: "📁",
                    FileStatus.DIRECTORY_MISSING: "❌📁"
                }.get(file_report.status, "❓")
                
                size_info = f"{file_report.size_bytes:6d} bytes" if file_report.size_bytes > 0 else "        N/A"
                line_info = f"{file_report.line_count:3d} lines" if file_report.line_count > 0 else "       N/A"
                
                print(f"      {status_icon} {file_report.expected_path.name:30} {size_info} {line_info}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS")
        print("   " + "-"*70)
        
        if report.files_missing:
            print("   1. Create missing files:")
            for file_report in report.files_missing[:5]:  # Show first 5
                print(f"      - {file_report.expected_path}")
            if len(report.files_missing) > 5:
                print(f"      ... and {len(report.files_missing) - 5} more")
        
        if report.files_dummy:
            print(f"   2. Implement {len(report.files_dummy)} placeholder/dummy files:")
            dummy_py = [f for f in report.files_dummy if str(f.expected_path).endswith('.py')]
            dummy_other = [f for f in report.files_dummy if not str(f.expected_path).endswith('.py')]
            
            if dummy_py:
                print(f"      - {len(dummy_py)} Python files need implementation")
            if dummy_other:
                print(f"      - {len(dummy_other)} other files need content")
        
        if report.dirs_missing:
            print(f"   3. Create {len(report.dirs_missing)} missing directories")
        
        if not report.files_missing and not report.files_dummy and not report.dirs_missing:
            print("   🎉 Project structure is complete and all files have substance!")
            print("   The weapon is ready for deployment.")
        
        print("\n" + "="*80)

    def export_json_report(self, report: ProjectReport, output_path: Path) -> None:
        """Export the report as JSON for programmatic use."""
        export_data = {
            "scan_timestamp": None,  # Would be datetime.now().isoformat() in real use
            "project_root": str(self.project_root),
            "summary": {
                "files_checked": report.files_checked,
                "files_missing": len(report.files_missing),
                "files_dummy": len(report.files_dummy),
                "dirs_missing": len(report.dirs_missing),
            },
            "missing_files": [
                {
                    "path": str(fr.expected_path),
                    "notes": fr.notes
                }
                for fr in report.files_missing
            ],
            "dummy_files": [
                {
                    "path": str(fr.expected_path),
                    "size_bytes": fr.size_bytes,
                    "line_count": fr.line_count,
                    "code_line_count": fr.code_line_count,
                    "notes": fr.notes
                }
                for fr in report.files_dummy
            ],
            "missing_dirs": [str(p) for p in report.dirs_missing],
            "all_files": {
                str(path): {
                    "status": report_item.status.value,
                    "size_bytes": report_item.size_bytes,
                    "line_count": report_item.line_count,
                    "code_line_count": report_item.code_line_count,
                    "notes": report_item.notes
                }
                for path, report_item in report.all_reports.items()
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"[+] JSON report exported to: {output_path}")

def main():
    """Main entry point for the scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ARACHNE Project Integrity Scanner")
    parser.add_argument("--project-root", "-p", default=".", 
                       help="Root directory of the ARACHNE project")
    parser.add_argument("--json", "-j", metavar="OUTPUT_FILE",
                       help="Export report as JSON to the specified file")
    parser.add_argument("--quiet", "-q", action="store_true",
                       help="Suppress detailed output, only show summary")
    
    args = parser.parse_args()
    
    # Run the scan
    scanner = IntegrityScanner(args.project_root)
    report = scanner.scan()
    
    # Export JSON if requested
    if args.json:
        scanner.export_json_report(report, Path(args.json))
    
    # Print report (unless quiet mode)
    if not args.quiet:
        scanner.print_report(report)
    else:
        # Quiet mode: just show summary numbers
        missing = len(report.files_missing)
        dummy = len(report.files_dummy)
        dirs_missing = len(report.dirs_missing)
        
        if missing == 0 and dummy == 0 and dirs_missing == 0:
            print("✅ Project structure complete and healthy.")
        else:
            print(f"⚠️  Issues found: {missing} missing files, {dummy} dummy files, {dirs_missing} missing directories.")
    
    # Return exit code based on severity
    if report.files_missing:
        sys.exit(1)  # Critical issues
    elif report.files_dummy:
        sys.exit(2)  # Warning issues
    else:
        sys.exit(0)  # All good

if __name__ == "__main__":
    main()