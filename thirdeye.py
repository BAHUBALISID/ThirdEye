#!/usr/bin/env python3
"""
ThirdEye - Advanced OSINT and Reconnaissance Tool
Author: sid7.py
"""

import tldextract
import argparse
import subprocess
import sys
import time
from typing import Dict, List, Tuple
import os

def display_banner():
    banner = """
            ..,,;;;;;;,,,,
       .,;'';;,..,;;;,,,,,.''';;,..
    ,,''                    '';;;;,;''
   ;'    ,;@@;'  ,@@;, @@, ';;;@@;,;';.
  ''  ,;@@@@@'  ;@@@@; ''    ;;@@@@@;;;;
     ;;@@@@@;    '''     .,,;;;@@@@@@@;;;
    ;;@@@@@@;           , ';;;@@@@@@@@;;;.
     '';@@@@@,.  ,   .   ',;;;@@@@@@;;;;;;
        .   '';;;;;;;;;,;;;;@@@@@;;' ,.:;'
          ''..,,     ''''    '  .,;'
               ''''''::''''''''
    
    ╔══════════════════════════════════════╗
    ║            ThirdEye v1.0             ║
    ║      Advanced OSINT Recon Tool       ║
    ║              by sid7                 ║
    ╚══════════════════════════════════════╝
    """
    print(banner)

class ThirdEye:
    def __init__(self, domain: str, output: str = None):
        self.domain = domain
        self.output = output
        self.target = tldextract.extract(str(domain)).domain
        self.dork_categories = self._initialize_dork_categories()
        self.search_engines = ["google", "bing", "duckduckgo", "startpage", "yandex"]
        
    def _initialize_dork_categories(self) -> Dict[str, List[Tuple[str, str]]]:
        """Initialize all dork categories"""
        return {
            "git": [
                ("Git folders", f'inurl:"/.git" {self.domain} -github'),
                ("Git config files", f'site:{self.domain} ext:git'),
                ("GitHub repositories", f'site:github.com "{self.target}"'),
                ("GitLab repositories", f'site:gitlab.com "{self.target}"'),
                ("Bitbucket repositories", f'site:bitbucket.org "{self.target}"'),
            ],
            "backup": [
                ("Backup files", f'site:{self.domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup | ext:tar | ext:gz | ext:zip'),
                ("Database backups", f'site:{self.domain} ext:sql | ext:dmp | ext:dump'),
                ("Configuration backups", f'site:{self.domain} "backup" filetype:txt | filetype:conf | filetype:ini'),
            ],
            "documents": [
                ("Exposed documents", f'site:{self.domain} ext:doc | ext:docx | ext:pdf | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:txt | ext:rtf | ext:csv'),
                ("Confidential documents", f'inurl:{self.target} "confidential" | "proprietary" | "internal" | "restricted" filetype:pdf | filetype:doc | filetype:xls'),
                ("Employee documents", f'inurl:{self.target} "employee" | "staff" | "HR" filetype:pdf | filetype:doc'),
            ],
            "config": [
                ("Configuration files", f'site:{self.domain} ext:xml | ext:conf | ext:cfg | ext:ini | ext:env | ext:json | ext:yml | ext:yaml'),
                ("Environment files", f'site:{self.domain} ".env" | "environment" filetype:env'),
                ("API keys/configs", f'site:{self.domain} "api_key" | "apikey" | "secret" | "password" filetype:txt | filetype:env'),
            ],
            "admin": [
                ("Login pages", f'site:{self.domain} inurl:login | inurl:signin | inurl:admin | inurl:portal | inurl:dashboard'),
                ("Admin panels", f'site:{self.domain} intitle:"admin" | intitle:"dashboard" | intitle:"control panel"'),
                ("WordPress admin", f'site:{self.domain} inurl:wp-admin | inurl:wp-login'),
            ],
            "subdomains": [
                ("Subdomains", f'site:*.{self.domain}'),
                ("Wildcard subdomains", f'site:*.*.{self.domain}'),
                ("Specific subdomains", f'site:dev.{self.domain} | site:test.{self.domain} | site:staging.{self.domain}'),
            ],
            "errors": [
                ("Error messages", f'site:{self.domain} "error" | "warning" | "exception" | "stack trace"'),
                ("SQL errors", f'site:{self.domain} "sql" "error" | "mysql" "error" | "database error"'),
                ("PHP errors", f'site:{self.domain} "PHP" "error" | "Parse error" | "Fatal error"'),
            ],
            "cloud": [
                ("AWS S3 buckets", f'site:.s3.amazonaws.com "{self.target}"'),
                ("Google Cloud Storage", f'site:storage.googleapis.com "{self.target}"'),
                ("Azure storage", f'site:.blob.core.windows.net "{self.target}"'),
            ],
            "monitoring": [
                ("Jenkins", f'intitle:"Dashboard [Jenkins]" "{self.target}"'),
                ("Traefik", f'intitle:traefik inurl:8080/dashboard "{self.target}"'),
                ("Grafana", f'intitle:"Grafana" inurl:3000 "{self.target}"'),
                ("Kibana", f'intitle:"Kibana" "{self.target}"'),
            ],
            "code": [
                ("Source code leaks", f'site:{self.domain} ext:py | ext:java | ext:js | ext:php | ext:cpp | ext:c | ext:html'),
                ("Pastebin sites", f'site:pastebin.com | site:justpaste.it | site:codepad.co "{self.target}"'),
                ("Code sharing", f'site:github.com | site:gitlab.com | site:bitbucket.org "{self.target}"'),
            ],
            "apis": [
                ("API endpoints", f'site:{self.domain} inurl:api | inurl:rest | inurl:graphql | inurl:soap'),
                ("API documentation", f'site:{self.domain} "swagger" | "openapi" | "api docs"'),
                ("JSON/XML endpoints", f'site:{self.domain} ext:json | ext:xml | ext:yaml'),
            ],
            "misc": [
                ("Directory listings", f'site:{self.domain} intitle:"index of" | "parent directory"'),
                ("Open redirects", f'site:{self.domain} inurl:redirect | inurl:url= | inurl:return= | inurl:next='),
                ("Stack Overflow", f'site:stackoverflow.com "{self.domain}"'),
                ("LinkedIn employees", f'site:linkedin.com employees {self.domain}'),
            ]
        }
    
    def save(self, data: str):
        """Save data to output file"""
        if self.output:
            with open(self.output, "a", encoding="utf-8") as f:
                f.write(data + "\n")
    
    def run_dork(self, description: str, dork: str, category: str = "General"):
        """Execute a single dork search"""
        print(f"\n{'='*60}")
        print(f"[*] Category: {category}")
        print(f"[*] Description: {description}")
        print(f"[*] Dork: {dork}")
        print(f"{'='*60}")
        
        # Save to file
        if self.output:
            self.save(f"\n{'='*60}")
            self.save(f"Category: {category}")
            self.save(f"Description: {description}")
            self.save(f"Dork: {dork}")
            self.save(f"{'='*60}")
        
        try:
            # Build command
            cmd = [
                "xnldorker", "-i", dork,
                "-nb",  # no banner
                "-s", ",".join(self.search_engines),
                "-t", "2",  # timeout
                "-l", "10"  # limit results
            ]
            
            print(f"[+] Running: {' '.join(cmd)}")
            
            # Execute command with timeout
            result = subprocess.run(
                cmd,
                text=True,
                capture_output=True,
                timeout=90,
                encoding='utf-8'
            )
            
            # Print results
            if result.stdout:
                print(result.stdout)
                if self.output:
                    self.save(result.stdout)
            else:
                print("[-] No results found")
                if self.output:
                    self.save("[-] No results found")
                    
            if result.stderr:
                print(f"[!] Errors: {result.stderr[:200]}...")
                
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running dork: {e}")
            if self.output:
                self.save(f"[!] Error: {e}")
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout after 90 seconds")
            if self.output:
                self.save("[!] Timeout after 90 seconds")
        except FileNotFoundError:
            print("[!] xnldorker not found. Please install it first.")
            print("[!] Install: pip install xnldorker")
            sys.exit(1)
        
        time.sleep(2)  # Rate limiting
    
    def list_categories(self):
        """List all available categories"""
        print("\n[+] Available Dork Categories:")
        print("-" * 40)
        for i, category in enumerate(self.dork_categories.keys(), 1):
            print(f"  {i:2d}. {category:<15} - {len(self.dork_categories[category])} dorks")
        print()
    
    def list_dorks(self, category: str = None):
        """List all dorks in a category or all categories"""
        if category:
            if category in self.dork_categories:
                print(f"\n[+] Dorks in category '{category}':")
                print("-" * 60)
                for i, (desc, dork) in enumerate(self.dork_categories[category], 1):
                    print(f"{i:2d}. {desc}")
                    print(f"    Dork: {dork[:80]}..." if len(dork) > 80 else f"    Dork: {dork}")
                    print()
            else:
                print(f"[-] Category '{category}' not found")
        else:
            for cat_name, dorks in self.dork_categories.items():
                print(f"\n[+] Category: {cat_name}")
                print("-" * 60)
                for i, (desc, dork) in enumerate(dorks, 1):
                    print(f"{i:2d}. {desc}")
    
    def run_category(self, category: str):
        """Run all dorks in a specific category"""
        if category in self.dork_categories:
            print(f"\n[+] Running category: {category}")
            print(f"[+] Found {len(self.dork_categories[category])} dorks")
            
            for desc, dork in self.dork_categories[category]:
                self.run_dork(desc, dork, category)
        else:
            print(f"[-] Category '{category}' not found")
    
    def run_all(self):
        """Run all dorks from all categories"""
        total_dorks = sum(len(dorks) for dorks in self.dork_categories.values())
        print(f"\n[+] Running ALL dorks")
        print(f"[+] Total dorks to execute: {total_dorks}")
        print(f"[+] Estimated time: {total_dorks * 2} seconds")
        print()
        
        for category, dorks in self.dork_categories.items():
            print(f"\n{'#'*60}")
            print(f"# CATEGORY: {category.upper()}")
            print(f"# DORKS: {len(dorks)}")
            print(f"{'#'*60}\n")
            
            if self.output:
                self.save(f"\n{'#'*60}")
                self.save(f"# CATEGORY: {category.upper()}")
                self.save(f"# DORKS: {len(dorks)}")
                self.save(f"{'#'*60}")
            
            for desc, dork in dorks:
                self.run_dork(desc, dork, category)

def parse_args():
    parser = argparse.ArgumentParser(
        description="ThirdEye - Advanced OSINT and Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com -c git,config
  %(prog)s -d example.com -c all -o results.txt
  %(prog)s -d example.com --list-categories
  %(prog)s -d example.com --list-dorks --category git
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-c', '--categories', default='all',
                       help='Comma-separated list of categories to run (default: all)')
    parser.add_argument('--list-categories', action='store_true',
                       help='List all available categories')
    parser.add_argument('--list-dorks', action='store_true',
                       help='List all dorks (use with --category for specific category)')
    parser.add_argument('--engines', default='google,bing,duckduckgo',
                       help='Search engines to use (comma-separated)')
    parser.add_argument('--timeout', type=int, default=90,
                       help='Timeout per dork in seconds (default: 90)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    return parser.parse_args()

def main():
    display_banner()
    
    args = parse_args()
    
    # Initialize ThirdEye
    eye = ThirdEye(args.domain, args.output)
    
    # Update search engines if specified
    if args.engines != 'google,bing,duckduckgo':
        eye.search_engines = [e.strip() for e in args.engines.split(',')]
    
    # List categories mode
    if args.list_categories:
        eye.list_categories()
        return
    
    # List dorks mode
    if args.list_dorks:
        eye.list_dorks()
        return
    
    print(f"[+] Target Domain: {args.domain}")
    print(f"[+] Extracted Target: {eye.target}")
    print(f"[+] Search Engines: {', '.join(eye.search_engines)}")
    if args.output:
        print(f"[+] Output File: {args.output}")
    print()
    
    # Determine which categories to run
    if args.categories.lower() == 'all':
        categories_to_run = list(eye.dork_categories.keys())
    else:
        categories_to_run = [cat.strip().lower() for cat in args.categories.split(',')]
        # Validate categories
        valid_categories = []
        for cat in categories_to_run:
            if cat in eye.dork_categories:
                valid_categories.append(cat)
            else:
                print(f"[!] Warning: Unknown category '{cat}'")
        
        if not valid_categories:
            print("[!] No valid categories specified. Available categories:")
            eye.list_categories()
            return
        
        categories_to_run = valid_categories
    
    print(f"[+] Running categories: {', '.join(categories_to_run)}")
    print()
    
    # Create output directory if needed
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)) if os.path.dirname(args.output) else '.', exist_ok=True)
        
        # Write header to output file
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"ThirdEye Scan Report\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Domain: {args.domain}\n")
            f.write(f"Categories: {', '.join(categories_to_run)}\n")
            f.write("="*60 + "\n\n")
    
    # Run the scan
    start_time = time.time()
    
    if len(categories_to_run) == len(eye.dork_categories):
        eye.run_all()
    else:
        for category in categories_to_run:
            eye.run_category(category)
    
    elapsed_time = time.time() - start_time
    
    print(f"\n{'='*60}")
    print("[+] Scan completed!")
    print(f"[+] Total time: {elapsed_time:.2f} seconds")
    if args.output:
        print(f"[+] Results saved to: {args.output}")
    print(f"{'='*60}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
