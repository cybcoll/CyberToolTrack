#!/usr/bin/env python3
"""
Tiny Security-Adjacent LLM Tool - Indicator Extractor
Extracts IPs, domains, file paths, and usernames from incident notes.
"""

import re
import sys
import json
from typing import Set, Dict, List
from pathlib import Path
from urllib.parse import urlparse

class IncidentIndicatorExtractor:
    """Extract security indicators from plain-text incident notes."""
    
    def __init__(self):
        # IPv4 pattern (excludes private/internal ranges optionally)
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # Domain pattern (simplified, excludes IPs)
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        )
        
        # File path pattern (Windows and Unix)
        self.filepath_pattern = re.compile(
            r'(?:[a-zA-Z]:\\[^*|"<>?\n]*|/[^/*|"<>\n]*/(?:[^/*|"<>\n]*/)*[^/*|"<>\n]+)'
            r'|\.?/(?:[^/\s]+/)*[^/\s]+\.[a-zA-Z0-9]{2,4}'
            r'|C:\\[^*|"<>?\n]*\\[^*|"<>?\n]+\.\w+'
        )
        
        # Username pattern (common formats: domain\user, user@domain, just username)
        self.username_patterns = [
            re.compile(r'(?:[a-zA-Z0-9]+\\[a-zA-Z0-9._-]+)'),  # DOMAIN\user
            re.compile(r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b'),  # user@domain
            re.compile(r'\b(?:user|admin|root|[a-z]{3,20})\b', re.I),  # Basic usernames
        ]
    
    def extract_ips(self, text: str) -> Set[str]:
        """Extract IPv4 addresses."""
        ips = set()
        for match in self.ipv4_pattern.finditer(text):
            ip = match.group()
            # Filter out common false positives (version numbers, etc.)
            if not any(x in text[max(0, match.start()-5):match.end()+5] 
                      for x in ['version', 'v.', 'ver.']):
                ips.add(ip)
        return ips
    
    def extract_domains(self, text: str, exclude_ips: Set[str] = None) -> Set[str]:
        """Extract domain names (excludes IPs)."""
        domains = set()
        for match in self.domain_pattern.finditer(text):
            domain = match.group().lower()
            # Exclude if it looks like an IP
            if exclude_ips and domain in exclude_ips:
                continue
            # Filter common TLDs that might be false positives
            if domain.split('.')[-1] in ['com', 'org', 'net', 'edu', 'gov', 'mil', 
                                          'io', 'co', 'uk', 'de', 'fr', 'jp', 'cn',
                                          'ru', 'br', 'in', 'it', 'es', 'nl', 'ca',
                                          'au', 'local', 'internal', 'lan']:
                domains.add(domain)
        return domains
    
    def extract_filepaths(self, text: str) -> Set[str]:
        """Extract file paths (Windows and Unix)."""
        filepaths = set()
        for match in self.filepath_pattern.finditer(text):
            path = match.group().strip()
            # Minimum length validation
            if len(path) >= 3 and not path.endswith(('/', '\\')):
                filepaths.add(path)
        return filepaths
    
    def extract_usernames(self, text: str) -> Set[str]:
        """Extract usernames from various formats."""
        usernames = set()
        
        # Pattern 1: DOMAIN\username
        for match in self.username_patterns[0].finditer(text):
            usernames.add(match.group())
        
        # Pattern 2: user@domain (extract just the username part)
        for match in self.username_patterns[1].finditer(text):
            email = match.group()
            username = email.split('@')[0]
            usernames.add(username)
            usernames.add(email)  # Also keep full email
        
        # Pattern 3: Common usernames (with context)
        common_context = ['user', 'username', 'login', 'account', 'as ', 'by ']
        words = text.lower().split()
        for i, word in enumerate(words):
            # Check if word appears in security-relevant context
            if any(ctx in ' '.join(words[max(0,i-2):i+1]) for ctx in common_context):
                # Clean the word
                cleaned = re.sub(r'[^\w._-]', '', word)
                if len(cleaned) >= 3 and len(cleaned) <= 64:
                    usernames.add(cleaned)
        
        return usernames
    
    def extract_all(self, text: str) -> Dict[str, List[str]]:
        """Extract all indicators from text."""
        ips = self.extract_ips(text)
        domains = self.extract_domains(text, ips)
        filepaths = self.extract_filepaths(text)
        usernames = self.extract_usernames(text)
        
        return {
            'ips': sorted(list(ips)),
            'domains': sorted(list(domains)),
            'file_paths': sorted(list(filepaths)),
            'usernames': sorted(list(usernames))
        }

def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python incident_extractor.py <incident_note_file> [--json]")
        print("   or: cat incident.txt | python incident_extractor.py --stdin [--json]")
        sys.exit(1)
    
    use_json = '--json' in sys.argv
    extractor = IncidentIndicatorExtractor()
    
    # Read input
    if '--stdin' in sys.argv or sys.argv[1] == '-':
        text = sys.stdin.read()
    else:
        file_path = sys.argv[1]
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Extract indicators
    results = extractor.extract_all(text)
    
    # Output
    if use_json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "="*60)
        print("SECURITY INCIDENT INDICATORS")
        print("="*60)
        
        print(f"\n🌐 IP Addresses ({len(results['ips'])}):")
        for ip in results['ips']:
            print(f"  • {ip}")
        
        print(f"\n🏠 Domains ({len(results['domains'])}):")
        for domain in results['domains']:
            print(f"  • {domain}")
        
        print(f"\n📁 File Paths ({len(results['file_paths'])}):")
        for path in results['file_paths']:
            print(f"  • {path}")
        
        print(f"\n👤 Usernames ({len(results['usernames'])}):")
        for user in results['usernames']:
            print(f"  • {user}")
        
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    # Example usage demonstration
    example_text = """
    INCIDENT REPORT #2024-001
    
    Time: 2024-03-15 14:23:45 UTC
    Source IP: 192.168.1.100, Destination: 45.33.22.11
    Domain: evil-domain.com, subdomain.malware.net
    
    File paths accessed:
    C:\Windows\System32\cmd.exe
    /tmp/malware.sh
    ~/.ssh/id_rsa
    
    User account: jdoe executed the malicious file.
    Domain admin: CORP\asmith was also compromised.
    Email: attacker@breach-site.org
    
    Additional indicators:
    - Download from http://malicious-site.org/payload.exe
    - SSH key for user 'backdoor' found
    """
    
    print("DEMO MODE - Sample extraction:")
    extractor = IncidentIndicatorExtractor()
    demo_results = extractor.extract_all(example_text)
    print(json.dumps(demo_results, indent=2))
    print("\n" + "-"*60)
    print("For production use, provide a file as argument:")
    print("python incident_extractor.py incident_note.txt")
    print("-"*60)