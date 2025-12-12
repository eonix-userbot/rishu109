#!/usr/bin/env python3
"""
Python Deobfuscator - Automatically decode and remove lambda-based obfuscation
Just run: python deobfuscate.py
"""

import re
import base64


def decode_reversed_base64(encoded_str):
    """Decode a reversed base64 string."""
    try:
        reversed_str = encoded_str[::-1]
        decoded = base64.urlsafe_b64decode(reversed_str)
        return decoded.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[Decoding error: {e}]"


def decode_base64(encoded_str):
    """Decode a regular base64 string."""
    try:
        decoded = base64.b64decode(encoded_str)
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        try:
            decoded = base64.urlsafe_b64decode(encoded_str)
            return decoded.decode('utf-8', errors='replace')
        except Exception as e:
            return f"[Decoding error: {e}]"


def find_and_decode(content):
    """Find all obfuscation patterns and decode them."""
    findings = []
    
    # Pattern 1: _ = lambda __ : __import__('base64').urlsafe_b64decode(__[::-1]);exec((_)(b'...'))
    lambda_pattern = r"_\s*=\s*lambda\s+__\s*:\s*__import__\s*\(\s*['\"]base64['\"]\s*\)\s*\.\s*urlsafe_b64decode\s*\(\s*__\s*\[\s*::\s*-1\s*\]\s*\)\s*;\s*exec\s*\(\s*\(\s*_\s*\)\s*\(\s*b['\"]([^'\"]+)['\"]\s*\)\s*\)"
    
    for match in re.finditer(lambda_pattern, content, re.MULTILINE | re.DOTALL):
        encoded = match.group(1)
        decoded = decode_reversed_base64(encoded)
        findings.append({
            'type': 'lambda + reversed base64',
            'match': match.group(0),
            'encoded': encoded,
            'decoded': decoded
        })
    
    # Pattern 2: exec(__import__('base64').b64decode(b'...'))
    exec_pattern = r"exec\s*\(\s*__import__\s*\(\s*['\"]base64['\"]\s*\)\s*\.\s*b64decode\s*\(\s*b['\"]([^'\"]+)['\"]\s*\)\s*\)"
    
    for match in re.finditer(exec_pattern, content, re.MULTILINE):
        encoded = match.group(1)
        decoded = decode_base64(encoded)
        findings.append({
            'type': 'exec + base64',
            'match': match.group(0),
            'encoded': encoded,
            'decoded': decoded
        })
    
    # Pattern 3: exec(__import__('base64').urlsafe_b64decode(b'...'))
    exec_urlsafe_pattern = r"exec\s*\(\s*__import__\s*\(\s*['\"]base64['\"]\s*\)\s*\.\s*urlsafe_b64decode\s*\(\s*b['\"]([^'\"]+)['\"]\s*\)\s*\)"
    
    for match in re.finditer(exec_urlsafe_pattern, content, re.MULTILINE):
        encoded = match.group(1)
        decoded = decode_base64(encoded)
        findings.append({
            'type': 'exec + urlsafe_b64decode',
            'match': match.group(0),
            'encoded': encoded,
            'decoded': decoded
        })
    
    return findings


def remove_obfuscation(content):
    """Remove obfuscation patterns from content."""
    patterns = [
        r"^\s*_\s*=\s*lambda\s+__\s*:\s*__import__\s*\(\s*['\"]base64['\"]\s*\).*?;.*?exec\s*\(\s*\(\s*_\s*\)\s*\(\s*b['\"].*?['\"]\s*\)\s*\)\s*$",
        r"^\s*exec\s*\(\s*__import__\s*\(\s*['\"]base64['\"]\s*\).*?\)\s*$",
    ]
    
    cleaned = content
    for pattern in patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.MULTILINE)
    
    # Clean up extra blank lines
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip() + '\n'


def main():
    print("\n" + "=" * 50)
    print("  Python Deobfuscator")
    print("=" * 50)
    
    filename = input("\nEnter Python filename: ").strip()
    
    if not filename:
        print("No filename entered.")
        return
    
    # Add .py extension if not present
    if not filename.endswith('.py'):
        filename += '.py'
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in current folder.")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    print(f"\nAnalyzing: {filename}")
    print("-" * 50)
    
    # Find and decode obfuscation
    findings = find_and_decode(content)
    
    if not findings:
        print("No obfuscation patterns detected.")
        return
    
    print(f"Found {len(findings)} obfuscation pattern(s):\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"[Pattern {i}] Type: {finding['type']}")
        print(f"Encoded: {finding['encoded'][:60]}..." if len(finding['encoded']) > 60 else f"Encoded: {finding['encoded']}")
        print(f"\nDecoded content:")
        print("-" * 40)
        print(finding['decoded'])
        print("-" * 40)
        print()
    
    # Ask to clean file
    choice = input("Remove obfuscation and save cleaned file? (y/n): ").strip().lower()
    
    if choice == 'y':
        cleaned = remove_obfuscation(content)
        output_name = filename.replace('.py', '_cleaned.py')
        
        with open(output_name, 'w', encoding='utf-8') as f:
            f.write(cleaned)
        
        print(f"\nCleaned file saved as: {output_name}")
    else:
        print("\nNo changes made.")


if __name__ == '__main__':
    main()
