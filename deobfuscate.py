import re
import base64

INPUT_FILE = "SPAM_BY_SHIN.py"   # rename if needed
OUTPUT_FILE = "decoded_output.py"


def extract_payload(code: str) -> bytes:
    """
    Extracts the first bytes literal b'....' from the code.
    """
    match = re.search(r"b'([^']+)'", code, re.DOTALL)
    if not match:
        match = re.search(r'b"([^"]+)"', code, re.DOTALL)

    if not match:
        raise ValueError("No b'...' payload found in file.")

    return match.group(1).encode()


def decode_payload(obf: bytes) -> bytes:
    """
    Safely decodes reversed urlsafe-base64 payload.
    NEVER executes the result.
    """
    try:
        rev = obf[::-1]
        decoded = base64.urlsafe_b64decode(rev)
        return decoded
    except Exception as e:
        print("Decoding failed:", e)
        return b""


def main():
    print("[*] Reading input file...")
    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    print("[*] Extracting obfuscated payload...")
    payload = extract_payload(content)

    print("[*] Decoding payload safely...")
    decoded = decode_payload(payload)

    print("[*] Writing decoded output...")
    with open(OUTPUT_FILE, "wb") as f:
        f.write(decoded)

    print("\n[✓] Done! Decoded file saved as:", OUTPUT_FILE)
    print("    (The decoded file was NOT executed — only extracted.)")


if __name__ == "__main__":
    main()    
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
