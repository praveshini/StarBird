import sys

def ipfuscate(file_path):
    with open(file_path, "rb") as f:
        shellcode = f.read()

    # Padding: Ensure length is a multiple of 4
    padding = len(shellcode) % 4
    if padding != 0:
        print(f"[*] Padding shellcode with {4 - padding} NOPs...")
        shellcode += b"\x90" * (4 - padding)

    ip_list = []
    for i in range(0, len(shellcode), 4):
        # Grab 4 bytes and format as IP
        bytes_chunk = shellcode[i:i+4]
        ip = f"{bytes_chunk[0]}.{bytes_chunk[1]}.{bytes_chunk[2]}.{bytes_chunk[3]}"
        ip_list.append(f'"{ip}"')

    # Output formatted for Rust
    print("\n[+] Copy this into your Rust code:\n")
    print("let shellcode_ips = [")
    print("    " + ",\n    ".join(ip_list))
    print("];")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 obfuscate.py <payload.bin>")
    else:
        ipfuscate(sys.argv[1])
