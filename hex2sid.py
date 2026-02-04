# hex2sid.py
import sys

def hex_to_sid(hexstr):
    # acepta '0x...' o solo hex
    if hexstr.startswith("0x") or hexstr.startswith("0X"):
        hexstr = hexstr[2:]
    b = bytes.fromhex(hexstr)

    revision = b[0]
    subauth_count = b[1]
    id_auth = int.from_bytes(b[2:8], byteorder='big', signed=False)

    sid_parts = [f"S-{revision}-{id_auth}"]
    offset = 8
    for i in range(subauth_count):
        sub = int.from_bytes(b[offset:offset+4], byteorder='little', signed=False)
        sid_parts.append(str(sub))
        offset += 4

    return '-'.join(sid_parts)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 hex2sid.py 0xHEXSID")
        sys.exit(1)
    hexsid = sys.argv[1].strip()
    sid = hex_to_sid(hexsid)
    print("SID completo:   ", sid)
    # Domain SID = SID sin el último segmento (el RID)
    domain_sid = '-'.join(sid.split('-')[:-1])
    print("Domain SID:     ", domain_sid)

