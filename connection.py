import socket
import struct
from typing import Tuple, List, Dict, Any

print("TCP/IP FILE STARTED..........")

class ModbusError(RuntimeError):
    """Raised on Modbus exception responses or malformed frames."""



# ==============================
# Low-level helpers
# ==============================
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed early.")
        buf.extend(chunk)
    return bytes(buf)

def _u8(name: str, v: int):
    if not (0 <= v <= 0xFF):
        raise ValueError(f"{name} must be 0–255.")

def _u16(name: str, v: int):
    if not (0 <= v <= 0xFFFF):
        raise ValueError(f"{name} must be 0–65535.")








# ==============================
# FC06 — Write Single Holding Register (u16)
# ==============================
def write_single_holding_register_fc06(
    transaction_id: int,
    address: int,
    value: int,
    timeout: float = 3.0,
    ip: str = "10.17.100.105",
    port: int = 502,
    unit_id: int = 2
) -> Tuple[int, int]:
    _u16("transaction_id", transaction_id)
    _u8("unit_id", unit_id)
    _u16("address", address)
    _u16("value", value)

    fc = 0x06
    pdu  = struct.pack(">BHH", fc, address & 0xFFFF, value & 0xFFFF)
    mbap = struct.pack(">HHHB", transaction_id & 0xFFFF, 0x0000, len(pdu) + 1, unit_id & 0xFF)
    req  = mbap + pdu

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.sendall(req)
        hdr = _recv_exact(sock, 7)
        rx_txid, rx_proto, rx_len, rx_unit = struct.unpack(">HHHB", hdr)
        if rx_proto != 0x0000:
            raise ModbusError(f"Unexpected Protocol ID: {rx_proto}")
        pdu_resp = _recv_exact(sock, rx_len - 1)
        if not pdu_resp:
            raise ConnectionError("No response received.")

    if pdu_resp[0] == (fc | 0x80):
        ex = pdu_resp[1] if len(pdu_resp) > 1 else 0
        raise ModbusError(f"Modbus exception (FC06): 0x{ex:02X}")

    echo_addr, echo_val = struct.unpack(">HH", pdu_resp[1:5])
    return echo_addr, echo_val


# ==============================
# FC16 — Write Multiple Holding Registers (for float32)
# ==============================
def write_multiple_holding_registers_fc16(
    transaction_id: int,
    address: int,           # starting register
    values: List[int],      # list of u16 words
    timeout: float = 3.0,
    ip: str = "10.17.100.105",
    port: int = 502,
    unit_id: int = 2
) -> Tuple[int, int]:
    _u16("transaction_id", transaction_id)
    _u8("unit_id", unit_id)
    _u16("address", address)
    if not values:
        raise ValueError("values must be non-empty")
    for i, w in enumerate(values):
        _u16(f"values[{i}]", w)

    fc = 0x10
    reg_count = len(values)
    byte_count = 2 * reg_count
    pdu = struct.pack(">BHHB", fc, address & 0xFFFF, reg_count & 0xFFFF, byte_count)
    pdu += struct.pack(">" + "H" * reg_count, *[w & 0xFFFF for w in values])

    mbap = struct.pack(">HHHB", transaction_id & 0xFFFF, 0x0000, len(pdu) + 1, unit_id & 0xFF)
    req  = mbap + pdu

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.sendall(req)
        hdr = _recv_exact(sock, 7)
        rx_txid, rx_proto, rx_len, rx_unit = struct.unpack(">HHHB", hdr)
        if rx_proto != 0x0000:
            raise ModbusError(f"Unexpected Protocol ID: {rx_proto}")
        pdu_resp = _recv_exact(sock, rx_len - 1)
        if not pdu_resp:
            raise ConnectionError("No response received.")

    if pdu_resp[0] == (fc | 0x80):
        ex = pdu_resp[1] if len(pdu_resp) > 1 else 0
        raise ModbusError(f"Modbus exception (FC16): 0x{ex:02X}")

    echo_addr, echo_count = struct.unpack(">HH", pdu_resp[1:5])
    return echo_addr, echo_count




# ==============================
# Float mirror helpers
# ==============================
def int_to_float_mirror(int_addr: int) -> int:
    """
    Map an integer register address to its floating-point mirror start address.
    From Bill: float_addr = 0x8000 + (int_addr * 2)
    Example: int 8201 -> float 49170 & 49171
    """
    _u16("int_addr", int_addr)
    return 0x8000 + (int_addr * 2)

def pack_float32_to_words(value: float) -> Tuple[int, int]:
    """
    Pack a Python float into two 16-bit words (big-endian IEEE-754).
    If your device expects word-swapped floats, swap the returned words.
    """
    b = struct.pack(">f", float(value))      # IEEE-754 big-endian
    hi, lo = struct.unpack(">HH", b)         # two 16-bit words
    return hi, lo


# ==============================
# High-level EPC writer (ONLY TSP as float)
# ==============================
def write_segments(
    segments: List[Dict[str, Any]],
    start_segment: int = 1,
    program_base: int = 8328,
    ip: str = "10.17.100.105",
    port: int = 502,
    unit_id: int = 2
) -> None:

    def segment_start(program_base_: int, seg_num: int) -> int:
        if not (1 <= seg_num <= 16):
            raise ValueError("segment_number must be 1–16")
        # seg1 starts at 8328 + 8 = 8336
        return (program_base_ & 0xFFFF) + (8 * seg_num)

    if not segments:
        return
    if not (1 <= start_segment <= 16):
        raise ValueError("start_segment must be 1..16")
    if start_segment - 1 + len(segments) > 16:
        raise ValueError("sequence would exceed 16 segments")

    type_map = {"END": 0, "RAMP": 2, "DWELL": 3}  # adjust if your manual differs

    for idx, seg in enumerate(segments):
        seg_no = start_segment + idx
        s_type = seg["segment_type"]
        if s_type not in type_map:
            raise ValueError(f"Invalid segment_type: {s_type}")

        seg_type_code = type_map[s_type]
        tsp   = float(seg.get("target_setpoint", 0.0))
        param = int(seg.get("time_or_dwell", 0)) & 0xFFFF  # integer in segment register
        ev    = int(seg.get("event_outputs_mask", 0)) & 0xFFFF

        start_addr = segment_start(program_base, seg_no)
        tx_base    = (0x3000 + (seg_no & 0xFF) * 0x10) & 0xFFFF

        # +0 Segment Type (int16 at normal segment address)
        write_single_holding_register_fc06(tx_base + 0, start_addr + 0, seg_type_code,
                                           ip=ip, port=port, unit_id=unit_id)
        print(f"seg{seg_no} @ {start_addr}: +0 type={s_type} ({seg_type_code})")

        if s_type == "RAMP":
            # +1 TSP — write to FLOAT MIRROR ONLY
            tsp_int_addr   = start_addr + 1
            tsp_float_addr = int_to_float_mirror(tsp_int_addr)  # 0x8000 + (int*2)
            w0, w1 = pack_float32_to_words(tsp)
            write_multiple_holding_registers_fc16(tx_base + 1, tsp_float_addr, [w0, w1],
                                                  ip=ip, port=port, unit_id=unit_id)
            print(f"seg{seg_no}: +1 TSP(float)={tsp} -> regs {tsp_float_addr},{tsp_float_addr+1}")

            # +2 TIME (or rate units) — keep in NORMAL SEGMENT REGISTER as int16
            write_single_holding_register_fc06(tx_base + 2, start_addr + 2, param,
                                               ip=ip, port=port, unit_id=unit_id)
            print(f"seg{seg_no}: +2 time/dwell(int)={param} -> reg {start_addr+2}")

        elif s_type == "DWELL":
            # +2 DWELL — NORMAL SEGMENT REGISTER as int16
            write_single_holding_register_fc06(tx_base + 2, start_addr + 2, param,
                                               ip=ip, port=port, unit_id=unit_id)
            print(f"seg{seg_no}: +2 dwell(int)={param} -> reg {start_addr+2}")

        else:
            # END: nothing else to write
            pass

        # +4 Events (int16 at normal int address)
        if ev:
            try:
                write_single_holding_register_fc06(tx_base + 4, start_addr + 4, ev,
                                                   ip=ip, port=port, unit_id=unit_id)
                print(f"seg{seg_no}: +4 event_mask=0x{ev:04X}")
            except ModbusError as e:
                if "0x02" in str(e):  # Illegal data address
                    print(f"seg{seg_no}: +4 (events) not mapped — skipped")
                else:
                    raise


def write_program_header(
    program_base: int,
    Program_Cycles_8332: int,
    Program_End_Type_8334: int,
    ip: str = "10.17.100.105",
    port: int = 502,
    unit_id: int = 2
) -> None:
   
    cyc  = int(Program_Cycles_8332)   & 0xFFFF
    pend = int(Program_End_Type_8334) & 0xFFFF

    addr = program_base + 4   # 8332 p.cyc
    write_single_holding_register_fc06(0x2104, addr, cyc, ip=ip, port=port, unit_id=unit_id)
    print(f"ProgramHeader @ {addr} (p.cyc / 8332) = {cyc}")

    addr = program_base + 6   # 8334 p.end
    write_single_holding_register_fc06(0x2106, addr, pend, ip=ip, port=port, unit_id=unit_id)
    print(f"ProgramHeader @ {addr} (p.end / 8334) = {pend}")



if __name__ == "__main__":
    try:
        write_program_header(
            program_base=8328,
            Program_Cycles_8332=2,
            Program_End_Type_8334=1,
        )

        segments = [
            dict(segment_type="RAMP",  target_setpoint=222.52,  time_or_dwell=89, event_outputs_mask=0),
            dict(segment_type="DWELL",                          time_or_dwell=30, event_outputs_mask=0),
            dict(segment_type="DWELL",                          time_or_dwell=35, event_outputs_mask=0),
            dict(segment_type="DWELL",                          time_or_dwell=40, event_outputs_mask=0),
            dict(segment_type="RAMP",  target_setpoint=23,       time_or_dwell=40, event_outputs_mask=0),
            dict(segment_type="END",   event_outputs_mask=0),
        ]

        write_segments(segments=segments, start_segment=1, program_base=8328)

        print("✅ Done: header written, segments written.")
    except Exception as e:
        print("❌ ERROR:", e)

print("TCP/IP FILE ENDED..........")
