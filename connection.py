import socket
import struct
from typing import Tuple, List, Dict, Any

print("TCP/IP FILE STARTED..........")

class ModbusError(RuntimeError):
    """Raised on Modbus exception responses or malformed frames."""


# ==========================================================
# FC06 — Write Single Holding Register
# ==========================================================
def write_single_holding_register_fc06(
    ip: str,
    port: int,
    transaction_id: int,  # u16
    unit_id: int,         # u8
    address: int,         # u16
    value: int,           # u16
    timeout: float = 3.0
) -> Tuple[int, int]:
    """Modbus/TCP: Function 0x06 — Write Single Holding Register."""

    def _u8(name: str, v: int):
        if not (0 <= v <= 0xFF):
            raise ValueError(f"{name} must be 0–255.")
    def _u16(name: str, v: int):
        if not (0 <= v <= 0xFFFF):
            raise ValueError(f"{name} must be 0–65535.")

    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed early.")
            buf.extend(chunk)
        return bytes(buf)

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


# ==========================================================
# Helpers
# ==========================================================
def segment_start(program_base: int, seg_num: int) -> int:
    """
    Program 1 header starts at 8328.
    Segment 1 starts at 8336 (= 8328 + 8*1). Each segment block = +8 regs.
    """
    if not (1 <= seg_num <= 16):
        raise ValueError("segment_number must be 1–16")
    return (program_base & 0xFFFF) + 8 * seg_num


# ==========================================================
# 1) Write ONLY Program Header (8 registers at 8328..8335)
# ==========================================================
def write_program_header(
    ip: str,
    port: int,
    unit_id: int,
    *,
    program_base: int = 8328,
    p_num: int = 1,          # register +0
    hb_style: int = 0,       # +1
    hb_type: int = 0,        # +2
    hb_value: int = 0,       # +3
    ramp_units: int = 0,     # +4
    dwell_units: int = 0,    # +5
    cycle_program: int = 0,  # +6
    end_type: int = 0        # +7
) -> None:
    """
    Writes the first 8 program (header) registers starting at program_base (default 8328):
      +0 p.num, +1 hb.sty, +2 hb.typ, +3 hb.val,
      +4 rmp.u, +5 dwl.u, +6 p.cyc, +7 p.end
    """
    values = [p_num, hb_style, hb_type, hb_value, ramp_units, dwell_units, cycle_program, end_type]
    for i, val in enumerate(values):
        addr = program_base + i
        txid = (0x2100 + i) & 0xFFFF  # arbitrary txid pattern
        write_single_holding_register_fc06(ip, port, txid, unit_id, addr, int(val) & 0xFFFF)
        print(f"ProgramHeader +{i} @ {addr} = {val}")


# ==========================================================
# 2) Write ONLY Segments (no header)
#     RAMP uses TIME mode (type=2): +1 target SP, +2 time-to-target
#     DWELL (type=3): +2 dwell duration
#     END   (type=0): no extra fields
# ==========================================================
def write_segments(
    ip: str,
    port: int,
    unit_id: int,
    *,
    segments: List[Dict[str, Any]],
    start_segment: int = 1,
    program_base: int = 8328,
) -> None:
    """
    segments: list of dicts like:
      { "segment_type": "RAMP",  "target_setpoint": 120, "time_or_dwell": 50, "event_outputs_mask": 0 }
      { "segment_type": "DWELL",                         "time_or_dwell": 30, "event_outputs_mask": 0 }
      { "segment_type": "END",   "event_outputs_mask": 0 }
    """
    if not segments:
        return
    if not (1 <= start_segment <= 16):
        raise ValueError("start_segment must be 1..16")
    if start_segment - 1 + len(segments) > 16:
        raise ValueError("sequence would exceed 16 segments")

    type_map = {"END": 0, "RAMP": 2, "DWELL": 3}  # RAMP=TIME
    for idx, seg in enumerate(segments):
        seg_no = start_segment + idx
        s_type = seg["segment_type"]
        if s_type not in type_map:
            raise ValueError(f"Invalid segment_type: {s_type}")

        seg_type_code = type_map[s_type]
        tsp   = int(seg.get("target_setpoint", 0)) & 0xFFFF
        param = int(seg.get("time_or_dwell", 0)) & 0xFFFF
        ev    = int(seg.get("event_outputs_mask", 0)) & 0xFFFF

        start_addr = segment_start(program_base, seg_no)
        base_txid  = (0x3000 + (seg_no & 0xFF) * 0x10) & 0xFFFF

        # +0: type
        write_single_holding_register_fc06(ip, port, base_txid + 0, unit_id, start_addr + 0, seg_type_code)
        print(f"seg{seg_no} +0 type={s_type} ({seg_type_code})")

        # fields by type
        if s_type == "RAMP":
            write_single_holding_register_fc06(ip, port, base_txid + 1, unit_id, start_addr + 1, tsp)   # target SP
            write_single_holding_register_fc06(ip, port, base_txid + 2, unit_id, start_addr + 2, param) # time-to-target
            print(f"seg{seg_no} +1 tsp={tsp}, +2 time={param}")
        elif s_type == "DWELL":
            write_single_holding_register_fc06(ip, port, base_txid + 2, unit_id, start_addr + 2, param) # dwell time
            print(f"seg{seg_no} +2 dwell={param}")
        else:  # END
            pass

        # optional event outputs at +4 (ignore if 0)
        if ev:
            try:
                write_single_holding_register_fc06(ip, port, base_txid + 4, unit_id, start_addr + 4, ev)
                print(f"seg{seg_no} +4 event_mask=0x{ev:04X}")
            except ModbusError as e:
                if "0x02" in str(e):
                    print(f"seg{seg_no} +4 (events) not mapped — skipped")
                else:
                    raise


# ==========================================================
# Example usage (run separately when you want)
# ==========================================================
if __name__ == "__main__":
    IP = "10.17.100.101"
    PORT = 502
    UNIT = 1

    try:
        # (A) Write ONLY program header (8328..8335)


        # (B) Later, write ONLY segments starting at segment 1 (8336)
        segments = [
            dict(segment_type="RAMP",  target_setpoint=120, time_or_dwell=50, event_outputs_mask=0),
            dict(segment_type="DWELL",                         time_or_dwell=30, event_outputs_mask=0),
            dict(segment_type="DWELL",                         time_or_dwell=35, event_outputs_mask=0),
            dict(segment_type="DWELL",                         time_or_dwell=40, event_outputs_mask=0),
            dict(segment_type="RAMP",  target_setpoint=75,  time_or_dwell=40, event_outputs_mask=0),
            dict(segment_type="END",   event_outputs_mask=0),
            
        ]
        write_segments(IP, PORT, UNIT, segments=segments, start_segment=1, program_base=8328)

        print("✅ Done: header written, segments written.")
    except Exception as e:
        print("❌ ERROR:", e)

print("TCP/IP FILE ENDED..........")
