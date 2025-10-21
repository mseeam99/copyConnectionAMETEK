import socket
import struct
from typing import Tuple, List, Dict, Any

print("TCP/IP FILE STARTED..........")


class ModbusError(RuntimeError):
    """Raised on Modbus exception responses or malformed frames."""


# ==========================================================
# FC03 — Read Holding Registers (helper)
# ==========================================================
def read_holding_registers_fc03(
    ip: str,
    port: int,
    transaction_id: int,  # u16
    unit_id: int,         # u8
    start_address: int,   # u16
    quantity: int,        # u16 (1..125 typical)
    timeout: float = 3.0
) -> List[int]:
    """Modbus/TCP: Function 0x03 — Read Holding Registers; returns list of u16 values."""
    if not (1 <= quantity <= 125):
        raise ValueError("quantity must be 1..125")

    def _u8(name: str, v: int) -> None:
        if not (0 <= v <= 0xFF):
            raise ValueError(f"{name} must be 0..255 (u8). Got {v}.")

    def _u16(name: str, v: int) -> None:
        if not (0 <= v <= 0xFFFF):
            raise ValueError(f"{name} must be 0..65535 (u16). Got {v}.")

    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed before receiving expected bytes.")
            buf.extend(chunk)
        return bytes(buf)

    _u16("transaction_id", transaction_id)
    _u8("unit_id", unit_id)
    _u16("start_address", start_address)
    _u16("quantity", quantity)

    function_code = 0x03
    pdu = struct.pack(">BHH", function_code, start_address & 0xFFFF, quantity & 0xFFFF)

    proto_id = 0x0000
    length = 1 + len(pdu)  # Unit(1) + PDU(5)
    mbap = struct.pack(">HHHB", transaction_id & 0xFFFF, proto_id, length, unit_id & 0xFF)
    req = mbap + pdu

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.sendall(req)
        hdr = _recv_exact(sock, 7)
        rx_txid, rx_proto, rx_len, rx_unit = struct.unpack(">HHHB", hdr)
        if rx_proto != 0x0000:
            raise ModbusError(f"Unexpected Protocol ID: 0x{rx_proto:04X}")
        remaining = rx_len - 1
        if remaining < 0:
            raise ModbusError(f"Bad length in MBAP: {rx_len}")
        pdu_resp = _recv_exact(sock, remaining)

    fc = pdu_resp[0]
    if fc == (function_code | 0x80):
        ex_code = pdu_resp[1] if len(pdu_resp) > 1 else 0
        raise ModbusError(f"Modbus exception (FC03): 0x{ex_code:02X}")
    if fc != function_code:
        raise ModbusError(f"Unexpected function in response: 0x{fc:02X}")

    if len(pdu_resp) < 2:
        raise ModbusError("Short FC03 PDU.")

    byte_count = pdu_resp[1]
    if byte_count != 2 * quantity or len(pdu_resp) != 2 + byte_count:
        raise ModbusError(f"FC03 byte count mismatch: got {byte_count}, expected {2*quantity}.")

    regs = list(struct.unpack(">" + "H" * quantity, pdu_resp[2:2 + byte_count]))
    return regs


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

    def _u8(name: str, v: int) -> None:
        if not (0 <= v <= 0xFF):
            raise ValueError(f"{name} must be 0..255 (u8). Got {v}.")

    def _u16(name: str, v: int) -> None:
        if not (0 <= v <= 0xFFFF):
            raise ValueError(f"{name} must be 0..65535 (u16). Got {v}.")

    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed before receiving expected bytes.")
            buf.extend(chunk)
        return bytes(buf)

    _u16("transaction_id", transaction_id)
    _u8("unit_id", unit_id)
    _u16("address", address)
    _u16("value", value)

    function_code = 0x06
    pdu = struct.pack(">BHH", function_code, address & 0xFFFF, value & 0xFFFF)

    proto_id = 0x0000
    length = 1 + len(pdu)  # Unit(1) + PDU(5) = 6
    mbap = struct.pack(">HHHB", transaction_id & 0xFFFF, proto_id, length, unit_id & 0xFF)
    req = mbap + pdu

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.sendall(req)
        hdr = _recv_exact(sock, 7)
        rx_txid, rx_proto, rx_len, rx_unit = struct.unpack(">HHHB", hdr)
        if rx_proto != 0x0000:
            raise ModbusError(f"Unexpected Protocol ID: 0x{rx_proto:04X}")
        remaining = rx_len - 1
        if remaining < 0:
            raise ModbusError(f"Bad length in MBAP: {rx_len}")
        pdu_resp = _recv_exact(sock, remaining)
        if not pdu_resp:
            raise ConnectionError("No PDU received.")

    fc = pdu_resp[0]
    if fc == (function_code | 0x80):
        ex_code = pdu_resp[1] if len(pdu_resp) > 1 else 0
        raise ModbusError(f"Modbus exception (FC06): 0x{ex_code:02X}")
    if fc != function_code:
        raise ModbusError(f"Unexpected function in response: 0x{fc:02X}")
    if len(pdu_resp) != 5:
        raise ModbusError(f"Unexpected PDU length for FC06: {len(pdu_resp)} (expected 5).")

    echo_addr, echo_val = struct.unpack(">HH", pdu_resp[1:5])

    if rx_unit != (unit_id & 0xFF):
        raise ModbusError(f"Unit ID mismatch: got {rx_unit}, expected {unit_id & 0xFF}.")
    if rx_txid != (transaction_id & 0xFFFF):
        raise ModbusError(f"Transaction ID mismatch: got {rx_txid}, expected {transaction_id & 0xFFFF}.")

    return echo_addr, echo_val


# ==========================================================
# Helpers
# ==========================================================
def segment_start(program_base_block0: int, segment_number: int) -> int:
    """
    EPC3000 (2400-compatible) layout:
      Program-1 block0 (Program General Data) starts at base (e.g., 8328).
      Segment N (1..16) starts at base + 8*N  (seg1=8336, seg2=8344 when base=8328).
    """
    if segment_number < 1 or segment_number > 16:
        raise ValueError("segment_number must be 1..16 for the 2400-compatible area.")
    return (program_base_block0 & 0xFFFF) + 8 * segment_number


def verify_ramp_rate_mode(ip: str, port: int, unit_id: int, segment_number: int, program1_block0_base: int) -> None:
    """Read back +0..+2 and assert s.type==1 so +2 is interpreted as RATE (not TIME)."""
    start = segment_start(program1_block0_base, segment_number)
    regs = read_holding_registers_fc03(
        ip, port, transaction_id=0x7100 + segment_number, unit_id=unit_id,
        start_address=start, quantity=3, timeout=3.0
    )
    s_type, tsp, param = regs[0], regs[1], regs[2]
    print(f"seg{segment_number} verify: s.type={s_type} (1=RAMP/RATE, 2=TIME), tsp={tsp}, +2={param}")
    if s_type != 1:
        raise ModbusError(
            f"Segment {segment_number} is not RATE (s.type={s_type}). "
            f"+2 will be treated as TIME-to-target, not RATE."
        )


# ==========================================================
# High-level: write only the fields your unit uses per type
# ==========================================================
def write_program_segment(
    ip: str,
    port: int,
    unit_id: int,
    *,
    segment_number: int,
    segment_type: str,          # "END","RAMP","TIME","DWELL","STEP","CALL"
    target_setpoint: int = 0,   # u16 scaled
    rate_time_or_dwell: int = 0,# u16 scaled (depends on type)
    call_or_end_type: int = 0,  # u16 (only for CALL/END)
    event_outputs_mask: int = 0,# u16 bitmask; optional
    program1_block0_base: int = 8328,
    verify_after_write: bool = True,
) -> None:
    """
    Per-type writes that match your EPC3008 behavior:
      RAMP : +0 type(=1 RATE), +1 target SP, +2 ramp RATE;           [ev.op at +4 if present]
      DWELL: +0 type(=3),           +2 duration;                     [ev.op at +4 if present]
      TIME : +0 type(=2), +1 target SP, +2 TIME-to-target;           [ev.op at +4 if present]
      STEP : +0 type(=4), +1 target SP;                              [ev.op at +4 if present]
      CALL : +0 type(=5),                +3 call program no;         [ev.op at +4 if present]
      END  : +0 type(=0); (no +3 on your unit)                       [ev.op at +4 if present]
    We NEVER write +5,+6,+7. We only try ev.op at +4 (no +3 fallback).
    """
    type_map = {"END":0, "RAMP":1, "TIME":2, "DWELL":3, "STEP":4, "CALL":5}
    if segment_type not in type_map:
        raise ValueError("segment_type must be one of: END,RAMP,TIME,DWELL,STEP,CALL.")

    seg_type_u16 = type_map[segment_type] & 0xFFFF
    tsp_u16      = int(target_setpoint) & 0xFFFF
    param_u16    = int(rate_time_or_dwell) & 0xFFFF
    call_end_u16 = int(call_or_end_type) & 0xFFFF
    ev_mask_u16  = int(event_outputs_mask) & 0xFFFF

    start = segment_start(program1_block0_base, segment_number)
    base_txid = 0x3000 + (segment_number & 0xFF) * 0x10

    # Always write +0 first: establishes RATE vs TIME interpretation of +2
    addr0 = start + 0
    txid0 = (base_txid + 0) & 0xFFFF
    echo_addr, echo_val = write_single_holding_register_fc06(ip, port, txid0, unit_id, addr0, seg_type_u16, timeout=3.0)
    print(f"seg{segment_number} +0 (type={segment_type} code={seg_type_u16}): -> echo {echo_addr}:{echo_val}")

    # Per-type plan (only the offsets your unit uses)
    plan: Dict[int, int] = {}
    if segment_type == "RAMP":          # RATE
        plan[1] = tsp_u16
        plan[2] = param_u16            # RAMP RATE (not time)
    elif segment_type == "DWELL":
        plan[2] = param_u16            # duration only
    elif segment_type == "TIME":
        plan[1] = tsp_u16
        plan[2] = param_u16            # TIME-to-target
    elif segment_type == "STEP":
        plan[1] = tsp_u16
    elif segment_type == "CALL":
        plan[3] = call_end_u16         # program number to call
    elif segment_type == "END":
        # Your unit: +3 empty/unused — do not write it
        pass

    # Write the planned offsets
    for off in sorted(plan.keys()):
        if off in (5, 6, 7):
            continue
        addr = start + off
        txid = (base_txid + off) & 0xFFFF
        val = plan[off] & 0xFFFF
        echo_addr, echo_val = write_single_holding_register_fc06(ip, port, txid, unit_id, addr, val, timeout=3.0)
        print(f"seg{segment_number} +{off}: wrote 0x{val:04X} -> echo {echo_addr}:{echo_val}")

    # Optional per-segment events — ONLY at +4 for your unit
    if ev_mask_u16:
        try:
            addr = start + 4
            txid = (base_txid + 4) & 0xFFFF
            echo_addr, echo_val = write_single_holding_register_fc06(
                ip, port, txid, unit_id, addr, ev_mask_u16, timeout=3.0
            )
            print(f"seg{segment_number} +4 (ev.op): wrote 0x{ev_mask_u16:04X} -> echo {echo_addr}:{echo_val}")
        except ModbusError as me:
            if "0x02" in str(me):
                print(f"seg{segment_number} +4 (ev.op) not mapped (0x02) — skipped")
            else:
                raise

    # Verify RAMP is in RATE mode so +2 was interpreted as rate
    if verify_after_write and segment_type == "RAMP":
        verify_ramp_rate_mode(ip, port, unit_id, segment_number, program1_block0_base)


def write_program(
    ip: str,
    port: int,
    unit_id: int,
    segments: List[Dict[str, Any]],
    *,
    start_segment: int = 1,
    program1_block0_base: int = 8328,
    verify_after_write: bool = True,
) -> None:
    """
    Write a sequence of segments starting at start_segment.
    Each item example:
      { "segment_type": "RAMP",  "target_setpoint": 111, "rate_time_or_dwell": 12, "event_outputs_mask": 0 }
      { "segment_type": "DWELL", "rate_time_or_dwell": 99,                          "event_outputs_mask": 0 }
      { "segment_type": "END",   "event_outputs_mask": 0 }
    """
    if not segments:
        return
    if not (1 <= start_segment <= 16):
        raise ValueError("start_segment must be 1..16")
    if start_segment - 1 + len(segments) > 16:
        raise ValueError("sequence would exceed 16 segments in the 2400-compatible area")

    for idx, seg in enumerate(segments):
        seg_no = start_segment + idx
        write_program_segment(
            ip, port, unit_id,
            segment_number=seg_no,
            segment_type=seg["segment_type"],
            target_setpoint=seg.get("target_setpoint", 0),
            rate_time_or_dwell=seg.get("rate_time_or_dwell", 0),
            call_or_end_type=seg.get("call_or_end_type", 0),
            event_outputs_mask=seg.get("event_outputs_mask", 0),
            program1_block0_base=program1_block0_base,
            verify_after_write=verify_after_write,
        )
        print(f"✔️ programmed segment {seg_no} ({seg['segment_type']})")


# ==========================================================
# Example usage — build any length you want (up to 16)
# ==========================================================
if __name__ == "__main__":
    IP = "10.17.100.101"
    PORT = 502
    UNIT = 1

    try:
        # Example: RAMP (rate) -> DWELL -> RAMP (rate) -> DWELL -> RAMP (rate) -> END
        sequence = [
            dict(segment_type="RAMP",  target_setpoint=20, rate_time_or_dwell=50, event_outputs_mask=1),
            dict(segment_type="DWELL",                      rate_time_or_dwell=20, event_outputs_mask=0),
            dict(segment_type="RAMP",  target_setpoint=20, rate_time_or_dwell=50, event_outputs_mask=0),
            dict(segment_type="DWELL",                      rate_time_or_dwell=80, event_outputs_mask=0),
            dict(segment_type="RAMP",  target_setpoint=90, rate_time_or_dwell=90, event_outputs_mask=0),
            dict(segment_type="END",   event_outputs_mask=1),
        ]

        # Program into Program 1, starting at segment 1 (seg1=8336, seg2=8344 when base=8328)
        write_program(
            IP, PORT, UNIT,
            segments=sequence,
            start_segment=1,
            program1_block0_base=8328,
            verify_after_write=True,  # proves s.type==1 after each RAMP
        )

        print("✅ Sequence written successfully!")
    except Exception as e:
        print("❌ ERROR:", e)

print("TCP/IP FILE ENDED..........")
