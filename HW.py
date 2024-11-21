from scapy.all import sniff, IP, ICMP, TCP, UDP, DNS, Raw
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import struct
import socket
from datetime import datetime

# 전역 리스트로 캡처된 패킷 저장
captured_packets = []
packet_queue = queue.Queue()

def packet_matches_filter(packet, ip_filter, protocol_filter):
    """
    패킷이 주어진 IP 및 프로토콜 필터 조건에 맞는지 확인합니다.
    """
    # IP 필터 적용
    ip_match = True
    if ip_filter:
        if IP in packet:
            ip_match = (packet[IP].src == ip_filter) or (packet[IP].dst == ip_filter)
        else:
            ip_match = False

    # 프로토콜 필터 적용
    protocol_match = True
    if protocol_filter != "ALL":
        if protocol_filter == "HTTP":
            if TCP in packet and (packet[TCP].sport == 80 or packet[TCP].dport == 80):
                protocol_match = True
            else:
                protocol_match = False
        elif protocol_filter == "TCP":
            # HTTP는 별도로 처리되므로 TCP 필터링 시 포트 80 제외
            if TCP in packet and not (packet[TCP].sport == 80 or packet[TCP].dport == 80):
                protocol_match = True
            else:
                protocol_match = False
        elif protocol_filter == "UDP":
            protocol_match = UDP in packet
        elif protocol_filter == "ICMP":
            protocol_match = ICMP in packet
        elif protocol_filter == "DNS":
            protocol_match = (UDP in packet and DNS in packet) or (TCP in packet and DNS in packet)
        else:
            protocol_match = False  # 알 수 없는 프로토콜
    # 'ALL'일 경우 모든 프로토콜 허용

    # 두 조건 모두 만족할 때만 True 반환
    return ip_match and protocol_match

def compute_checksum(data):
    """
    인터넷 체크섬을 계산합니다.
    """
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = ~checksum & 0xffff
    return checksum

def verify_ip_checksum(ip_layer):
    """
    IP 헤더의 체크섬을 검증합니다.
    """
    ip_copy = ip_layer.copy()
    ip_copy.chksum = 0
    raw_bytes = bytes(ip_copy)[:ip_layer.ihl * 4]
    computed_checksum = compute_checksum(raw_bytes)
    return "Good" if computed_checksum == ip_layer.chksum else "Bad"

def verify_icmp_checksum(icmp_layer):
    """
    ICMP 체크섬을 검증합니다.
    """
    icmp_copy = icmp_layer.copy()
    icmp_copy.chksum = 0
    raw_bytes = bytes(icmp_copy)
    computed_checksum = compute_checksum(raw_bytes)
    return "Good" if computed_checksum == icmp_layer.chksum else "Bad"

def verify_tcp_checksum(ip_layer, tcp_layer):
    """
    TCP 체크섬을 검증합니다.
    """
    tcp_copy = tcp_layer.copy()
    tcp_copy.chksum = 0
    # Pseudo-header
    pseudo_header = struct.pack('!4s4sBBH', 
                                socket.inet_aton(ip_layer.src), 
                                socket.inet_aton(ip_layer.dst), 
                                0, 
                                ip_layer.proto, 
                                len(tcp_copy))
    raw_bytes = pseudo_header + bytes(tcp_copy)
    computed_checksum = compute_checksum(raw_bytes)
    return "Good" if computed_checksum == tcp_layer.chksum else "Bad"

def verify_udp_checksum(ip_layer, udp_layer):
    """
    UDP 체크섬을 검증합니다.
    """
    if udp_layer.chksum == 0:
        return "No Checksum"
    udp_copy = udp_layer.copy()
    udp_copy.chksum = 0
    # Pseudo-header
    pseudo_header = struct.pack('!4s4sBBH', 
                                socket.inet_aton(ip_layer.src), 
                                socket.inet_aton(ip_layer.dst), 
                                0, 
                                ip_layer.proto, 
                                len(udp_copy))
    raw_bytes = pseudo_header + bytes(udp_copy)
    computed_checksum = compute_checksum(raw_bytes)
    return "Good" if computed_checksum == udp_layer.chksum else "Bad"

def get_protocol_info(packet):
    """
    패킷의 프로토콜과 추가 정보를 반환합니다.
    각 프로토콜에 대한 상세 정보를 포함합니다.
    """
    if ICMP in packet:
        protocol = "ICMP"
        # 기본 정보
        extra_info = f"Type={packet[ICMP].type}, Code={packet[ICMP].code}, Checksum={hex(packet[ICMP].chksum)}"
    elif TCP in packet:
        if packet[TCP].sport == 80 or packet[TCP].dport == 80:
            # HTTP와 일반 TCP 구분
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode(errors='ignore')
                    if payload.startswith("GET") or payload.startswith("POST") or "HTTP" in payload:
                        protocol = "HTTP"
                    else:
                        protocol = "TCP"
                except:
                    protocol = "TCP"
            else:
                protocol = "TCP"
            extra_info = f"SrcPort={packet[TCP].sport}, DstPort={packet[TCP].dport}, Flags={packet[TCP].flags}, Seq={packet[TCP].seq}, Ack={packet[TCP].ack}"
        elif DNS in packet:
            protocol = "DNS"
            if packet[DNS].qd:
                try:
                    qname = packet[DNS].qd.qname.decode()
                except:
                    qname = "Invalid Query"
                extra_info = f"Query={qname}"
            else:
                extra_info = "Response"
        else:
            protocol = "TCP"
            extra_info = f"SrcPort={packet[TCP].sport}, DstPort={packet[TCP].dport}, Flags={packet[TCP].flags}, Seq={packet[TCP].seq}, Ack={packet[TCP].ack}"
    elif UDP in packet:
        if DNS in packet:
            protocol = "DNS"
            if packet[DNS].qd:
                try:
                    qname = packet[DNS].qd.qname.decode()
                except:
                    qname = "Invalid Query"
                extra_info = f"Query={qname}"
            else:
                extra_info = "Response"
        else:
            protocol = "UDP"
            extra_info = f"SrcPort={packet[UDP].sport}, DstPort={packet[UDP].dport}, Length={packet[UDP].len}, Checksum={hex(packet[UDP].chksum)}"
    else:
        protocol = "Unknown"
        extra_info = "-"
    return protocol, extra_info

# 패킷 캡처 콜백 함수
def packet_callback(packet):
    if IP in packet:  # IP 계층 패킷만 처리
        packet_queue.put(packet)

# 큐에서 패킷을 가져와 처리하고 GUI 업데이트
def process_packets():
    ip_filter = ip_filter_entry.get().strip()
    protocol_filter = protocol_combobox.get().strip().upper()
    while not packet_queue.empty():
        packet = packet_queue.get()
        captured_packets.append(packet)
        if packet_matches_filter(packet, ip_filter, protocol_filter):
            protocol, extra_info = get_protocol_info(packet)
            # 리스트뷰에 표시 (필터에 맞는 경우)
            add_packet_to_tree(len(captured_packets), packet, protocol, extra_info)
    root.after(100, process_packets)  # 100ms마다 다시 호출

# 패킷을 Treeview에 추가하는 함수
def add_packet_to_tree(no, packet, protocol, extra_info):
    try:
        packet_tree.insert(
            "", "end",
            values=(
                no,
                packet[IP].src, 
                packet[IP].dst, 
                packet[IP].ttl, 
                protocol, 
                extra_info
            )
        )
    except Exception as e:
        print(f"Error inserting packet into tree: {e}")

# 캡처 중지 및 UI 업데이트
def stop_sniffing():
    sniff_running.set(False)
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

# 선택한 패킷의 상세 정보 표시
def show_packet_details(packet, packet_no):
    try:
        # 새로운 창에서 상세 정보 표시
        detail_window = tk.Toplevel(root)
        detail_window.title(f"Packet {packet_no} Details")
        detail_window.geometry("700x600")
        
        text_area = tk.Text(detail_window, wrap="word", font=("Courier", 10))
        text_area.pack(fill="both", expand=True, padx=10, pady=10)
        
        # IP 계층 정보
        text_area.insert("1.0", f"Source IP        : {packet[IP].src}\n")
        text_area.insert("end", f"Destination IP   : {packet[IP].dst}\n")
        text_area.insert("end", f"Version          : {packet[IP].version}\n")
        text_area.insert("end", f"Header Length    : {packet[IP].ihl * 4} bytes\n")
        text_area.insert("end", f"Differentiated Services Field: {packet[IP].tos}\n")
        text_area.insert("end", f"Total Length     : {packet[IP].len}\n")
        text_area.insert("end", f"Identification   : {hex(packet[IP].id)} ({packet[IP].id})\n")
        text_area.insert("end", f"Flags            : {packet[IP].flags}\n")
        text_area.insert("end", f"Fragment Offset  : {packet[IP].frag}\n")
        text_area.insert("end", f"TTL (Time to Live): {packet[IP].ttl}\n")
        text_area.insert("end", f"Protocol         : {packet[IP].proto}\n")
        # IP 체크섬 상태 표시
        ip_checksum_status = verify_ip_checksum(packet[IP])
        text_area.insert("end", f"Checksum         : {hex(packet[IP].chksum)} [{ip_checksum_status}]\n")
        text_area.insert("end", f"Packet Length    : {len(packet)} bytes\n")
        
        # ICMP, TCP, UDP, HTTP 상세 처리
        if ICMP in packet:
            text_area.insert("end", f"\nInternet Control Message Protocol\n")
            text_area.insert("end", f"Type             : {packet[ICMP].type} ({icmp_type_description(packet[ICMP].type)})\n")
            text_area.insert("end", f"Code             : {packet[ICMP].code}\n")
            # 체크섬 상태 확인 및 표시
            icmp_checksum_status = verify_icmp_checksum(packet[ICMP])
            text_area.insert("end", f"Checksum         : {hex(packet[ICMP].chksum)} [{icmp_checksum_status}]\n")
            # Response frame (패킷 번호 사용)
            text_area.insert("end", f"[Response frame:] {packet_no}\n")
            # Data length
            if Raw in packet:
                data_length = len(packet[Raw].load)
                text_area.insert("end", f"Data ({data_length} bytes):\n")
                # Display data in hexadecimal
                data_hex = ' '.join(f"{byte:02x}" for byte in packet[Raw].load)
                text_area.insert("end", f"{data_hex}\n")
            else:
                text_area.insert("end", "Data (0 bytes): No Data\n"
                )
        
        elif TCP in packet:
            text_area.insert("end", f"\nTCP Header:\n")
            text_area.insert("end", f"Source Port      : {packet[TCP].sport}\n")
            text_area.insert("end", f"Destination Port : {packet[TCP].dport}\n")
            text_area.insert("end", f"Sequence Number  : {packet[TCP].seq}\n")
            text_area.insert("end", f"Acknowledgment Number: {packet[TCP].ack}\n")
            text_area.insert("end", f"Data Offset      : {packet[TCP].dataofs * 4} bytes\n")
            text_area.insert("end", f"Flags            : {packet[TCP].flags}\n")
            # TCP 체크섬 상태 표시
            tcp_checksum_status = verify_tcp_checksum(packet[IP], packet[TCP])
            text_area.insert("end", f"Checksum         : {hex(packet[TCP].chksum)} [{tcp_checksum_status}]\n")
            text_area.insert("end", f"Window Size      : {packet[TCP].window}\n")
            text_area.insert("end", f"Urgent Pointer   : {packet[TCP].urgptr}\n")
            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                # HTTP는 Raw 데이터에서 추가 정보 추출 가능
                if Raw in packet:
                    try:
                        http_payload = packet[Raw].load.decode(errors='ignore')
                        # 간단한 HTTP 요청/응답 파싱 (예: 첫 줄)
                        first_line = http_payload.split('\r\n')[0]
                        text_area.insert("end", f"\nHTTP Info:\n{first_line}\n")
                    except:
                        text_area.insert("end", "HTTP Info        : Unable to decode\n")
                else:
                    text_area.insert("end", "No HTTP Data\n")
            else:
                if Raw in packet:
                    text_area.insert("end", "\nTCP Payload:\n")
                    try:
                        tcp_payload = packet[Raw].load.decode(errors='ignore')
                        text_area.insert("end", tcp_payload)
                    except:
                        text_area.insert("end", "Unable to decode TCP payload.\n")
                else:
                    text_area.insert("end", "No TCP Payload\n")
        
        elif UDP in packet:
            text_area.insert("end", f"\nUDP Header:\n")
            text_area.insert("end", f"Source Port      : {packet[UDP].sport}\n")
            text_area.insert("end", f"Destination Port : {packet[UDP].dport}\n")
            text_area.insert("end", f"Length           : {packet[UDP].len}\n")
            # UDP 체크섬 상태 표시
            udp_checksum_status = verify_udp_checksum(packet[IP], packet[UDP])
            text_area.insert("end", f"Checksum         : {hex(packet[UDP].chksum)} [{udp_checksum_status}]\n")
            if Raw in packet:
                data_length = len(packet[Raw].load)
                text_area.insert("end", f"Data ({data_length} bytes):\n")
                try:
                    udp_payload = packet[Raw].load.decode(errors='ignore')
                    text_area.insert("end", udp_payload)
                except:
                    text_area.insert("end", "Unable to decode UDP payload.\n")
            else:
                text_area.insert("end", "Data (0 bytes): No Data\n")
        
        # DNS 추가 정보
        if DNS in packet:
            text_area.insert("end", f"\nDNS Details:\n")
            if packet[DNS].qd:
                try:
                    qname = packet[DNS].qd.qname.decode()
                except:
                    qname = "Invalid Query"
                text_area.insert("end", f"DNS Query        : {qname}\n")
            else:
                text_area.insert("end", f"DNS Response\n")
                # Include answers
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        rr = packet[DNS].an[i]
                        try:
                            rrname = rr.rrname.decode()
                        except:
                            rrname = "Invalid RR Name"
                        try:
                            rdata = rr.rdata.decode()
                        except:
                            rdata = str(rr.rdata)
                        text_area.insert("end", f"Answer {i+1}: {rrname} {rdata}\n")
        
        # Raw Payload (기타 프로토콜의 경우)
        if Raw in packet and not (ICMP in packet or TCP in packet or UDP in packet):
            text_area.insert("end", "\nRaw Payload:\n")
            try:
                raw_payload = packet[Raw].load.decode(errors='ignore')
            except:
                raw_payload = "Invalid Raw Data"
            text_area.insert("end", raw_payload)
        
        text_area.config(state="disabled")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to display packet details: {e}")

def icmp_type_description(icmp_type):
    """
    ICMP 타입에 대한 설명을 반환합니다.
    """
    descriptions = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo (ping) request",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp",
        14: "Timestamp Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply",
    }
    return descriptions.get(icmp_type, "Unknown")

def parse_icmp_timestamp(packet, packet_no):
    """
    ICMP 데이터에서 타임스탬프를 추출하고 상대 시간을 계산합니다.
    """
    timestamp_str = "N/A"
    relative_time = "N/A"
    if Raw in packet:
        try:
            # Assuming the timestamp is a readable string in the payload
            payload_str = packet[Raw].load.decode(errors='ignore')
            # Example: "Timestamp from ICMP data: Nov 11, 2024 18:04:36.000000000 KST"
            if "Timestamp from ICMP data:" in payload_str:
                timestamp_part = payload_str.split("Timestamp from ICMP data:")[1].split("\n")[0].strip()
                timestamp_str = timestamp_part
                # Parse the timestamp
                try:
                    # Remove timezone for parsing
                    timestamp_dt = datetime.strptime(timestamp_part.split(" KST")[0], "%b %d, %Y %H:%M:%S.%f")
                    current_time = datetime.now()
                    delta = current_time - timestamp_dt
                    relative_time = f"{delta.total_seconds():.9f}"
                except:
                    relative_time = "Invalid Timestamp Format"
        except:
            pass
    return timestamp_str, relative_time

# 패킷 캡처 스레드
def start_sniffing():
    sniff_running.set(True)
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    sniff_thread = threading.Thread(
        target=sniff_packets,
        daemon=True  # 메인 스레드 종료 시 함께 종료되도록 설정
    )
    sniff_thread.start()

def sniff_packets():
    try:
        sniff(
            filter="ip",
            prn=packet_callback,
            stop_filter=lambda x: not sniff_running.get(),
            store=False
        )
    except Exception as e:
        print(f"Sniffing error: {e}")

# 캡처된 패킷 초기화
def reset_packets():
    global captured_packets
    captured_packets = []
    for item in packet_tree.get_children():
        packet_tree.delete(item)

# 필터링된 패킷만 화면에 표시
def display_filtered_packets():
    # 현재 필터 조건 가져오기
    ip_filter = ip_filter_entry.get().strip()
    protocol_filter = protocol_combobox.get().strip().upper()
    
    # Treeview 초기화
    for item in packet_tree.get_children():
        packet_tree.delete(item)
    
    # 캡처된 패킷 중 필터에 맞는 패킷만 표시
    for i, packet in enumerate(captured_packets):
        if packet_matches_filter(packet, ip_filter, protocol_filter):
            protocol, extra_info = get_protocol_info(packet)
            # 리스트뷰에 표시
            add_packet_to_tree(i + 1, packet, protocol, extra_info)

# 패킷 더블클릭 이벤트 연결
def on_item_double_click(event):
    selected_item = packet_tree.selection()
    if not selected_item:
        messagebox.showwarning("Warning", "Please select a packet.")
        return

    try:
        index = int(packet_tree.item(selected_item)["values"][0]) - 1
        packet = captured_packets[index]
        show_packet_details(packet, index + 1)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve packet details: {e}")

# Flow 버튼 클릭 시 실행할 함수
def show_flow_view():
    """
    Flow 버튼을 클릭하면 Flow 뷰를 보여주는 새 창을 엽니다.
    패킷 송신지-목적지 쌍별로 요청(Request)과 응답(Reply)을 정리합니다.
    """
    # 현재 필터 조건 가져오기
    ip_filter = ip_filter_entry.get().strip()
    protocol_filter = protocol_combobox.get().strip().upper()
    
    flow_window = tk.Toplevel(root)
    flow_window.title("Flow View")
    flow_window.geometry("900x500")
    
    # Treeview 생성
    flow_tree = ttk.Treeview(
        flow_window,
        columns=("No", "Source", "Destination", "Protocol", "Type", "Details"),
        show="headings",
        height=20
    )
    flow_tree.heading("No", text="No.")
    flow_tree.heading("Source", text="Source IP")
    flow_tree.heading("Destination", text="Destination IP")
    flow_tree.heading("Protocol", text="Protocol")
    flow_tree.heading("Type", text="Type (Request/Reply)")
    flow_tree.heading("Details", text="Details")
    
    flow_tree.column("No", width=50, anchor="center")
    flow_tree.column("Source", width=150, anchor="center")
    flow_tree.column("Destination", width=150, anchor="center")
    flow_tree.column("Protocol", width=100, anchor="center")
    flow_tree.column("Type", width=150, anchor="center")
    flow_tree.column("Details", width=350, anchor="w")
    flow_tree.pack(fill="both", expand=True, padx=10, pady=10)

    # Flow 뷰 데이터 정리
    for idx, packet in enumerate(captured_packets):
        if packet_matches_filter(packet, ip_filter, protocol_filter):
            if IP in packet:
                protocol, extra_info = get_protocol_info(packet)
                pkt_type = "-"
                details = extra_info
                if ICMP in packet:
                    if packet[ICMP].type == 8:
                        pkt_type = "Request"
                    elif packet[ICMP].type == 0:
                        pkt_type = "Reply"
                    else:
                        pkt_type = "Other"
                elif TCP in packet:
                    flags = packet[TCP].flags
                    if flags == "S":
                        pkt_type = "SYN"
                    elif flags == "SA":
                        pkt_type = "SYN-ACK"
                    elif flags == "F":
                        pkt_type = "FIN"
                    elif flags == "A":
                        pkt_type = "ACK"
                    else:
                        pkt_type = "Data"
                elif UDP in packet:
                    pkt_type = "Data"
                flow_tree.insert(
                    "",
                    "end",
                    values=(
                        idx + 1,
                        packet[IP].src,
                        packet[IP].dst,
                        protocol,
                        pkt_type,
                        details
                    )
                )

# tkinter 초기화
root = tk.Tk()
root.title("Packet Viewer")
root.geometry("900x600")  # 크기 조정

sniff_running = tk.BooleanVar(value=False)

# GUI 구성
frame = tk.Frame(root)
frame.pack(fill="both", expand=True, padx=10, pady=10)

# 필터 입력창 추가 (IP와 프로토콜로 분할)
filter_frame = tk.Frame(root)
filter_frame.pack(fill="x", pady=5)

# IP 필터
ip_label = tk.Label(filter_frame, text="IP Address:")
ip_label.pack(side="left", padx=5)
ip_filter_entry = tk.Entry(filter_frame, width=30)
ip_filter_entry.pack(side="left", padx=5)

# 프로토콜 필터
protocol_label = tk.Label(filter_frame, text="Protocol:")
protocol_label.pack(side="left", padx=5)
protocol_combobox = ttk.Combobox(filter_frame, values=["ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP"], state="readonly", width=10)
protocol_combobox.current(0)  # 기본값은 ALL
protocol_combobox.pack(side="left", padx=5)

# Apply Filter 버튼
filter_btn = tk.Button(filter_frame, text="Apply Filter", command=display_filtered_packets)
filter_btn.pack(side="left", padx=5)

# Flow 버튼 추가
flow_btn = tk.Button(filter_frame, text="Flow", command=show_flow_view)
flow_btn.pack(side="left", padx=5)

# 패킷 리스트 표시
packet_tree = ttk.Treeview(frame, columns=("No", "Source", "Destination", "TTL", "Protocol", "Extra Info"), show="headings", height=20)
packet_tree.heading("No", text="No.")
packet_tree.heading("Source", text="Source IP")
packet_tree.heading("Destination", text="Destination IP")
packet_tree.heading("TTL", text="TTL")
packet_tree.heading("Protocol", text="Protocol")
packet_tree.heading("Extra Info", text="Extra Info")
packet_tree.column("No", width=50, anchor="center")
packet_tree.column("Source", width=150, anchor="center")
packet_tree.column("Destination", width=150, anchor="center")
packet_tree.column("TTL", width=50, anchor="center")
packet_tree.column("Protocol", width=100, anchor="center")
packet_tree.column("Extra Info", width=300, anchor="w")
packet_tree.pack(fill="both", expand=True)

# 패킷 더블클릭 이벤트 연결
packet_tree.bind("<Double-1>", on_item_double_click)

# 버튼 구성
btn_frame = tk.Frame(root)
btn_frame.pack(fill="x", pady=5)

start_btn = tk.Button(btn_frame, text="Start Capture", command=start_sniffing)
start_btn.pack(side="left", padx=5)

stop_btn = tk.Button(btn_frame, text="Stop Capture", state="disabled", command=stop_sniffing)
stop_btn.pack(side="left", padx=5)

reset_btn = tk.Button(btn_frame, text="Reset Packets", command=reset_packets)
reset_btn.pack(side="left", padx=5)

exit_btn = tk.Button(btn_frame, text="Exit", command=root.destroy)
exit_btn.pack(side="right", padx=5)

# 메인 루프 실행 전에 패킷 처리 함수 시작
root.after(100, process_packets)

# 메인 루프 실행
try:
    root.mainloop()
except KeyboardInterrupt:
    # 키보드 인터럽트 (Ctrl+C) 시 스니핑 중지
    sniff_running.set(False)
    root.destroy()
except Exception as e:
    messagebox.showerror("Error", f"An unexpected error occurred: {e}")
