from scapy.all import sniff, IP, ICMP, TCP, UDP, DNS, Raw
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue

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

def get_protocol_info(packet):
    """
    패킷의 프로토콜과 추가 정보를 반환합니다.
    TCP와 HTTP를 구분하기 위해 TCP 페이로드를 검사.
    """
    if ICMP in packet:
        protocol = "ICMP"
        extra_info = f"Type={packet[ICMP].type}, Code={packet[ICMP].code}"
    elif TCP in packet:
        if packet[TCP].sport == 80 or packet[TCP].dport == 80:
            # HTTP와 일반 TCP 구분
            if Raw in packet:
                payload = packet[Raw].load.decode(errors='ignore')
                if payload.startswith("GET") or payload.startswith("POST") or "HTTP" in payload:
                    protocol = "HTTP"
                else:
                    protocol = "TCP"
            else:
                protocol = "TCP"
            extra_info = f"SrcPort={packet[TCP].sport}, DstPort={packet[TCP].dport}"
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
            extra_info = f"SrcPort={packet[TCP].sport}, DstPort={packet[TCP].dport}"
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
            extra_info = f"SrcPort={packet[UDP].sport}, DstPort={packet[UDP].dport}"
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
        detail_window.geometry("600x400")
        
        text_area = tk.Text(detail_window, wrap="word", font=("Courier", 10))
        text_area.pack(fill="both", expand=True, padx=10, pady=10)
        text_area.insert("1.0", f"Source IP        : {packet[IP].src}\n")
        text_area.insert("end", f"Destination IP   : {packet[IP].dst}\n")
        text_area.insert("end", f"TTL (Time to Live): {packet[IP].ttl}\n")
        text_area.insert("end", f"Protocol         : {packet[IP].proto}\n")
        text_area.insert("end", f"Packet Length    : {len(packet)} bytes\n")
        
        # ICMP, TCP, UDP, HTTP 상세 처리
        if ICMP in packet:
            text_area.insert("end", f"ICMP Type        : {packet[ICMP].type}\n")
            text_area.insert("end", f"ICMP Code        : {packet[ICMP].code}\n")
        
        elif TCP in packet:
            text_area.insert("end", f"Source Port      : {packet[TCP].sport}\n")
            text_area.insert("end", f"Destination Port : {packet[TCP].dport}\n")
            text_area.insert("end", f"Flags            : {packet[TCP].flags}\n")
            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                # HTTP는 Raw 데이터에서 추가 정보 추출 가능
                if Raw in packet:
                    try:
                        http_payload = packet[Raw].load.decode(errors='ignore')
                        # 간단한 HTTP 요청/응답 파싱 (예: 첫 줄)
                        first_line = http_payload.split('\r\n')[0]
                        text_area.insert("end", f"HTTP Info        : {first_line}\n")
                    except:
                        text_area.insert("end", "HTTP Info        : Unable to decode\n")
        
        elif UDP in packet:
            text_area.insert("end", f"Source Port      : {packet[UDP].sport}\n")
            text_area.insert("end", f"Destination Port : {packet[UDP].dport}\n")
        
        # DNS 추가 정보
        if DNS in packet:
            if packet[DNS].qd:
                try:
                    qname = packet[DNS].qd.qname.decode()
                except:
                    qname = "Invalid Query"
                text_area.insert("end", f"DNS Query        : {qname}\n")
            else:
                text_area.insert("end", f"DNS Response\n")
        
        # Raw Payload
        text_area.insert("end", "\nRaw Payload:\n")
        if Raw in packet:
            try:
                raw_payload = packet[Raw].load.decode(errors='ignore')
            except:
                raw_payload = "Invalid Raw Data"
            text_area.insert("end", raw_payload)
        else:
            text_area.insert("end", "No Raw Data")
        text_area.config(state="disabled")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to display packet details: {e}")

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
    flow_tree.column("Type", width=100, anchor="center")
    flow_tree.column("Details", width=350, anchor="w")
    flow_tree.pack(fill="both", expand=True, padx=10, pady=10)

    # Flow 뷰 데이터 정리
    for idx, packet in enumerate(captured_packets):
        if packet_matches_filter(packet, ip_filter, protocol_filter):
            if IP in packet:
                protocol, extra_info = get_protocol_info(packet)
                if ICMP in packet:
                    pkt_type = "Request" if packet[ICMP].type == 8 else "Reply"
                elif TCP in packet:
                    if packet[TCP].flags == "S":
                        pkt_type = "SYN"
                    elif packet[TCP].flags == "SA":
                        pkt_type = "SYN-ACK"
                    elif packet[TCP].flags == "F":
                        pkt_type = "FIN"
                    else:
                        pkt_type = "Data"
                else:
                    pkt_type = "-"
                
                flow_tree.insert(
                    "",
                    "end",
                    values=(
                        idx + 1,
                        packet[IP].src,
                        packet[IP].dst,
                        protocol,
                        pkt_type,
                        extra_info
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
