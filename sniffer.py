import socket
import struct
import platform
import psutil
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime

# Dicionários para mapeamento de protocolos e portas conhecidas
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    41: "IPv6",
    89: "OSPF"
}

COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
    5353: "mDNS",
    1900: "UPnP",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    161: "SNMP",
    20: "FTP Data",
    21: "FTP Control",
    23: "Telnet",
    5060: "SIP",
    5222: "XMPP",
    5228: "Apple Push",
    5223: "Apple Push (SSL)",
    1935: "RTMP",
    3478: "STUN/TURN",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    3306: "MySQL",
    27017: "MongoDB",
    5357: "WS-Discovery",
    32400: "Plex",
    6881: "BitTorrent",
    9090: "Prometheus",
    9100: "Printer"
}

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return {
        'version': version,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'src_ip': socket.inet_ntoa(src),
        'dest_ip': socket.inet_ntoa(target),
        'data': data[header_length:]
    }

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack(
        '! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1
    }
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'sequence': sequence,
        'acknowledgment': acknowledgment,
        'flags': flags,
        'data': data[offset:]
    }

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'data': data[8:]
    }

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'proto': socket.ntohs(proto),
        'data': data[14:]
    }

def get_protocol_name(proto_num):
    return PROTOCOLS.get(proto_num, f"Protocolo {proto_num}")

def get_service_name(port):
    return COMMON_PORTS.get(port, f"Porta {port}")

def analyze_traffic(src_ip, dest_ip, src_port, dest_port, protocol, data=None):
    """Analisa o tráfego com mais inteligência para identificar atividades específicas"""
    is_internet = not (src_ip.startswith(('192.168.', '10.', '172.')) or 
                       dest_ip.startswith(('192.168.', '10.', '172.')))
    direction = "Enviando" if is_internet else "Recebendo"
    remote_ip = dest_ip if is_internet else src_ip
    service = get_service_name(dest_port) if is_internet else get_service_name(src_port)
    interpretation = ""
    activity = ""

    # HTTP/HTTPS análise
    if service in ["HTTP", "HTTPS"]:
        host = ""
        if data and len(data) > 0:
            try:
                decoded_data = data.decode('utf-8', errors='ignore').split('\r\n')
                for line in decoded_data:
                    if line.lower().startswith('host:'):
                        host = line[5:].strip()
                        break
                    elif line.startswith('GET') or line.startswith('POST'):
                        path = line.split(' ')[1]
                        if 'youtube' in path or 'youtu.be' in path:
                            host = "youtube.com"
                            activity = "Assistindo vídeo"
                        elif 'netflix' in path:
                            host = "netflix.com"
                            activity = "Assistindo Netflix"
            except:
                pass
        if host:
            interpretation = f"{direction} dados para {host} (HTTP)"
            if not activity:
                if 'youtube' in host:
                    activity = "Navegando no YouTube"
                elif 'google' in host:
                    activity = "Usando serviços Google"
                elif 'facebook' in host:
                    activity = "Navegando no Facebook"
                elif 'instagram' in host:
                    activity = "Navegando no Instagram"
                elif 'twitter' in host:
                    activity = "Navegando no Twitter"
                elif 'whatsapp' in host:
                    activity = "Usando WhatsApp Web"
        else:
            interpretation = f"{direction} tráfego web ({service})"

    elif service in ["RTMP", "Plex"]:
        interpretation = f"{direction} stream de mídia ({service})"
        activity = "Assistindo vídeo/transmissão"

    elif service in ["SMTP", "POP3", "IMAP"]:
        interpretation = f"{direction} e-mails ({service})"
        activity = "Enviando/Recebendo e-mails"

    elif service in ["XMPP", "SIP"]:
        interpretation = f"{direction} mensagens/ligações ({service})"
        activity = "Mensagens instantâneas/VoIP"

    elif service == "DNS":
        if direction == "Enviando":
            interpretation = "Resolvendo nome de domínio"
            activity = "Consultando DNS"
        else:
            interpretation = "Recebendo resposta DNS"

    elif service in ["SSH", "RDP"]:
        interpretation = f"{direction} conexão remota ({service})"
        activity = f"Conexão remota com {remote_ip}"

    elif service == "BitTorrent":
        interpretation = f"{direction} tráfego P2P"
        activity = "Baixando/Compartilhando via torrent"

    else:
        interpretation = f"{direction} tráfego {service}"
        if service.startswith("HTTP"):
            activity = "Navegando na web"
        elif service.startswith("HTTPS"):
            activity = "Navegando na web (seguro)"

    if not interpretation:
        if protocol == "TCP":
            if dest_port == 443 or src_port == 443:
                interpretation = f"{direction} dados criptografados (HTTPS)"
                activity = "Comunicação segura com servidor"
            elif dest_port == 80 or src_port == 80:
                interpretation = f"{direction} tráfego web (HTTP)"
                activity = "Navegando na web"
            else:
                interpretation = f"{direction} dados TCP"
        elif protocol == "UDP":
            interpretation = f"{direction} dados UDP"

    return {
        'service': service,
        'interpretation': interpretation,
        'activity': activity,
        'direction': direction,
        'remote_ip': remote_ip
    }

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniffer de Pacotes Avançado")
        self.sniffer = None
        self.sniffing = False
        self.thread = None
        self.setup_ui()

    def setup_ui(self):
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky='w')
        self.interface_var = tk.StringVar()
        self.interfaces = self.get_interfaces()
        self.combo = ttk.Combobox(control_frame, textvariable=self.interface_var, 
                                 values=self.interfaces, state="readonly")
        self.combo.grid(row=0, column=1, sticky='ew', padx=5)
        self.combo.current(0)
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=0, column=2, sticky='e')
        self.start_btn = ttk.Button(btn_frame, text="Iniciar Captura", command=self.start_sniffing)
        self.start_btn.pack(side='left', padx=2)
        self.stop_btn = ttk.Button(btn_frame, text="Parar Captura", command=self.stop_sniffing, state='disabled')
        self.stop_btn.pack(side='left', padx=2)
        self.text = scrolledtext.ScrolledText(self.root, height=25, width=100, wrap=tk.WORD)
        self.text.pack(padx=5, pady=5, fill='both', expand=True)
        self.text.tag_config('info', foreground='blue')
        self.text.tag_config('warning', foreground='orange')
        self.text.tag_config('error', foreground='red')
        self.text.tag_config('success', foreground='green')
        self.text.tag_config('highlight', background='yellow')
        self.text.insert(tk.END, "Hora        | Direção   | Protocolo | Origem → Destino                | Serviço  | Interpretação\n")
        self.text.insert(tk.END, "------------|-----------|-----------|---------------------------------|----------|--------------\n")
        self.text.tag_add('highlight', '1.0', '2.0')

    def get_interfaces(self):
        return list(psutil.net_if_addrs().keys())

    def log(self, msg, tags=()):
        self.text.insert(tk.END, msg + "\n", tags)
        self.text.see(tk.END)

    def start_sniffing(self):
        iface = self.interface_var.get()
        if not iface:
            messagebox.showerror("Erro", "Selecione uma interface!")
            return
        self.sniffing = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.text.delete(1.0, tk.END)
        self.thread = threading.Thread(target=self.sniff, args=(iface,), daemon=True)
        self.thread.start()
        self.log("[🎧] Iniciando captura na interface: " + iface, ('info',))

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        if self.sniffer:
            try:
                if platform.system() == 'Windows':
                    self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.sniffer.close()
            except Exception as e:
                self.log(f"[Erro] Falha ao parar captura: {e}", ('error',))
            self.sniffer = None
        self.log("[🛑] Captura parada.", ('info',))

    def sniff(self, interface):
        try:
            if platform.system() == 'Windows':
                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                ip_address = None
                for addr in psutil.net_if_addrs()[interface]:
                    if addr.family == socket.AF_INET:
                        ip_address = addr.address
                        break
                sniffer.bind((ip_address, 0))
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                sniffer.bind((interface, 0))
            self.sniffer = sniffer
            connections = {}
            while self.sniffing:
                if platform.system() == 'Windows':
                    data = sniffer.recv(65535)
                    ip_packet = ipv4_packet(data)
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    protocol_name = get_protocol_name(ip_packet['protocol'])
                    if ip_packet['protocol'] == 6:  # TCP
                        tcp = tcp_segment(ip_packet['data'])
                        analysis = analyze_traffic(
                            ip_packet['src_ip'], ip_packet['dest_ip'],
                            tcp['src_port'], tcp['dest_port'], "TCP", tcp['data']
                        )
                        conn_key = f"{ip_packet['src_ip']}:{tcp['src_port']}-{ip_packet['dest_ip']}:{tcp['dest_port']}"
                        if conn_key not in connections:
                            connections[conn_key] = {
                                'start_time': timestamp,
                                'last_activity': timestamp,
                                'service': analysis['service'],
                                'activity': analysis['activity'],
                                'count': 0
                            }
                        else:
                            connections[conn_key]['last_activity'] = timestamp
                            connections[conn_key]['count'] += 1
                        flags = "".join([k for k, v in tcp['flags'].items() if v])
                        if connections[conn_key]['count'] < 3 or 'SYN' in flags or 'FIN' in flags or analysis['activity']:
                            log_msg = f"{timestamp} | {analysis['direction']:8} | TCP {analysis['service']:6} | "
                            log_msg += f"{ip_packet['src_ip']}:{tcp['src_port']} → {ip_packet['dest_ip']}:{tcp['dest_port']} | "
                            log_msg += f"{analysis['interpretation']}"
                            if analysis['activity']:
                                log_msg += f"\n   ↳ Atividade: {analysis['activity']}"
                            if 'SYN' in flags:
                                log_msg += "\n   ↳ Nova conexão estabelecida"
                            elif 'FIN' in flags:
                                log_msg += "\n   ↳ Conexão encerrada"
                            self.log(log_msg)
                    elif ip_packet['protocol'] == 17:  # UDP
                        udp = udp_segment(ip_packet['data'])
                        analysis = analyze_traffic(
                            ip_packet['src_ip'], ip_packet['dest_ip'],
                            udp['src_port'], udp['dest_port'], "UDP", udp['data']
                        )
                        log_msg = f"{timestamp} | {analysis['direction']:8} | UDP {analysis['service']:6} | "
                        log_msg += f"{ip_packet['src_ip']}:{udp['src_port']} → {ip_packet['dest_ip']}:{udp['dest_port']} | "
                        log_msg += f"{analysis['interpretation']}"
                        if analysis['activity']:
                            log_msg += f"\n   ↳ Atividade: {analysis['activity']}"
                        self.log(log_msg)
                    else:
                        log_msg = f"{timestamp} | Tráfego {protocol_name:4} | {ip_packet['src_ip']} → {ip_packet['dest_ip']}"
                        self.log(log_msg)
                else:
                    raw_data, addr = sniffer.recvfrom(65535)
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    eth_frame = ethernet_frame(raw_data)
                    if eth_frame['proto'] == 8:  # IPv4
                        ip_packet = ipv4_packet(eth_frame['data'])
                        protocol_name = get_protocol_name(ip_packet['protocol'])
                        if ip_packet['protocol'] == 6:  # TCP
                            tcp = tcp_segment(ip_packet['data'])
                            analysis = analyze_traffic(
                                ip_packet['src_ip'], ip_packet['dest_ip'],
                                tcp['src_port'], tcp['dest_port'], "TCP", tcp['data']
                            )
                            flags = "".join([k for k, v in tcp['flags'].items() if v])
                            log_msg = f"{timestamp} | {analysis['direction']:8} | TCP {analysis['service']:6} | "
                            log_msg += f"{ip_packet['src_ip']}:{tcp['src_port']} → {ip_packet['dest_ip']}:{tcp['dest_port']} | "
                            log_msg += f"{analysis['interpretation']}"
                            if analysis['activity']:
                                log_msg += f"\n   ↳ Atividade: {analysis['activity']}"
                            if 'SYN' in flags:
                                log_msg += "\n   ↳ Nova conexão estabelecida"
                            elif 'FIN' in flags:
                                log_msg += "\n   ↳ Conexão encerrada"
                            self.log(log_msg)
                        elif ip_packet['protocol'] == 17:  # UDP
                            udp = udp_segment(ip_packet['data'])
                            analysis = analyze_traffic(
                                ip_packet['src_ip'], ip_packet['dest_ip'],
                                udp['src_port'], udp['dest_port'], "UDP", udp['data']
                            )
                            log_msg = f"{timestamp} | {analysis['direction']:8} | UDP {analysis['service']:6} | "
                            log_msg += f"{ip_packet['src_ip']}:{udp['src_port']} → {ip_packet['dest_ip']}:{udp['dest_port']} | "
                            log_msg += f"{analysis['interpretation']}"
                            if analysis['activity']:
                                log_msg += f"\n   ↳ Atividade: {analysis['activity']}"
                            self.log(log_msg)
                        else:
                            log_msg = f"{timestamp} | Tráfego {protocol_name:4} | {ip_packet['src_ip']} → {ip_packet['dest_ip']}"
                            self.log(log_msg)
        except Exception as e:
            self.log(f"[Erro] {e}", ('error',))

if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("1000x600")
    app = SnifferApp(root)
    root.mainloop()
