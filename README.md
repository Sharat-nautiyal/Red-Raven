# Red Raven Network Pen Test Tool - User Guide



<img width="679" alt="Raven" src="https://github.com/user-attachments/assets/e6fcfb3e-3010-41b8-b317-f10e72027a9e" />




Welcome to Red Raven, a comprehensive network penetration testing tool designed for educational purposes and ethical security testing. This guide will walk you through its features, how to use them, and important considerations for optimal performance.

**Disclaimer:** This tool is for educational purposes only. Unauthorized activities on networks or systems without explicit permission are illegal and unethical. Always ensure you have proper authorization before performing any scans or interactions.

## Running Red Raven from the Command Line (CLI)

To execute Red Raven from the command line, follow these steps:

1.  **Clone the Git Repository:**
    Open your terminal and clone the Red Raven repository from GitHub using the following command:
    ```bash
    git clone https://github.com/Sharat-nautiyal/Red-Raven.git
    cd Red-Raven
    ```

3.  **Make the `run.sh` script executable:**
    Navigate into the cloned directory (Red-Raven) and give the `run.sh` script execute permissions:
    
    chmod +x run.sh
   

4.  **Run Red Raven:**
    Execute the `run.sh` script:
    
    ./run.sh
    
    run.sh script will attempt to launch the Red Raven application, handling necessary environment setup.
    
------


## 1. Overview

Red Raven provides a graphical user interface (GUI) for performing various network penetration testing tasks, including:

* **Port Scanning:** Identify open ports on target systems.
* **Network Discovery:** Discover active hosts on a local network.
* **Lateral Movement:** Execute commands and interact with network services using tools like `netexec` (or `crackmapexec`).
* **Brute Force:** Attempt to guess passwords for a single user against a service.
* **Password Spray:** Attempt to guess a single password against multiple user accounts.
* **Banner Grabbing:** Identify software versions running on open ports.
* **Password Dumping:** Simulate credential extraction using `secretsdump.py`.
* **Exfil:** Simulate data exfiltration to local or remote destinations.

## 2. Prerequisites & Setup

Before running Red Raven, ensure you have the following:

### 2.1 Python Environment

* **Python 3.x:** Installed on your system.
* **Required Python Libraries:** Red Raven will attempt to install these automatically on startup, but it's good to be aware of them:
    * `PyQt6`
    * `scapy` (Crucial for Network Discovery; often requires `pip install scapy` and may need elevated privileges)
    * `requests`

### 2.2 External Command-Line Tools

Many features of Red Raven rely on external command-line tools. These **must be installed and accessible in your system's PATH environment variable** for the respective features to work.

* **Nmap:** For advanced port scanning.
* **NetExec (or CrackMapExec):** For lateral movement, brute force, and password spraying. `crackmapexec` is an older name for `netexec`; ensure you have one installed.
* **Hydra:** An alternative tool for brute force and password spraying.
* **Impacket (specifically `secretsdump.py`):** For password dumping. You might need to install Impacket and ensure `secretsdump.py` is executable and in your PATH, or provide its full path if prompted by an error.

### 2.3 Elevated Privileges (Important!)

Some operations, particularly **Network Discovery (Scapy)** and potentially **Nmap** scans, require elevated privileges (Administrator on Windows, `sudo` on Linux/macOS) to send and receive raw network packets. If you encounter "Permission Denied" errors, try running the application with appropriate permissions.

## 3. General Usage

### 3.1 Authorization Checkbox

At the top of the application, you'll find a crucial checkbox:
"**I confirm I have explicit authorization to scan and interact with this network.**"

**You MUST check this box to enable any functionality within the tool.** This serves as a mandatory reminder of ethical hacking principles.

### 3.2 Status Bar

Located at the bottom of the window, the status bar provides real-time feedback on the current operation, its progress, or any errors.

### 3.3 Output Areas

Each tab has a dedicated `QTextEdit` area to display the results and output of the operations. This output typically auto-scrolls to show the latest information.

### 3.4 Stopping Operations

Most long-running operations (scans, brute force, exfil) have a "Stop" button. Clicking this will attempt to gracefully terminate the ongoing process.

### 3.5 Window Resizing

The application window is resizable. You can drag the edges (especially top and bottom) to adjust its size.

## 4. Feature Guide (Tab by Tab)

### 4.1 Port Scanner Tab

This tab allows you to perform basic TCP port scans. You can choose between a Python-based scanner (multi-threaded, good for quick checks) or Nmap (more robust, feature-rich, requires Nmap installation).

* **Target IP/Hostname/CIDR:** Enter the IP address (e.g., `192.168.1.1`), hostname (e.g., `example.com`), or a CIDR range (e.g., `192.168.1.0/24`) of the target.
* **Port Range:** Specify the ports to scan. Examples: `1-1000` (for ports 1 through 1000) or `80` (for a single port).
* **Number of Threads (for Python scanner):** Set the number of concurrent connections for the Python scanner. A higher number can be faster but might be more resource-intensive or prone to errors on unstable networks. (Max 200 threads).
* **Use Python Port Scanner (default):** Select this for the built-in, multi-threaded Python scanner.
* **Use Nmap for Scan (Requires Nmap installed):** Select this to leverage the powerful Nmap tool. If selected, the "Number of Threads" field will be disabled as Nmap manages its own threading.
* **Start Scan / Stop Scan:** Initiates or terminates the selected scan.
* **Scan Results:** Displays the output of the port scan, showing open ports and any identified banners.

### 4.2 Network Discovery Tab

This tab uses Scapy to perform an ARP scan, identifying active hosts on your local network.

* **Target IP/Range:** Enter the IP address or CIDR range for the ARP scan (e.g., `192.168.1.0/24`).
* **Save to PCAP File (Optional):** Provide a filename (e.g., `discovery.pcap`) to save the captured ARP packets to a PCAP file for later analysis with tools like Wireshark. Leave empty to not save.
* **Start Discovery / Stop Discovery:** Initiates or terminates the network discovery process.
* **Discovery Results:** Shows the IP and MAC addresses of discovered devices.

### 4.3 Lateral Movement Tab

This tab allows you to run `netexec` (or `crackmapexec`) commands against target systems. It provides a flexible command input field.

* **Target IP/Range:** Enter the target IP address or CIDR range. The tool will iterate through each host in the range.
* **Select Protocol:** Choose the network protocol `netexec` should use (SMB, SSH, WinRM, MSSQL, LDAP, RDP, VNC).
* **NetExec Command:** This field will auto-populate with a basic command based on the selected protocol, but you can **edit it freely**.
    * **Important:** Use `<target_ip>` as a placeholder, and the tool will replace it with the actual IP address during execution. If you don't include `<target_ip>`, the tool will attempt to intelligently insert the target IP.
    * Example: `netexec smb <target_ip> --shares`
    * Example: `crackmapexec ssh <target_ip> -u administrator -p 'Password123!' --exec-shell`
* **Run NetExec / Stop NetExec:** Executes or terminates the NetExec command.
* **NetExec Output:** Displays the real-time output from the `netexec` command.

### 4.4 Brute Force Tab

This tab facilitates brute-force attacks against a single username using a wordlist. You can choose between Hydra, NetExec, or CrackMapExec.

* **Target IP/Host:** The target IP address or hostname.
* **Username:** The single username you want to brute force.
* **Tool:** Select the tool to use: `Hydra`, `NetExec`, or `CrackMapExec`.
* **Protocol:** Choose the service protocol (SMB, SSH, WinRM, etc.).
* **Command:** This field will auto-populate with a template based on the selected tool and protocol.
    * **Important:** `<target_ip>`, `<username>`, and `<wordlist_file>` are placeholders that will be replaced.
    * The tool will automatically handle the creation and deletion of a temporary wordlist file.
* **Wordlist Options:**
    * **Use default 'rockyou.txt':** Uses a small, pre-created `rockyou.txt` file (for testing purposes).
    * **Paste Wordlist:** Paste your own list of passwords, one per line. This option takes precedence over the default or uploaded file.
    * **Upload Wordlist File:** Browse and select a text file containing passwords (one per line). This option takes precedence over the default `rockyou.txt` if pasted text is empty.
* **Start Brute Force / Stop Brute Force:** Initiates or terminates the brute force attack.
* **Brute Force Output:** Displays the real-time output from the chosen brute-force tool.

### 4.5 Password Spray Tab

This tab performs a password spray attack, testing a single password against multiple usernames.

* **Target IP/Host:** The target IP address or hostname.
* **Password:** The single password you want to test against multiple usernames.
* **Tool:** Select the tool to use: `NetExec`, `Hydra`, or `CrackMapExec`.
* **Protocol:** Choose the service protocol (SMB, SSH, WinRM, etc.).
* **Command:** This field will auto-populate with a template based on the selected tool and protocol.
    * **Important:** `<target_ip>`, `<password>`, and `<usernames_file>` are placeholders that will be replaced.
    * The tool will automatically handle the creation and deletion of a temporary usernames file.
* **Usernames List Options:**
    * **Paste Usernames:** Paste your own list of usernames, one per line. This option takes precedence over an uploaded file.
    * **Upload Usernames File:** Browse and select a text file containing usernames (one per line).
* **Start Password Spray / Stop Password Spray:** Initiates or terminates the password spray attack.
* **Password Spray Output:** Displays the real-time output from the chosen tool.

### 4.6 Banner Grabbing Tab

This tab attempts to connect to specified ports on targets and retrieve service banners, which often reveal software and version information.

* **Target IP/Hostname/CIDR:** Enter the IP address, hostname, or CIDR range of the target(s).
* **Target Port(s):** Enter one or more ports, separated by commas (e.g., `80,443,22,21`).
* **Start Banner Grabbing / Stop Banner Grabbing:** Initiates or terminates the banner grabbing process.
* **Banner Grabbing Output:** Displays the banners received from the target services.

### 4.7 Password Dumping Tab

This tab simulates password dumping using `secretsdump.py` from the Impacket toolkit. This is a powerful feature typically used post-exploitation.

* **Target IP/Hostname:** The target system's IP address or hostname.
* **Domain (Optional):** The domain name if the target is part of a domain.
* **Username:** The username for authentication to the target.
* **Use Hashes (LM:NT format):** Check this if you want to authenticate using NTLM hashes instead of a cleartext password. If checked, the "Password" field's label will change to "Hash (LM:NT):".
* **Password / Hash (LM:NT):** Enter either the cleartext password or the LM:NT hash pair (e.g., `aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0`).
* **Additional Options:** Any extra command-line arguments you want to pass to `secretsdump.py` (e.g., `--just-dc-ntlm`).
* **Start Password Dump / Stop Dump:** Executes or terminates the `secretsdump.py` command.
* **secretsdump.py Output:** Displays the output of the `secretsdump.py` script, which may include extracted credentials.

### 4.8 Exfil Tab

This tab provides a simulated environment for data exfiltration, demonstrating how data might be moved out of a compromised system.

* **Dummy File: `dummy_200MB_file.bin` (200 MB):** A pre-defined dummy file that can be created for testing exfil.
* **Create Dummy File:** Creates the `dummy_200MB_file.bin` in the application's directory. You will be prompted to overwrite if it already exists.
* **Progress Bar & Label:** Shows the progress of dummy file creation.
* **Simulated Exfil Server:**
    * **Server Address:** Shows the local address where the simulated exfil server will run (default: `http://127.0.0.1:8080`).
    * **Files will be saved to:** The directory where files received by the simulated server will be stored (`exfil_received` in the application's directory).
    * **Start Exfil Server / Stop Exfil Server:** Controls the local HTTP server that simulates a remote exfiltration endpoint.
* **Exfil Source File:**
    * **Select File for Exfil:** Click this button to browse and select *any* file on your system that you wish to simulate exfiltrating. This overrides the default dummy file.
* **Local Destination Path:** The directory on your local machine where the file will be copied if "Local (Internal)" or "Both" exfil types are selected.
* **Remote Exfil URL:** The URL of the simulated exfil server (or any other HTTP endpoint) where the file will be sent if "Remote (External)" or "Both" exfil types are selected.
* **Exfil Destination Type:**
    * **Local (Internal):** Simulates copying the file to a local directory.
    * **Remote (External):** Simulates sending the file to the specified remote URL.
    * **Both:** Simulates both local copying and remote sending simultaneously.
* **Perform Simulated Exfil:** Initiates the exfiltration process for the selected file.
* **Exfil Progress Bar & Label:** Shows the progress of the exfil operation.
* **Exfil Output:** Displays messages and status updates related to the exfil process, including server messages.

## 5. Important Notes & Troubleshooting

* **Dependency Issues:** If features are not working, check the console output where you launched the Python script. It will show messages about missing dependencies and attempts to install them. If automatic installation fails, you may need to install them manually using `pip` (e.g., `pip install scapy`).
* **PATH Environment Variable:** Ensure that the directories containing `nmap`, `netexec`/`crackmapexec`, `hydra`, and `secretsdump.py` are included in your system's PATH. This allows the application to find and execute these commands.
* **Permissions:** For network-level operations (Scapy, Nmap), you might need to run the Python script with administrator/root privileges.
* **Real-time Output:** The output areas update in near real-time. For very verbose commands, there might be a slight delay as output is buffered.
* **Stopping Operations:** Always use the dedicated "Stop" buttons to terminate ongoing operations gracefully. Closing the application window will also attempt to stop all running threads.
* **Ethical Use:** Remember the core principle: **Always have explicit authorization** before performing any actions on a network or system. This tool is for learning and authorized testing only.

## 6. License 

Red Raven is licensed under the **GNU GPL v3.0**.

You are free to use, modify, and distribute this software under GPLv3, ensuring derivatives remain open source.

**Dependencies and Their Licenses**

* Nmap (GPL)

* Hydra (GPL)

* Scapy (BSD)

* Impacket (MIT)

* CrackMapExec (MIT)

* NetExec (various licenses)

Please comply with each dependency’s license terms.

-------


Enjoy using Red Raven for your ethical penetration testing learning journey!
