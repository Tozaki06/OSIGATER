import tkinter as tk
import tkinter as ttk
import subprocess
import whois # Importing the WHOIS module
import socket
import nmap
import threading
import requests
import dns.resolver
from tkinter import messagebox
from tkinter import ttk
from tkinter import simpledialog
from bs4 import BeautifulSoup
from PIL import Image, ImageTk
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from shodan_module import shodan_lookup # Import the Shodan Integration

resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

# Function to open the WHOIS Lookup window
def open_whois_window():
    whois_window = tk.Toplevel(root)
    whois_window.title("WHOIS Lookup")
    whois_window.geometry("800x600")

    label_target = tk.Label(whois_window, text="Enter Domain/IP:", font=("Arial",12))
    label_target.pack(pady=10)

    global input_target
    input_target = tk.Entry(whois_window, width=50)
    input_target.pack(pady=10)

    result_text = tk.Text(whois_window, height=10, width=50)
    result_text.pack(pady=10)
    result_text.insert(tk.END, "WHOIS Lookup Results:\n")

    def run_whois_lookup():
        target = input_target.get()
        result_text.delete(1.0, tk.END) # Clear previous results

        # Check if the input is empty
        if not target.strip():
            messagebox.showerror("Input Error", "Please enter a valid domain name.")
            return
        try:
            whois_data = whois.whois(target) # Perform the WHOIS lookup
        
            #Check if the WHOIS data is empty or imcomplete
            if not whois_data or whois_data.get('domain_name') is None:
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, "No WHOIS information found.\n")
            else:
                # Display WHOIS data if found
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, whois_data)
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}")
        result_text.insert(tk.END, f"WHOIS result for {target}:\n...")

    whois_button = tk.Button(whois_window, text="Run WHOIS Lookup", command=run_whois_lookup)
    whois_button.pack()

# Function to open the DNS Lookup Window
def open_dns_window():
    dns_window = tk.Toplevel(root)
    dns_window.title("DNS Lookup")
    dns_window.geometry("400x300")

    label_target = tk.Label(dns_window, text="Enter Domain:")
    label_target.pack()

    input_target = tk.Entry(dns_window)
    input_target.pack()

    result_text = tk.Text(dns_window, height=10, width=50)
    result_text.pack()

    def run_dns_lookup():
        domain = input_target.get()
        result_text.delete(1.0, tk.END)

        #Check if the input is empty
        if not domain:
            messagebox.showerror("Input Error", "Please enter a valid domain name.")
            return

        try:
            # Perform DNS Lookups (A, MX, NS, TXT)
            records = dns_lookup(domain)
            result_text.insert(tk.END, f"DNS lookup for {domain}:\n")
            for record_type, records in records.items():
                result_text.insert(tk.END, f"{record_type} Records: {records}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}\n")

    dns_button = tk.Button(dns_window, text="Run DNS Lookup", command=run_dns_lookup)
    dns_button.pack()

# Function to open the Nmap window
def open_nmap_window():
    nmap_window = tk.Toplevel(root)
    nmap_window.title("Nmap Scan")
    nmap_window.geometry("400x300")

    label_target = tk.Label(nmap_window, text="Enter IP/Domain:")
    label_target.pack()

    input_target = tk.Entry(nmap_window)
    input_target.pack()

    label_scan_type = tk.Label(nmap_window, text="Select Scan Type:")
    label_scan_type.pack()

    scan_types = ["SYN", "TCP", "UDP"]
    input_scan_type = tk.StringVar(nmap_window)
    input_scan_type.set("SYN") #Default scan type
    scan_type_menu = tk.OptionMenu(nmap_window, input_scan_type, *scan_types)
    scan_type_menu.pack()

    result_text = tk.Text(nmap_window, height=10, width=50)
    result_text.pack()

    nm=nmap.PortScanner()

    def validate_ip(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def run_nmap_scan():
        target = input_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a valid IP address.")
            return

        if not validate_ip(target):
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Invalid IP address.\n")
            return

        try:
            if target == "127.0.0.1":
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Scanning Localhost ({target})...\n\n")
                nm.scan(hosts=target, arguments='-sS')
                for proto in nm[target].all_protocols():
                    lport=nm[target][proto].keys()
                    for port in sorted(lport):
                        result_text.insert(tk.END, f"Port: {port}\tState: {nm[target][proto][port]['state']}\n")
            else:
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Scanning {target}...\n\n")
                nm.scan(hosts=target, arguments='-sS')

                #Check if the host is up
                if nm[target].state() == "up":
                    for proto in nm[target].all_protocols():
                        lport = nm[target][proto].keys()
                        for port in sorted(lport):
                            result_text.insert(tk.END, f"Port: {port}\tState: {nm[target][proto][port]['state']}\n")
                else:
                    #Host cannot be reached
                    result_text.insert(tk.END, "Host cannot be reached.\n")
        
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error: {str(e)}")

    nmap_button = tk.Button(nmap_window, text="Run Nmap Scan", command=run_nmap_scan)
    nmap_button.pack()

def open_theharvester_window():
    # Create a new window (Toplevel) for theHarvester
    theharvester_window = tk.Toplevel(root)
    theharvester_window.title("theHarvester")
    theharvester_window.geometry("800x600")

    label_target = tk.Label(theharvester_window, text="Enter Domain for theHarvester Lookup:")
    label_target.pack(pady=10)

    input_target = tk.Entry(theharvester_window)
    input_target.pack(pady=10)

    result_text = tk.Text(theharvester_window, height=10, width=60)
    result_text.pack(pady=10)

    def run_theharvester_lookup():
        target = input_target.get()
        
        if not target:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        try:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Running theHarvester on {target}...\n\n")

            command = f"theHarvester -d {target} -b all"
            process = subprocess.run(command, shell=True, capture_output=True, text=True)

            if "No hosts found" in process.stdout or not process.stdout.strip():
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, "No information found.\n")
                return

            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, process.stdout)

        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error: {str(e)}")

        def theharvester_thread():
            try:
                # Execute theHarvester as a subprocess
                command = f"theHarvester -d {target} -b all"
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                stdout, stderr = process.communicate()

                if stdout:
                    result_text.insert(tk.END, stdout.decode())
                if stderr:
                    result_text.insert(tk.END, f"Error: {stderr.decode()}")
            except Exception as e:
                result_text.insert(tk.END, f"Error: {str(e)}")

        # Run theHarvester in a separate thread to avoid freezing the GUI
        threading.Thread(target=theharvester_thread).start()

    run_button = tk.Button(theharvester_window, text="Run theHarvester", command=run_theharvester_lookup)
    run_button.pack(pady=10)


# Function for dns_lookup
def open_dns_recon_window():
    dns_recon_window = tk.Toplevel(root)
    dns_recon_window.title("DNS Reconnaissance")
    dns_recon_window.geometry("800x600")

    label_target = tk.Label(dns_recon_window, text="Enter Domain:")
    label_target.pack(pady=10)

    input_target = tk.Entry(dns_recon_window)
    input_target.pack(pady=10)

    result_text = tk.Text(dns_recon_window, height=20, width=80)
    result_text.pack(pady=10)

    def validate_input(domain_or_ip):
        if not domain_or_ip.strip():
            return False
        return True

    def run_dns_lookup():
        domain = input_target.get()

        if not validate_input(domain):
            messagebox.showerror("Input Error", "Please enter a valid domain or IP address.")

        try:
            result_text.delete(1.0, tk.END)
            # Perform DNS lookups (A,MX, NS, TXT)
            records = dns_lookup(domain)
            result_text.insert(tk.END, f"DNS lookup for {domain}:\n")
            for record_type, records in records.items():
                result_text.insert(tk.END, f"{record_type} Records: {records}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}\n")

    def run_reverse_ip_lookup():
        ip_address = input_target.get().strip()
        result_text.delete(1.0, tk.END)

        if not validate_input(ip_address):
            messagebox.showerror("Input Error", "Please enter a valid IP address.")
            return

        try:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Reverse IP Lookup for {ip_address}:\n\n")

            host_info = socket.gethostbyaddr(ip_address)
            result_text.insert(tk.END, f"Domain: {host_info[0]}\n")
            result_text.insert(tk.END, f"Aliases: {', '.join(host_info[1])}\n")
            result_text.insert(tk.END, f"IP Addresses: {', '.join(host_info[2])}\n")

        except socket.herror:
            result_text.insert(tk.END, f"Error: Host not found for {ip_address}.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}\n")

    def run_subdomain_enumeration():
        domain = input_target.get()
        result_text.delete(1.0, tk.END)

        if not validate_input(domain):
            messagebox.showerror("Input Error", "Please enter a valid domain.")
            return

        try:
            # Perform subdomain enumeration using SecurityTrails API
            api_key = "hGPIJmkohww_WAq5E2WOAxQLshtND5F3"
            subdomains = subdomain_enumeration(domain, api_key)
            result_text.insert(tk.END, f"Subdomains for {domain}:\n{subdomains}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}\n")

    def run_ptr_lookup():
        domain = input_target.get()
        result_text.delete(1.0, tk.END)

        try:
            # Perform PTR (reverse DNS) lookup
            records = dns_lookup(domain)
            if 'A' in records:
                ip_address = records['A'][0]
                ptr_record = reverse_dns_lookup(ip_address)
                result_text.insert(tk.END, f"PTR Record for {ip_address}:\n{ptr_record}\n")
            else:
                result_text.insert(tk.END, "No A record found to perform PTR lookup.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}\n")

    def run_whois_lookup():
        domain = input_target.get()
        result_text.delete(1.0, tk.END)

        try:
            # Perform Whois Lookup
            whois_info = whois_lookup(domain)
            result_text.insert(tk.END, f"Whois Information for {domain}:\n{whois_info}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error: {str(e)}\n")

    # DNS Lookup button
    dns_button = tk.Button(dns_recon_window, text="DNS Lookup", command=run_dns_lookup)
    dns_button.pack(pady=10)

    # Reverse IP lookup button
    reverse_ip_button = tk.Button(dns_recon_window, text="Reverse IP lookup", command=run_reverse_ip_lookup)
    reverse_ip_button.pack(pady=10)

    # Subdomain Enumeration button
    subdomain_button = tk.Button(dns_recon_window, text="Subdomain Enumeration", command=run_subdomain_enumeration)
    subdomain_button.pack(pady=10)

    # PTR Record Lookup button
    ptr_button = tk.Button(dns_recon_window, text="PTR Lookup", command=run_ptr_lookup)
    ptr_button.pack(pady=10)

    # Whois Lookup button
    whois_button = tk.Button(dns_recon_window, text="Whois Lookup", command=run_whois_lookup)
    whois_button.pack(pady=10)

    # Back button to close the window
    back_button = tk.Button(dns_recon_window, text="Back", command=dns_recon_window.destroy)
    back_button.pack(pady=10)

def dns_lookup(domain):

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    records = {}
    
    # A record (IP Address)
    try:
        a_records = resolver.resolve(domain, 'A')
        records['A'] = [str(record) for record in a_records]
    except Exception as e:
        records['A'] = f"Error: {str(e)}"

    # MX record (Mail servers)
    try:
        mx_records = resolver.resolve(domain, 'MX')
        records['MX'] = [str(record.exchange) for record in mx_records]
    except Exception as e:
        records['MX'] = f"Error: {str(e)}"

    # NS record (Name servers)
    try:
        ns_records = resolver.resolve(domain, 'NS')
        records['NS'] = [str(record) for record in ns_records]
    except Exception as e:
        records['NS'] = f"Error: {str(e)}"

    # TXT record (Text records)
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        records['TXT'] = [str(record) for record in txt_records]
    except Exception as e:
        records['TXT'] = f"Error: {str(e)}"

    return records

def reverse_ip_lookup(ip_address):
    url = f"https://viewdns.info/reverseip/?host={ip_address}&t=1"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find the table that contains the reverse IP results
    reverse_ip_table = soup.find("table", {"border": "1"})

    if not reverse_ip_table:
        return "No results found or unable to scrape reverse IP lookup."

    # Extract the domains from the table
    results = []
    rows = reverse_ip_table.find_all('tr')[1:] # Skip the header row
    for row in rows:
        cols = row.find_all('td')
        if cols:
            domain_name = cols[0].text.strip()
            results.append(domain_name)

    if resutls:
        return "\n".join(results)
    else:
        return "No domains found."

def subdomain_enumeration(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        'APIKEY': api_key,
    }
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        subdomains = data.get('subdomains', [])
        # Add the domain name to each subdomain to form the full URL
        full_subdomains = [f"{subdomain}.{domain}" for subdomain in subdomains]
        return full_subdomains
    else:
        return f"Error: {response.status_code} {response.text}"


# Function to open the new window for combined OSTIN scans
def open_combined_scan_window():
    combined_window = tk.Toplevel(root)
    combined_window.title("Combined OSINT Scan")
    combined_window.geometry("900x700")

    # Create a canvas and a vertical scrollbar
    canvas = tk.Canvas(combined_window)
    scrollbar = tk.Scrollbar(combined_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    # Configure the canvas and scrollbar
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0,0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Pack the canvas and scrollbar
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    label = tk.Label(scrollable_frame, text="Perform ALL scans and Generate Report", font=("Arial", 16))
    label.pack(pady=10)

    # Add input field for domain or IP address
    label_target = tk.Label(scrollable_frame, text="Enter Domain or IP to Scan:", font=("Arial", 12))
    label_target.pack(pady=10)

    global input_target # Global to access in scan functions
    input_target = tk.Entry(scrollable_frame, width=50)
    input_target.pack(pady=10)

    # Create a text box for each scan result
    whois_result_text = tk.Text(scrollable_frame, height=10, width=80)
    whois_result_text.pack(pady=5)
    whois_result_text.insert(tk.END, "WHOIS Lookup Results:\n")

    dns_result_text = tk.Text(scrollable_frame, height=10, width=80)
    dns_result_text.pack(pady=5)
    dns_result_text.insert(tk.END, "DNS Lookup Results:\n")
    
    harvester_result_text = tk.Text(scrollable_frame, height=10, width=80)
    harvester_result_text.pack(pady=5)
    harvester_result_text.insert(tk.END, "theHarvester Results:\n")
    
    nmap_result_text = tk.Text(scrollable_frame, height=10,width=80)
    nmap_result_text.pack(pady=5)
    nmap_result_text.insert(tk.END, "Nmap Scan Results:\n")

    #Variables to hold the scan results
    scan_results = {
        'whois': '',
        'dns': '',
        'harvester': '',
        'nmap': '',
    }

    def whois_lookup(domain):
        try:
            global whois_info
            whois_info = whois.whois(domain)
            return str(whois_info)
        except Exception as e:
            return f"Error: {str(e)}"

    def nmap_scan(ip_address):
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_address, arguments='-sS')

        if nm[ip_address].state() == "up":
            for proto in nm[ip_address].all_protocols():
                lport = nm[ip_address][proto].keys()
                for port in sorted(lport):
                    f"Port: {port}\tState: {nm[ip_address][proto][port]['state']}\n"

    def run_theharvester_lookup(domain):
        try:
            command = f"theHarvester -d {domain} -b all"
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = process.communicate()

            if stdout:
                return stdout.decode()
            elif stderr:
                return f"Error: {stderr.decode()}"
            else:
                return "No results found."

        except Exception as e:
            return f"Error: {str(e)}"

    # Function to run all scans in background threads
    def get_inputs():
        target = input_target.get()

        if not target:
            print("Please enter a valid domain or IP address.")
            return

        # Check if the target is a domain or IP address
        try:
            # Check if it's an IP address
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False

        domain = None
        ip_address = None

        # If the input is an IP address, ask for a domain if needed
        if is_ip:
            ip_address = target
            domain = simpledialog.askstring("Input Required", "Please enter the domain name(if applicable):")
        else:
            domain = target
            ip_address = simpledialog.askstring("Input Required", "Please enter the IP address (if applicable):")

        return domain, ip_address

    def run_all_scans(domain=None, ip_address=None):
        # Now perform each scan using the domain or IP as appropriate
        if domain:
            global whois_info
            whois_info = whois_lookup(domain)
            whois_result_text.insert(tk.END, whois_info + "\n")
            global dns_info
            dns_info = dns_lookup(domain)
            dns_result_text.insert(tk.END, dns_info)
            global harvester_info
            harvester_info = run_theharvester_lookup(domain)
            harvester_result_text.insert(tk.END, harvester_info + "\n")

        if ip_address:
            global nmap_info
            nmap_info = nmap_scan(ip_address)

            if nmap_info is not None:
                nmap_result_text.insert(tk.END, nmap_info + "\n")
            else:
                nmap_result_text.insert(tk.END, "No Nmap results found or an error occured.\n")

    def handle_scan():
        # Get the inputs on the main thread
        domain, ip_address = get_inputs()
        if domain or ip_address:
            # Run the scans in a separate thread
            threading.Thread(target=run_all_scans, args=(domain, ip_address)).start()


    # Button to start the combined scan
    run_button = tk.Button(scrollable_frame, text="Run All Scans", command=handle_scan)
    run_button.pack(pady=10)

    # Function to generate PDF report
    def generate_report():
        domain = input_target.get()
        generate_pdf_report(domain, whois_info, dns_info, harvester_info, nmap_info)

    # Button to generate PDF report
    report_button = tk.Button(scrollable_frame, text="Generate PDF Report", command=generate_report)
    report_button.pack(pady=10)

    # Button to close the window
    back_button = tk.Button(scrollable_frame, text="Back", command=combined_window.destroy)
    back_button.pack(pady=10)

def wrap_text(c, text, x, y, max_width):
    lines = []
    words = text.split()
    line = words[0]

    for word in words[1:]:
        if c.stringWidth(line + ' ' + word, "Helvetica", 10) < max_width:
            line += ' ' + word
        else:
            lines.append(line)
            line = word
    lines.append(line)

    for line in lines:
        c.drawString(x, y, line)
        y -= 12
    return y

def generate_pdf_report(domain, whois_info, dns_info, harvester_info, nmap_info):
    pdf_file = f"{domain}_OSINT_Report.pdf"
    c = canvas.Canvas(pdf_file, pagesize=letter)
    width, height = letter

    # Title of the report
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, f"OSINT Report for {domain}")

    y = height - 100

    # WHOIS Results
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "WHOIS Lookup Results:")
    c.setFont("Helvetica", 10)
    y = wrap_text(c, whois_info if whois_info else "No WHOIS data available.", 50, y - 20, max_width=500)

    #DNS Lookup Results
    c.setFont("Helvetica-Bold", 12)
    y -= 20
    c.drawString(50, y, "DNS Lookup Results:")
    c.setFont("Helvetica", 10)
    y = wrap_text(c, str(dns_info) if dns_info else "No DNS data available.", 50, y - 20, max_width=500)

    # Nmap Scan Results
    c.setFont("Helvetica-Bold", 12)
    y -= 20
    c.drawString(50, y, "Nmap Scan Results:") 
    c.setFont("Helvetica", 10)
    y = wrap_text(c, nmap_info if nmap_info else "No Nmap data available.", 50, y - 20, max_width=500)

    # theHarvester Results
    c.setFont("Helvetica-Bold", 12)
    y -= 20
    c.drawString(50, y, "theHarvester Results:")
    c.setFont("Helvetica", 10)
    y = wrap_text(c, harvester_info if harvester_info else "No theHarvester data available.", 50, y - 20, max_width=500)


    # Save the PDF file
    c.save()
    print(f"PDF report saved as {pdf_file}")


def open_shodan_window():
    shodan_window = tk.Toplevel(root)
    shodan_window.title("Shodan Lookup")
    shodan_window.geometry("600x400")

    # Add Input field for Ip address
    label_ip = tk.Label(shodan_window, text="Enter IP Address for Shodan Lookup:", font=("Arial", 12))
    label_ip.pack(pady=10)

    input_ip = tk.Entry(shodan_window, width=50)
    input_ip.pack(pady=10)

    result_text = tk.Text(shodan_window, height=15, width=70)
    result_text.pack(pady=10)
    result_text.insert(tk.END, "Shodan Lookup Results:\n")

    def validate_ip(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    # Function to run the Shodan scan
    def run_shodan():
        api_key = "KArCBgRxzVxCAA01O01PRcP0h2MEbou8"
        target_ip = input_ip.get().strip()

        if not target_ip:
            messagebox.showerror("Input Error", "Please enter a valid IP address.")
            return

        if not validate_ip(target_ip):
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Invalid IP address.\n")
            return


        # Perform Shodan lookup in a separate thread to keep the UI responsive
        def perform_lookup():
            results = shodan_lookup(api_key, target_ip)
            result_text.insert(tk.END, results + "\n")

        threading.Thread(target=perform_lookup).start()

    #Button to start Shodan scan
    run_button = tk.Button(shodan_window, text="Run Shodan Lookup", command=run_shodan)
    run_button.pack(pady=10)

    #Back button to close the window
    back_button = tk.Button(shodan_window, text="Back", command=shodan_window.destroy)
    back_button.pack(pady=10)


# Main window
root = tk.Tk()
root.title("OSIGATER - Integrated OSINT Tool")
root.geometry("900x700")
root.config(bg="#2b2b2b") # Background color for modern dark theme

# Styling for buttons
button_style = ttk.Style()
button_style.configure("TButton", font=("Arial", 12), padding=10)

# Create a title label with a modern font
title_label = ttk.Label(root, text="OSIGATER - Integrated OSINT Tool", font=("Arial", 24, "bold"), foreground="white", background="#2b2b2b")
title_label.pack(pady=20)

# Display the logo image in the center
try:
    logo_image = Image.open("RedTeam.png")
    logo_image = logo_image.resize((200, 200), Image.LANCZOS)
    logo_photo = ImageTk.PhotoImage(logo_image)

    logo_label = ttk.Label(root, image=logo_photo, background="#2b2b2b")
    logo_label.pack(pady=20)
except Exception as e:
    error_label = ttk.Label(root, text="Logo could not be loaded", foreground="red", background="#2b2b2b")
    error_label.pack()

# 

# Styling for modern buttons
style = ttk.Style()

# Customizing button style
style.configure("TButton",
                font=("Arial", 12, "bold"),
                padding=10,
                background="#1c1c1c",
                foreground="white",
                borderwidth=1,
                focusthickness=3,
                focuscolor="none")

style.map("TButton",
          background=[("active", "#333333"), ("pressed", "#555555")],
          foreground=[("active", "white"), ("pressed", "white")])


# Create a frame to organize buttons neatly
button_frame = ttk.Frame(root, style="TFrame", padding=10)
button_frame.pack(pady=30)


# Define button size and layout
button_width = 25
button_bg = "#1c1c1c"
button_fg = "white"
button_active_bg = "#444444"

#Header Frame (for sub-header menus like a website)


# Function to clear the main content area
def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

#Create main content frame
main_content_frame = tk.Frame(root)
main_content_frame.pack(fill=tk.BOTH, expand=True)

#Buttons in the Header (Navbar-style buttons)
# Button to open WHOIS Lookup window
whois_button = tk.Button(button_frame, text="WHOIS Lookup", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg, command=open_whois_window)
whois_button.grid(row=0, column=0, padx=10, pady=10)

# Button to open DNS Lookup window
dns_button = tk.Button(button_frame, text="DNS Lookup", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg, command=open_dns_window)
dns_button.grid(row=0, column=1, padx=10, pady=10)

# Button to open Nmap window
nmap_button = tk.Button(button_frame, text="Nmap Scan", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg, command=open_nmap_window)
nmap_button.grid(row=1, column=0, padx=10, pady=10)

# Button to open theHarvester
theharvester_button = tk.Button(button_frame, text="theHarvester", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg,  command=open_theharvester_window)
theharvester_button.grid(row=1, column=1, padx=10, pady=10)

# Add DNS_Recon button to the header
dns_recon_button = tk.Button(button_frame, text="DNS Recon", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg, command=open_dns_recon_window)
dns_recon_button.grid(row=2, column=0, padx=10, pady=10)

# Add the "Run All Scans" button
combined_scan_button = tk.Button(button_frame, text="Run All Scans", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg, command=open_combined_scan_window)
combined_scan_button.grid(row=3, column=0, columnspan=2, padx=10, pady=20)

#Add the "Shodan" button
shodan_button = tk.Button(button_frame, text="Shodan Lookup", width=button_width, bg=button_bg, fg=button_fg, activebackground=button_active_bg, command=open_shodan_window)
shodan_button.grid(row=2, column=1, padx=10, pady=10)
# Placeholder buttons for future tools (Web Scraper, etc).

# Footer 
footer_label = ttk.Label(root, text="© 2024 OSIGATER | Powered by Open Source Intelligence", font=("Arial", 10), foreground="white", background="#2b2b2b")
footer_label.pack(side="bottom", pady=20)
# Start the Tkinter main loop
root.mainloop()


