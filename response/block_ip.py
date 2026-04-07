import subprocess
import logging

logging.basicConfig(filename='logs/response.log', level=logging.INFO)

def block_ip_windows(ip, reason="Malicious activity"):
    try:
        rule_name_in = f"Block_IP_{ip.replace('.', '_')}_in"
        rule_name_out = f"Block_IP_{ip.replace('.', '_')}_out"
        
        check_in = subprocess.run(f'netsh advfirewall firewall show rule name="{rule_name_in}"', shell=True, capture_output=True, text=True)
        check_out = subprocess.run(f'netsh advfirewall firewall show rule name="{rule_name_out}"', shell=True, capture_output=True, text=True)
        
        if "No rules match" in check_in.stdout:
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip}'
            proc_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
            if proc_in.returncode != 0:
                logging.error(f"Failed to add inbound rule for {ip}: {proc_in.stderr}")
                return False
        
        if "No rules match" in check_out.stdout:
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip}'
            proc_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            if proc_out.returncode != 0:
                logging.error(f"Failed to add outbound rule for {ip}: {proc_out.stderr}")
                return False
        
        logging.info(f"Blocked IP {ip} (inbound+outbound) - {reason}")
        return True
    except Exception as e:
        logging.error(f"Exception blocking {ip}: {e}")
        return False

def unblock_ip_windows(ip):
    try:
        rule_name_in = f"Block_IP_{ip.replace('.', '_')}_in"
        rule_name_out = f"Block_IP_{ip.replace('.', '_')}_out"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_in}"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_out}"', shell=True, capture_output=True)
        logging.info(f"Unblocked IP {ip}")
        return True
    except Exception as e:
        logging.error(f"Exception unblocking {ip}: {e}")
        return False