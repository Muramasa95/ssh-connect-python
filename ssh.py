import paramiko
import socket
import concurrent.futures
from datetime import datetime
import argparse
import sys
import time

def try_ssh_connection(ip, username, password, port=22, timeout=3):
    """Try to connect to a host via SSH with improved error handling"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # First check if port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect to the port
        if sock.connect_ex((ip, port)) != 0:
            return (ip, False, None, "Port closed")
        
        # Close initial socket
        sock.close()
        
        # Add a small delay before SSH connection
        time.sleep(0.5)
        
        # Try SSH connection with extended timeout
        ssh.connect(
            ip,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout * 2,  # Extended banner timeout
            auth_timeout=timeout,
            look_for_keys=False,         # Don't look for SSH keys
            allow_agent=False            # Don't use SSH agent
        )
        
        # If we get here, connection successful
        try:
            stdin, stdout, stderr = ssh.exec_command('uname -a', timeout=timeout)
            system_info = stdout.read().decode().strip()
            is_pi = 'raspberrypi' in system_info.lower() or 'raspberry' in system_info.lower()
        except:
            # If command fails, still mark as successful connection
            system_info = "Command execution failed"
            is_pi = False
            
        return (ip, True, is_pi, system_info)
        
    except paramiko.AuthenticationException:
        return (ip, True, None, "Authentication failed - wrong credentials")
    except paramiko.SSHException as e:
        if "Error reading SSH protocol banner" in str(e):
            return (ip, True, None, "SSH service detected but not responding properly")
        return (ip, True, None, f"SSH error: {str(e)}")
    except socket.timeout:
        return (ip, False, None, "Connection timed out")
    except ConnectionRefusedError:
        return (ip, False, None, "Connection refused")
    except Exception as e:
        return (ip, False, None, f"Error: {str(e)}")
    finally:
        try:
            ssh.close()
        except:
            pass

def scan_network(subnet, username, password, max_workers=20):  # Reduced max workers
    print(f"\nStarting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanning subnet: {subnet}.*")
    print(f"Using username: {username}")
    print("Testing SSH connections...\n")
    
    results = []
    ips = [f"{subnet}.{i}" for i in range(256)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(try_ssh_connection, ip, username, password): ip 
            for ip in ips
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            ip, has_ssh, is_pi, message = future.result()
            
            # Update progress
            sys.stdout.write(f"\rProgress: {completed}/256 IPs checked")
            sys.stdout.flush()
            
            if has_ssh:
                if is_pi:
                    print(f"\n✅ Found Raspberry Pi at {ip}!")
                    print(f"System info: {message}")
                else:
                    print(f"\n📡 Found SSH service at {ip} - {message}")
                results.append((ip, is_pi, message))
    
    print(f"\n\nScan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find Raspberry Pi on network via SSH")
    parser.add_argument("--subnet", default="192.168.1", help="Subnet to scan (e.g., 192.168.1)")
    parser.add_argument("--username", default="pi", help="SSH username (default: pi)")
    parser.add_argument("--password", required=True, help="SSH password to try")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout in seconds (default: 3)")
    
    args = parser.parse_args()
    
    try:
        print("\n🔍 Raspberry Pi Finder")
        print("=====================")
        
        results = scan_network(args.subnet, args.username, args.password)
        
        if not results:
            print("\nNo SSH services found on the network.")
        else:
            print("\nSummary of findings:")
            print("===================")
            for ip, is_pi, message in results:
                if is_pi:
                    print(f"🎯 {ip} - Confirmed Raspberry Pi")
                else:
                    print(f"📡 {ip} - {message}")
                    
            print("\nTo connect to a specific IP:")
            print(f"ssh {args.username}@<IP>")
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
    except Exception as e:
        print(f"\nAn error occurred: {e}")