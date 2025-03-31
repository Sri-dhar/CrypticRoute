import netifaces
import binascii
import socket

from .utils import log_debug

def get_broadcast_address(interface=None):
    """Gets the broadcast address for a given interface or guesses the default."""
    try:
        if interface:
            if interface not in netifaces.interfaces():
                 log_debug(f"Error: Interface '{interface}' not found.")
                 print(f"Error: Interface '{interface}' not found. Available: {netifaces.interfaces()}")
                 return None
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                # Ensure 'broadcast' key exists before accessing
                if 'broadcast' in addrs[netifaces.AF_INET][0]:
                    return addrs[netifaces.AF_INET][0]['broadcast']
                else:
                    log_debug(f"Warning: Interface '{interface}' has IPv4 address but no broadcast address listed.")
                    # Attempt to calculate if mask is available
                    addr = addrs[netifaces.AF_INET][0].get('addr')
                    netmask = addrs[netifaces.AF_INET][0].get('netmask')
                    if addr and netmask:
                        try:
                            ip_int = int(binascii.hexlify(socket.inet_aton(addr)), 16)
                            mask_int = int(binascii.hexlify(socket.inet_aton(netmask)), 16)
                            bcast_int = ip_int | (~mask_int & 0xffffffff)
                            calculated_bcast = socket.inet_ntoa(binascii.unhexlify(f'{bcast_int:08x}'))
                            log_debug(f"Calculated broadcast address for {interface}: {calculated_bcast}")
                            return calculated_bcast
                        except (socket.error, ValueError, TypeError) as calc_e:
                            log_debug(f"Could not calculate broadcast address for {interface}: {calc_e}")
                            return None # Cannot determine broadcast
                    return None # Cannot determine broadcast
            else:
                log_debug(f"Warning: Interface '{interface}' has no IPv4 address.")
                return None
        else:
            # Try to guess default interface
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                 default_iface = gws['default'][netifaces.AF_INET][1]
                 if default_iface:
                     log_debug(f"Guessed default interface: {default_iface}")
                     addrs = netifaces.ifaddresses(default_iface)
                     if netifaces.AF_INET in addrs and 'broadcast' in addrs[netifaces.AF_INET][0]:
                         return addrs[netifaces.AF_INET][0]['broadcast']
            # Fallback if default guess fails
            log_debug("Default interface guess failed or lacks broadcast. Checking all interfaces.")
            for iface in netifaces.interfaces():
                 addrs = netifaces.ifaddresses(iface)
                 if netifaces.AF_INET in addrs:
                     bcast = addrs[netifaces.AF_INET][0].get('broadcast')
                     addr = addrs[netifaces.AF_INET][0].get('addr', '')
                     # Avoid loopback and ensure broadcast exists
                     if bcast and not addr.startswith('127.'):
                         log_debug(f"Using broadcast address from interface {iface}: {bcast}")
                         return bcast
        log_debug("Could not determine broadcast address.")
        print("Error: Could not determine broadcast address. Please specify an interface with -I or ensure network configuration is correct.")
        return None
    except Exception as e:
        log_debug(f"Error getting broadcast address: {e}")
        print(f"Error getting broadcast address: {e}")
        return None
