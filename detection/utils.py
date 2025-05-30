import psutil
import socket
import platform
import subprocess
import logging
from datetime import datetime
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_system_metrics():
    """Get current system performance metrics"""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)

        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent

        # Network statistics
        net_io = psutil.net_io_counters()

        # Load average (Unix-like systems)
        try:
            load_avg = psutil.getloadavg()
        except AttributeError:
            # Windows doesn't have load average
            load_avg = [0, 0, 0]

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'memory_total': memory.total,
            'memory_available': memory.available,
            'memory_used': memory.used,
            'disk_percent': disk_percent,
            'disk_total': disk.total,
            'disk_used': disk.used,
            'disk_free': disk.free,
            'network_bytes_sent': net_io.bytes_sent,
            'network_bytes_recv': net_io.bytes_recv,
            'network_packets_sent': net_io.packets_sent,
            'network_packets_recv': net_io.packets_recv,
            'load_avg_1': load_avg[0],
            'load_avg_5': load_avg[1],
            'load_avg_15': load_avg[2],
            'timestamp': timezone.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_percent': 0,
            'error': str(e)
        }


def get_network_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = []
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        for interface_name, addresses in net_if_addrs.items():
            interface_info = {
                'name': interface_name,
                'addresses': [],
                'is_up': net_if_stats[interface_name].isup if interface_name in net_if_stats else False,
                'speed': net_if_stats[interface_name].speed if interface_name in net_if_stats else 0,
            }

            for addr in addresses:
                if addr.family == socket.AF_INET:
                    interface_info['addresses'].append({
                        'type': 'IPv4',
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast,
                    })
                elif addr.family == socket.AF_INET6:
                    interface_info['addresses'].append({
                        'type': 'IPv6',
                        'address': addr.address,
                        'netmask': addr.netmask,
                    })

            interfaces.append(interface_info)

        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []


def get_active_connections():
    """Get active network connections"""
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                connections.append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status,
                    'pid': conn.pid,
                    'family': conn.family,
                    'type': conn.type,
                })

        return connections
    except Exception as e:
        logger.error(f"Error getting active connections: {e}")
        return []


def validate_ip_address(ip):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


def is_private_ip(ip):
    """Check if IP address is private"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_geolocation(ip):
    """Get geolocation information for IP address (placeholder)"""
    # This would typically use a GeoIP database or service
    # For now, return a placeholder
    if is_private_ip(ip):
        return {
            'country': 'Private Network',
            'city': 'Local',
            'latitude': 0,
            'longitude': 0,
        }

    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'latitude': 0,
        'longitude': 0,
    }


def format_bytes(bytes_value):
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def format_packets_per_second(packets, duration=1):
    """Format packets per second with appropriate units"""
    pps = packets / duration
    if pps < 1000:
        return f"{pps:.0f} pps"
    elif pps < 1000000:
        return f"{pps / 1000:.1f}K pps"
    else:
        return f"{pps / 1000000:.1f}M pps"


def calculate_threat_score(packet_rate, unique_ips, protocol_diversity, connection_rate):
    """Calculate threat score based on various metrics"""
    score = 0

    # Packet rate score (0-40 points)
    if packet_rate > 10000:
        score += 40
    elif packet_rate > 5000:
        score += 30
    elif packet_rate > 1000:
        score += 20
    elif packet_rate > 100:
        score += 10

    # IP diversity score (0-20 points)
    if unique_ips < 5:
        score += 20  # Few IPs generating lots of traffic is suspicious
    elif unique_ips < 20:
        score += 10

    # Protocol diversity score (0-20 points)
    if protocol_diversity < 2:
        score += 15  # Single protocol attacks
    elif protocol_diversity < 3:
        score += 10

    # Connection rate score (0-20 points)
    if connection_rate > 1000:
        score += 20
    elif connection_rate > 500:
        score += 15
    elif connection_rate > 100:
        score += 10

    return min(score, 100)  # Cap at 100


def get_threat_level(score):
    """Get threat level based on score"""
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    else:
        return 'LOW'


def ping_host(host, timeout=3):
    """Ping a host to check connectivity"""
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['ping', '-n', '1', '-w', str(timeout * 1000), host],
                                    capture_output=True, text=True, timeout=timeout + 1)
        else:
            result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), host],
                                    capture_output=True, text=True, timeout=timeout + 1)

        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False


def check_port(host, port, timeout=3):
    """Check if a port is open on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def get_system_info():
    """Get system information"""
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())

        return {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'boot_time': boot_time.isoformat(),
            'uptime': str(datetime.now() - boot_time),
            'python_version': platform.python_version(),
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {'error': str(e)}


def generate_alert_message(alert_type, source_ip, severity, additional_info=None):
    """Generate human-readable alert message"""
    messages = {
        'VOLUMETRIC': f"Volumetric DDoS attack detected from {source_ip}",
        'SYN_FLOOD': f"SYN flood attack detected from {source_ip}",
        'UDP_FLOOD': f"UDP flood attack detected from {source_ip}",
        'ICMP_FLOOD': f"ICMP flood attack detected from {source_ip}",
        'HTTP_FLOOD': f"HTTP flood attack detected from {source_ip}",
        'PROTOCOL': f"Protocol-based attack detected from {source_ip}",
        'APPLICATION': f"Application layer attack detected from {source_ip}",
    }

    base_message = messages.get(alert_type, f"Security alert from {source_ip}")

    if additional_info:
        base_message += f" - {additional_info}"

    return f"[{severity}] {base_message}"


def clean_old_logs(days=30):
    """Clean old log entries from database"""
    try:
        from .models import NetworkTrafficLog, DDoSAlert, NetworkStatistics, SystemHealth
        cutoff_date = timezone.now() - timezone.timedelta(days=days)

        # Clean old traffic logs
        deleted_traffic = NetworkTrafficLog.objects.filter(timestamp__lt=cutoff_date).delete()

        # Clean old resolved alerts
        deleted_alerts = DDoSAlert.objects.filter(
            timestamp__lt=cutoff_date,
            is_resolved=True
        ).delete()

        # Clean old statistics (keep monthly summaries)
        deleted_stats = NetworkStatistics.objects.filter(timestamp__lt=cutoff_date).delete()

        # Clean old system health data
        deleted_health = SystemHealth.objects.filter(timestamp__lt=cutoff_date).delete()

        logger.info(f"Cleaned old logs: {deleted_traffic[0]} traffic logs, "
                    f"{deleted_alerts[0]} alerts, {deleted_stats[0]} statistics, "
                    f"{deleted_health[0]} health records")

        return {
            'traffic_logs': deleted_traffic[0],
            'alerts': deleted_alerts[0],
            'statistics': deleted_stats[0],
            'health_records': deleted_health[0],
        }
    except Exception as e:
        logger.error(f"Error cleaning old logs: {e}")
        return {'error': str(e)}