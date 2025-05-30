import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
import psutil
import socket

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Network monitoring will be limited.")

from .models import NetworkTrafficLog, DDoSAlert, NetworkStatistics, SystemHealth
from .utils import get_system_metrics

logger = logging.getLogger(__name__)


class DDoSDetectionEngine:
    """Core DDoS detection engine"""

    def __init__(self):
        self.running = False
        self.packet_buffer = deque(maxlen=10000)
        self.ip_counters = defaultdict(lambda: defaultdict(int))
        self.protocol_counters = defaultdict(int)
        self.connection_tracker = defaultdict(set)
        self.alert_cooldown = {}

        # Thresholds
        self.packet_threshold = getattr(settings, 'DDOS_DETECTION', {}).get('PACKET_THRESHOLD', 1000)
        self.ip_threshold = getattr(settings, 'DDOS_DETECTION', {}).get('IP_THRESHOLD', 500)
        self.alert_cooldown_time = getattr(settings, 'DDOS_DETECTION', {}).get('ALERT_COOLDOWN', 300)

        # Detection patterns
        self.syn_flood_threshold = 100
        self.udp_flood_threshold = 200
        self.icmp_flood_threshold = 50
        self.http_flood_threshold = 1000

        self.monitor_thread = None
        self.analysis_thread = None

    def start_monitoring(self):
        """Start the DDoS detection monitoring"""
        if self.running:
            return

        self.running = True
        logger.info("Starting D4DoS Detection Engine")

        # Start packet monitoring thread
        if SCAPY_AVAILABLE:
            self.monitor_thread = threading.Thread(target=self._packet_monitor, daemon=True)
            self.monitor_thread.start()

        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()

        # Start system health monitoring
        self.health_thread = threading.Thread(target=self._health_monitor, daemon=True)
        self.health_thread.start()

    def stop_monitoring(self):
        """Stop the DDoS detection monitoring"""
        self.running = False
        logger.info("Stopping D4DoS Detection Engine")

    def _packet_monitor(self):
        """Monitor network packets using Scapy"""
        if not SCAPY_AVAILABLE:
            return

        def packet_handler(packet):
            if not self.running:
                return

            try:
                if IP in packet:
                    self._process_packet(packet)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")

        try:
            # Start packet capture
            sniff(
                iface=getattr(settings, 'DDOS_DETECTION', {}).get('MONITORING_INTERFACE', None),
                prn=packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error in packet monitoring: {e}")

    def _process_packet(self, packet):
        """Process individual network packet"""
        try:
            ip_layer = packet[IP]
            timestamp = datetime.now()

            # Extract packet information
            packet_info = {
                'timestamp': timestamp,
                'source_ip': ip_layer.src,
                'destination_ip': ip_layer.dst,
                'packet_size': len(packet),
                'protocol': 'UNKNOWN',
                'source_port': 0,
                'destination_port': 0,
                'flags': '',
            }

            # Determine protocol and extract port information
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.update({
                    'protocol': 'TCP',
                    'source_port': tcp_layer.sport,
                    'destination_port': tcp_layer.dport,
                    'flags': str(tcp_layer.flags),
                })
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'source_port': udp_layer.sport,
                    'destination_port': udp_layer.dport,
                })
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'

            # Add to packet buffer for analysis
            self.packet_buffer.append(packet_info)

            # Update counters
            self._update_counters(packet_info)

            # Check for immediate threats
            self._check_immediate_threats(packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _update_counters(self, packet_info):
        """Update packet counters for analysis"""
        src_ip = packet_info['source_ip']
        protocol = packet_info['protocol']
        current_minute = int(time.time() // 60)

        # Update IP-based counters
        self.ip_counters[src_ip][current_minute] += 1

        # Update protocol counters
        self.protocol_counters[protocol] += 1

        # Track connections for TCP
        if protocol == 'TCP':
            connection_key = f"{src_ip}:{packet_info['source_port']}"
            self.connection_tracker[src_ip].add(connection_key)

    def _check_immediate_threats(self, packet_info):
        """Check for immediate DDoS threats"""
        src_ip = packet_info['source_ip']
        protocol = packet_info['protocol']
        current_minute = int(time.time() // 60)

        # Check if IP is in cooldown
        if src_ip in self.alert_cooldown:
            if time.time() - self.alert_cooldown[src_ip] < self.alert_cooldown_time:
                return

        # Check packet rate from single IP
        recent_packets = sum(
            self.ip_counters[src_ip].get(current_minute - i, 0)
            for i in range(5)  # Last 5 minutes
        )

        if recent_packets > self.ip_threshold:
            self._create_alert(
                alert_type='VOLUMETRIC',
                source_ip=src_ip,
                target_ip=packet_info['destination_ip'],
                severity='HIGH',
                packets_per_second=recent_packets // 5,
                description=f"High packet rate detected from {src_ip}: {recent_packets} packets in 5 minutes"
            )
            self.alert_cooldown[src_ip] = time.time()

        # Protocol-specific checks
        if protocol == 'TCP' and 'S' in packet_info.get('flags', ''):
            # SYN flood detection
            syn_count = len([p for p in list(self.packet_buffer)[-100:]
                             if p['source_ip'] == src_ip and p['protocol'] == 'TCP'
                             and 'S' in p.get('flags', '')])

            if syn_count > self.syn_flood_threshold:
                self._create_alert(
                    alert_type='SYN_FLOOD',
                    source_ip=src_ip,
                    target_ip=packet_info['destination_ip'],
                    severity='CRITICAL',
                    packets_per_second=syn_count,
                    description=f"SYN flood attack detected from {src_ip}"
                )
                self.alert_cooldown[src_ip] = time.time()

    def _analysis_loop(self):
        """Main analysis loop for pattern detection"""
        while self.running:
            try:
                self._analyze_traffic_patterns()
                self._cleanup_old_data()
                self._save_statistics()
                time.sleep(10)  # Analyze every 10 seconds
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                time.sleep(5)

    def _analyze_traffic_patterns(self):
        """Analyze traffic patterns for DDoS detection"""
        if len(self.packet_buffer) < 100:
            return

        current_time = time.time()
        recent_packets = [p for p in self.packet_buffer
                          if (current_time - p['timestamp'].timestamp()) < 300]  # Last 5 minutes

        if not recent_packets:
            return

        # Analyze by source IP
        ip_stats = defaultdict(lambda: {'count': 0, 'protocols': set(), 'ports': set()})

        for packet in recent_packets:
            src_ip = packet['source_ip']
            ip_stats[src_ip]['count'] += 1
            ip_stats[src_ip]['protocols'].add(packet['protocol'])
            ip_stats[src_ip]['ports'].add(packet['destination_port'])

        # Detect volumetric attacks
        for ip, stats in ip_stats.items():
            if stats['count'] > self.packet_threshold:
                # Check if already alerted recently
                if ip in self.alert_cooldown and (current_time - self.alert_cooldown[ip]) < self.alert_cooldown_time:
                    continue

                severity = 'CRITICAL' if stats['count'] > self.packet_threshold * 2 else 'HIGH'

                self._create_alert(
                    alert_type='VOLUMETRIC',
                    source_ip=ip,
                    severity=severity,
                    packets_per_second=stats['count'] // 5,
                    description=f"Volumetric attack detected: {stats['count']} packets from {ip} in 5 minutes"
                )
                self.alert_cooldown[ip] = current_time

        # Detect protocol-specific attacks
        self._detect_protocol_attacks(recent_packets)

    def _detect_protocol_attacks(self, packets):
        """Detect protocol-specific DDoS attacks"""
        protocol_stats = defaultdict(lambda: defaultdict(int))

        for packet in packets:
            src_ip = packet['source_ip']
            protocol = packet['protocol']
            protocol_stats[src_ip][protocol] += 1

        current_time = time.time()

        for src_ip, protocols in protocol_stats.items():
            # Skip if in cooldown
            if src_ip in self.alert_cooldown and (
                    current_time - self.alert_cooldown[src_ip]) < self.alert_cooldown_time:
                continue

            # UDP flood detection
            if protocols.get('UDP', 0) > self.udp_flood_threshold:
                self._create_alert(
                    alert_type='UDP_FLOOD',
                    source_ip=src_ip,
                    severity='HIGH',
                    packets_per_second=protocols['UDP'] // 5,
                    description=f"UDP flood detected from {src_ip}: {protocols['UDP']} UDP packets"
                )
                self.alert_cooldown[src_ip] = current_time

            # ICMP flood detection
            if protocols.get('ICMP', 0) > self.icmp_flood_threshold:
                self._create_alert(
                    alert_type='ICMP_FLOOD',
                    source_ip=src_ip,
                    severity='MEDIUM',
                    packets_per_second=protocols['ICMP'] // 5,
                    description=f"ICMP flood detected from {src_ip}: {protocols['ICMP']} ICMP packets"
                )
                self.alert_cooldown[src_ip] = current_time

    def _create_alert(self, alert_type, source_ip, severity='MEDIUM', target_ip=None,
                      packets_per_second=0, bytes_per_second=0, description=''):
        """Create a DDoS alert"""
        try:
            alert = DDoSAlert.objects.create(
                alert_type=alert_type,
                source_ip=source_ip,
                target_ip=target_ip,
                severity=severity,
                packets_per_second=packets_per_second,
                bytes_per_second=bytes_per_second,
                description=description,
                duration=0  # Will be updated if attack continues
            )

            logger.warning(f"DDoS Alert Created: {alert_type} from {source_ip} - {severity}")

            # Mark related traffic as suspicious
            NetworkTrafficLog.objects.filter(
                source_ip=source_ip,
                timestamp__gte=timezone.now() - timedelta(minutes=5)
            ).update(is_suspicious=True, threat_level=severity)

        except Exception as e:
            logger.error(f"Error creating alert: {e}")

    def _cleanup_old_data(self):
        """Clean up old data from counters and buffers"""
        current_minute = int(time.time() // 60)
        cleanup_threshold = current_minute - 60  # Keep last 60 minutes

        # Clean IP counters
        for ip in list(self.ip_counters.keys()):
            old_minutes = [minute for minute in self.ip_counters[ip].keys()
                           if minute < cleanup_threshold]
            for minute in old_minutes:
                del self.ip_counters[ip][minute]

            # Remove empty IP entries
            if not self.ip_counters[ip]:
                del self.ip_counters[ip]

        # Clean connection tracker
        for ip in list(self.connection_tracker.keys()):
            if len(self.connection_tracker[ip]) == 0:
                del self.connection_tracker[ip]

    def _save_statistics(self):
        """Save network statistics to database"""
        try:
            current_time = timezone.now()
            recent_packets = [p for p in self.packet_buffer
                              if (current_time - timezone.make_aware(p['timestamp'])).seconds < 300]

            if not recent_packets:
                return

            # Calculate statistics
            total_packets = len(recent_packets)
            tcp_packets = len([p for p in recent_packets if p['protocol'] == 'TCP'])
            udp_packets = len([p for p in recent_packets if p['protocol'] == 'UDP'])
            icmp_packets = len([p for p in recent_packets if p['protocol'] == 'ICMP'])
            total_bytes = sum(p['packet_size'] for p in recent_packets)
            unique_ips = len(set(p['source_ip'] for p in recent_packets))

            # Count suspicious activities
            suspicious_count = NetworkTrafficLog.objects.filter(
                timestamp__gte=current_time - timedelta(minutes=5),
                is_suspicious=True
            ).count()

            # Save statistics
            NetworkStatistics.objects.create(
                total_packets=total_packets,
                total_bytes=total_bytes,
                tcp_packets=tcp_packets,
                udp_packets=udp_packets,
                icmp_packets=icmp_packets,
                unique_source_ips=unique_ips,
                suspicious_activities=suspicious_count,
            )

        except Exception as e:
            logger.error(f"Error saving statistics: {e}")

    def _health_monitor(self):
        """Monitor system health"""
        while self.running:
            try:
                metrics = get_system_metrics()

                # Get network statistics
                net_stats = psutil.net_io_counters()
                active_connections = len(psutil.net_connections())

                SystemHealth.objects.create(
                    cpu_usage=metrics['cpu_percent'],
                    memory_usage=metrics['memory_percent'],
                    disk_usage=metrics['disk_percent'],
                    network_in=net_stats.bytes_recv,
                    network_out=net_stats.bytes_sent,
                    active_connections=active_connections,
                    detection_engine_status=self.running
                )

                time.sleep(60)  # Update every minute

            except Exception as e:
                logger.error(f"Error in health monitoring: {e}")
                time.sleep(30)

    def get_status(self):
        """Get current detection engine status"""
        return {
            'running': self.running,
            'packet_buffer_size': len(self.packet_buffer),
            'monitored_ips': len(self.ip_counters),
            'active_connections': len(self.connection_tracker),
            'scapy_available': SCAPY_AVAILABLE,
        }