from django.db import models
from django.utils import timezone
import json

class NetworkTrafficLog(models.Model):
    """Model to store network traffic logs"""
    timestamp = models.DateTimeField(default=timezone.now)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_size = models.IntegerField()
    flags = models.CharField(max_length=20, blank=True, null=True)
    is_suspicious = models.BooleanField(default=False)
    threat_level = models.CharField(max_length=20, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical')
    ], default='LOW')

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip', 'timestamp']),
            models.Index(fields=['destination_ip', 'timestamp']),
            models.Index(fields=['is_suspicious']),
        ]

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"

class DDoSAlert(models.Model):
    """Model to store DDoS alerts"""
    ALERT_TYPES = [
        ('VOLUMETRIC', 'Volumetric Attack'),
        ('PROTOCOL', 'Protocol Attack'),
        ('APPLICATION', 'Application Layer Attack'),
        ('SYN_FLOOD', 'SYN Flood'),
        ('UDP_FLOOD', 'UDP Flood'),
        ('ICMP_FLOOD', 'ICMP Flood'),
        ('HTTP_FLOOD', 'HTTP Flood'),
    ]

    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    source_ip = models.GenericIPAddressField()
    target_ip = models.GenericIPAddressField(blank=True, null=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='MEDIUM')
    packets_per_second = models.IntegerField(default=0)
    bytes_per_second = models.IntegerField(default=0)
    duration = models.IntegerField(default=0)  # in seconds
    description = models.TextField()
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(blank=True, null=True)
    mitigation_action = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip', 'timestamp']),
            models.Index(fields=['alert_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['is_resolved']),
        ]

    def __str__(self):
        return f"{self.alert_type} from {self.source_ip} - {self.severity}"

class NetworkStatistics(models.Model):
    """Model to store network statistics for analysis"""
    timestamp = models.DateTimeField(default=timezone.now)
    total_packets = models.IntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    tcp_packets = models.IntegerField(default=0)
    udp_packets = models.IntegerField(default=0)
    icmp_packets = models.IntegerField(default=0)
    http_requests = models.IntegerField(default=0)
    unique_source_ips = models.IntegerField(default=0)
    suspicious_activities = models.IntegerField(default=0)
    blocked_ips = models.IntegerField(default=0)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Network Stats - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

class BlockedIP(models.Model):
    """Model to store blocked IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=200)
    blocked_at = models.DateTimeField(default=timezone.now)
    blocked_until = models.DateTimeField(blank=True, null=True)
    is_permanent = models.BooleanField(default=False)
    block_count = models.IntegerField(default=1)
    last_activity = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-blocked_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['is_permanent']),
        ]

    def __str__(self):
        return f"Blocked IP: {self.ip_address}"

class SystemHealth(models.Model):
    """Model to store system health metrics"""
    timestamp = models.DateTimeField(default=timezone.now)
    cpu_usage = models.FloatField()
    memory_usage = models.FloatField()
    disk_usage = models.FloatField()
    network_in = models.BigIntegerField()
    network_out = models.BigIntegerField()
    active_connections = models.IntegerField()
    detection_engine_status = models.BooleanField(default=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"System Health - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"