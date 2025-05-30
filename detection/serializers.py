from rest_framework import serializers
from .models import NetworkTrafficLog, DDoSAlert, NetworkStatistics, BlockedIP, SystemHealth


class NetworkTrafficLogSerializer(serializers.ModelSerializer):
    """Serializer for NetworkTrafficLog model"""

    class Meta:
        model = NetworkTrafficLog
        fields = [
            'id', 'timestamp', 'source_ip', 'destination_ip',
            'source_port', 'destination_port', 'protocol',
            'packet_size', 'flags', 'is_suspicious', 'threat_level'
        ]
        read_only_fields = ['id', 'timestamp']


class DDoSAlertSerializer(serializers.ModelSerializer):
    """Serializer for DDoSAlert model"""

    duration_formatted = serializers.SerializerMethodField()
    timestamp_formatted = serializers.SerializerMethodField()

    class Meta:
        model = DDoSAlert
        fields = [
            'id', 'timestamp', 'timestamp_formatted', 'alert_type',
            'source_ip', 'target_ip', 'severity', 'packets_per_second',
            'bytes_per_second', 'duration', 'duration_formatted',
            'description', 'is_resolved', 'resolved_at', 'mitigation_action'
        ]
        read_only_fields = ['id', 'timestamp']

    def get_duration_formatted(self, obj):
        """Format duration in human readable format"""
        if obj.duration < 60:
            return f"{obj.duration}s"
        elif obj.duration < 3600:
            return f"{obj.duration // 60}m {obj.duration % 60}s"
        else:
            hours = obj.duration // 3600
            minutes = (obj.duration % 3600) // 60
            return f"{hours}h {minutes}m"

    def get_timestamp_formatted(self, obj):
        """Format timestamp for display"""
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')


class NetworkStatisticsSerializer(serializers.ModelSerializer):
    """Serializer for NetworkStatistics model"""

    timestamp_formatted = serializers.SerializerMethodField()
    total_bytes_formatted = serializers.SerializerMethodField()

    class Meta:
        model = NetworkStatistics
        fields = [
            'id', 'timestamp', 'timestamp_formatted', 'total_packets',
            'total_bytes', 'total_bytes_formatted', 'tcp_packets',
            'udp_packets', 'icmp_packets', 'http_requests',
            'unique_source_ips', 'suspicious_activities', 'blocked_ips'
        ]
        read_only_fields = ['id', 'timestamp']

    def get_timestamp_formatted(self, obj):
        """Format timestamp for display"""
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')

    def get_total_bytes_formatted(self, obj):
        """Format bytes in human readable format"""
        bytes_value = obj.total_bytes
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


class BlockedIPSerializer(serializers.ModelSerializer):
    """Serializer for BlockedIP model"""

    blocked_at_formatted = serializers.SerializerMethodField()
    blocked_until_formatted = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = BlockedIP
        fields = [
            'id', 'ip_address', 'reason', 'blocked_at', 'blocked_at_formatted',
            'blocked_until', 'blocked_until_formatted', 'is_permanent',
            'block_count', 'last_activity', 'status'
        ]
        read_only_fields = ['id', 'blocked_at', 'block_count', 'last_activity']

    def get_blocked_at_formatted(self, obj):
        """Format blocked_at timestamp"""
        return obj.blocked_at.strftime('%Y-%m-%d %H:%M:%S')

    def get_blocked_until_formatted(self, obj):
        """Format blocked_until timestamp"""
        if obj.blocked_until:
            return obj.blocked_until.strftime('%Y-%m-%d %H:%M:%S')
        return 'Permanent' if obj.is_permanent else 'Not set'

    def get_status(self, obj):
        """Get current block status"""
        from django.utils import timezone

        if obj.is_permanent:
            return 'Permanent'
        elif obj.blocked_until and obj.blocked_until > timezone.now():
            return 'Active'
        else:
            return 'Expired'


class SystemHealthSerializer(serializers.ModelSerializer):
    """Serializer for SystemHealth model"""

    timestamp_formatted = serializers.SerializerMethodField()
    network_in_formatted = serializers.SerializerMethodField()
    network_out_formatted = serializers.SerializerMethodField()
    status_indicator = serializers.SerializerMethodField()

    class Meta:
        model = SystemHealth
        fields = [
            'id', 'timestamp', 'timestamp_formatted', 'cpu_usage',
            'memory_usage', 'disk_usage', 'network_in', 'network_in_formatted',
            'network_out', 'network_out_formatted', 'active_connections',
            'detection_engine_status', 'status_indicator'
        ]
        read_only_fields = ['id', 'timestamp']

    def get_timestamp_formatted(self, obj):
        """Format timestamp for display"""
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')

    def get_network_in_formatted(self, obj):
        """Format network in bytes"""
        return self._format_bytes(obj.network_in)

    def get_network_out_formatted(self, obj):
        """Format network out bytes"""
        return self._format_bytes(obj.network_out)

    def get_status_indicator(self, obj):
        """Get overall system status indicator"""
        if not obj.detection_engine_status:
            return 'ERROR'
        elif obj.cpu_usage > 90 or obj.memory_usage > 90 or obj.disk_usage > 95:
            return 'CRITICAL'
        elif obj.cpu_usage > 70 or obj.memory_usage > 70 or obj.disk_usage > 80:
            return 'WARNING'
        else:
            return 'GOOD'

    def _format_bytes(self, bytes_value):
        """Helper method to format bytes"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


class AlertSummarySerializer(serializers.Serializer):
    """Serializer for alert summary data"""

    total_alerts = serializers.IntegerField()
    critical_alerts = serializers.IntegerField()
    high_alerts = serializers.IntegerField()
    medium_alerts = serializers.IntegerField()
    low_alerts = serializers.IntegerField()
    resolved_alerts = serializers.IntegerField()
    active_alerts = serializers.IntegerField()


class TrafficSummarySerializer(serializers.Serializer):
    """Serializer for traffic summary data"""

    total_packets = serializers.IntegerField()
    suspicious_packets = serializers.IntegerField()
    unique_source_ips = serializers.IntegerField()
    tcp_packets = serializers.IntegerField()
    udp_packets = serializers.IntegerField()
    icmp_packets = serializers.IntegerField()
    packets_per_second = serializers.FloatField()


class ThreatAnalysisSerializer(serializers.Serializer):
    """Serializer for threat analysis data"""

    threat_score = serializers.IntegerField()
    threat_level = serializers.CharField()
    total_alerts = serializers.IntegerField()
    attack_sources = serializers.IntegerField()
    blocked_ips = serializers.IntegerField()
    top_attack_type = serializers.CharField()
    attack_trend = serializers.CharField()  # 'increasing', 'decreasing', 'stable'