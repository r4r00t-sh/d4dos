from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import NetworkTrafficLog, DDoSAlert, NetworkStatistics, BlockedIP, SystemHealth

@admin.register(NetworkTrafficLog)
class NetworkTrafficLogAdmin(admin.ModelAdmin):
    """Admin interface for NetworkTrafficLog"""
    
    list_display = [
        'timestamp', 'source_ip', 'destination_ip', 'protocol', 
        'packet_size', 'is_suspicious', 'threat_level_badge'
    ]
    list_filter = [
        'protocol', 'is_suspicious', 'threat_level', 'timestamp'
    ]
    search_fields = ['source_ip', 'destination_ip']
    readonly_fields = ['timestamp']
    list_per_page = 50
    
    def threat_level_badge(self, obj):
        """Display threat level as colored badge"""
        colors = {
            'LOW': 'green',
            'MEDIUM': 'orange', 
            'HIGH': 'red',
            'CRITICAL': 'darkred'
        }
        color = colors.get(obj.threat_level, 'gray')
        html = '<span style="background-color: ' + color + '; color: white; padding: 2px 8px; border-radius: 3px;">' + str(obj.threat_level) + '</span>'
        return mark_safe(html)
    threat_level_badge.short_description = 'Threat Level'

@admin.register(DDoSAlert)
class DDoSAlertAdmin(admin.ModelAdmin):
    """Admin interface for DDoSAlert"""
    
    list_display = [
        'timestamp', 'alert_type', 'source_ip', 'target_ip', 
        'severity_badge', 'packets_per_second', 'resolution_status'
    ]
    list_filter = [
        'alert_type', 'severity', 'is_resolved', 'timestamp'
    ]
    search_fields = ['source_ip', 'target_ip', 'description']
    readonly_fields = ['timestamp', 'duration']
    list_per_page = 50
    
    fieldsets = (
        ('Alert Information', {
            'fields': ('timestamp', 'alert_type', 'severity', 'description')
        }),
        ('Network Details', {
            'fields': ('source_ip', 'target_ip', 'packets_per_second', 'bytes_per_second', 'duration')
        }),
        ('Resolution', {
            'fields': ('is_resolved', 'resolved_at', 'mitigation_action')
        }),
    )
    
    def severity_badge(self, obj):
        """Display severity as colored badge"""
        colors = {
            'LOW': 'green',
            'MEDIUM': 'orange',
            'HIGH': 'red', 
            'CRITICAL': 'darkred'
        }
        color = colors.get(obj.severity, 'gray')
        html = '<span style="background-color: ' + color + '; color: white; padding: 2px 8px; border-radius: 3px;">' + str(obj.severity) + '</span>'
        return mark_safe(html)
    severity_badge.short_description = 'Severity'
    
    def resolution_status(self, obj):
        """Display resolution status"""
        if obj.is_resolved:
            return mark_safe('<span style="color: green;">✓ Resolved</span>')
        else:
            return mark_safe('<span style="color: red;">⚠ Active</span>')
    resolution_status.short_description = 'Status'

@admin.register(NetworkStatistics)
class NetworkStatisticsAdmin(admin.ModelAdmin):
    """Admin interface for NetworkStatistics"""
    
    list_display = [
        'timestamp', 'total_packets', 'total_bytes_formatted', 
        'unique_source_ips', 'suspicious_activities', 'protocol_breakdown'
    ]
    list_filter = ['timestamp']
    readonly_fields = ['timestamp']
    list_per_page = 50
    
    def total_bytes_formatted(self, obj):
        """Format total bytes for display"""
        try:
            bytes_value = float(obj.total_bytes)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes_value < 1024.0:
                    return str(round(bytes_value, 2)) + ' ' + unit
                bytes_value /= 1024.0
            return str(round(bytes_value, 2)) + ' PB'
        except (ValueError, TypeError):
            return str(obj.total_bytes) + ' B'
    total_bytes_formatted.short_description = 'Total Bytes'
    
    def protocol_breakdown(self, obj):
        """Show protocol breakdown"""
        tcp = str(obj.tcp_packets)
        udp = str(obj.udp_packets)
        icmp = str(obj.icmp_packets)
        http = str(obj.http_requests)
        return mark_safe('TCP: ' + tcp + ' | UDP: ' + udp + ' | ICMP: ' + icmp + ' | HTTP: ' + http)
    protocol_breakdown.short_description = 'Protocols'

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    """Admin interface for BlockedIP"""
    
    list_display = [
        'ip_address', 'reason', 'blocked_at', 'block_status', 
        'block_count', 'last_activity'
    ]
    list_filter = ['is_permanent', 'blocked_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['blocked_at', 'block_count', 'last_activity']
    list_per_page = 50
    
    def block_status(self, obj):
        """Display block status"""
        from django.utils import timezone
        
        if obj.is_permanent:
            return mark_safe('<span style="color: red;">🔒 Permanent</span>')
        elif obj.blocked_until and obj.blocked_until > timezone.now():
            return mark_safe('<span style="color: orange;">⏰ Temporary</span>')
        else:
            return mark_safe('<span style="color: gray;">⏹ Expired</span>')
    block_status.short_description = 'Status'

@admin.register(SystemHealth)
class SystemHealthAdmin(admin.ModelAdmin):
    """Admin interface for SystemHealth"""
    
    list_display = [
        'timestamp', 'cpu_usage_display', 'memory_usage_display', 
        'disk_usage_display', 'active_connections', 'engine_status'
    ]
    list_filter = ['detection_engine_status', 'timestamp']
    readonly_fields = ['timestamp']
    list_per_page = 50
    
    def cpu_usage_display(self, obj):
        """Display CPU usage with color coding"""
        try:
            cpu_value = float(obj.cpu_usage)
            cpu_rounded = round(cpu_value, 1)
            
            if cpu_value > 80:
                color = 'red'
            elif cpu_value > 60:
                color = 'orange'
            else:
                color = 'green'
            
            html = '<span style="color: ' + color + ';">' + str(cpu_rounded) + '%</span>'
            return mark_safe(html)
        except (ValueError, TypeError):
            return str(obj.cpu_usage) + '%'
    cpu_usage_display.short_description = 'CPU Usage'
    
    def memory_usage_display(self, obj):
        """Display memory usage with color coding"""
        try:
            memory_value = float(obj.memory_usage)
            memory_rounded = round(memory_value, 1)
            
            if memory_value > 80:
                color = 'red'
            elif memory_value > 60:
                color = 'orange'
            else:
                color = 'green'
            
            html = '<span style="color: ' + color + ';">' + str(memory_rounded) + '%</span>'
            return mark_safe(html)
        except (ValueError, TypeError):
            return str(obj.memory_usage) + '%'
    memory_usage_display.short_description = 'Memory Usage'
    
    def disk_usage_display(self, obj):
        """Display disk usage with color coding"""
        try:
            disk_value = float(obj.disk_usage)
            disk_rounded = round(disk_value, 1)
            
            if disk_value > 90:
                color = 'red'
            elif disk_value > 70:
                color = 'orange'
            else:
                color = 'green'
            
            html = '<span style="color: ' + color + ';">' + str(disk_rounded) + '%</span>'
            return mark_safe(html)
        except (ValueError, TypeError):
            return str(obj.disk_usage) + '%'
    disk_usage_display.short_description = 'Disk Usage'
    
    def engine_status(self, obj):
        """Display detection engine status"""
        if obj.detection_engine_status:
            return mark_safe('<span style="color: green;">✓ Running</span>')
        else:
            return mark_safe('<span style="color: red;">✗ Stopped</span>')
    engine_status.short_description = 'Detection Engine'

# Customize admin site
admin.site.site_header = "D4DoS Detection System Administration"
admin.site.site_title = "D4DoS Admin"
admin.site.index_title = "Welcome to D4DoS Detection System Administration"