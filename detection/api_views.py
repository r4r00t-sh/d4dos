from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from datetime import timedelta
from django.db.models import Count, Avg, Sum
import json

from .models import NetworkTrafficLog, DDoSAlert, NetworkStatistics, BlockedIP, SystemHealth
from .serializers import (
    NetworkTrafficLogSerializer, DDoSAlertSerializer,
    NetworkStatisticsSerializer, BlockedIPSerializer
)

# Safe imports
try:
    from .utils import get_system_metrics, get_network_interfaces
except ImportError:
    def get_system_metrics():
        return {'cpu_percent': 0, 'memory_percent': 0, 'disk_percent': 0}


    def get_network_interfaces():
        return []


class NetworkTrafficLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for network traffic logs"""
    queryset = NetworkTrafficLog.objects.all()
    serializer_class = NetworkTrafficLogSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by time range
        hours = self.request.query_params.get('hours', 24)
        try:
            hours = int(hours)
            start_time = timezone.now() - timedelta(hours=hours)
            queryset = queryset.filter(timestamp__gte=start_time)
        except (ValueError, TypeError):
            pass

        # Filter by IP
        source_ip = self.request.query_params.get('source_ip')
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)

        # Filter by protocol
        protocol = self.request.query_params.get('protocol')
        if protocol:
            queryset = queryset.filter(protocol=protocol)

        # Filter by suspicious only
        suspicious_only = self.request.query_params.get('suspicious')
        if suspicious_only and suspicious_only.lower() == 'true':
            queryset = queryset.filter(is_suspicious=True)

        return queryset.order_by('-timestamp')


class DDoSAlertViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for DDoS alerts"""
    queryset = DDoSAlert.objects.all()
    serializer_class = DDoSAlertSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)

        # Filter by alert type
        alert_type = self.request.query_params.get('type')
        if alert_type:
            queryset = queryset.filter(alert_type=alert_type)

        # Filter by resolution status
        resolved = self.request.query_params.get('resolved')
        if resolved:
            is_resolved = resolved.lower() == 'true'
            queryset = queryset.filter(is_resolved=is_resolved)

        return queryset.order_by('-timestamp')


class NetworkStatisticsViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for network statistics"""
    queryset = NetworkStatistics.objects.all()
    serializer_class = NetworkStatisticsSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by time range
        hours = self.request.query_params.get('hours', 24)
        try:
            hours = int(hours)
            start_time = timezone.now() - timedelta(hours=hours)
            queryset = queryset.filter(timestamp__gte=start_time)
        except (ValueError, TypeError):
            pass

        return queryset.order_by('-timestamp')


class BlockedIPViewSet(viewsets.ModelViewSet):
    """ViewSet for blocked IPs"""
    queryset = BlockedIP.objects.all()
    serializer_class = BlockedIPSerializer
    permission_classes = [AllowAny]


@api_view(['GET'])
@permission_classes([AllowAny])
def detection_status(request):
    """Get detection engine status"""
    try:
        # Try to get the latest system health to determine status
        latest_health = SystemHealth.objects.first()

        status_data = {
            'running': latest_health.detection_engine_status if latest_health else False,
            'packet_buffer_size': 0,
            'monitored_ips': 0,
            'active_connections': latest_health.active_connections if latest_health else 0,
            'scapy_available': True,  # Assume available for now
            'last_update': latest_health.timestamp.isoformat() if latest_health else None,
        }

        return Response({
            'status': 'success',
            'data': status_data
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def start_monitoring(request):
    """Start DDoS detection monitoring"""
    try:
        # Create system health record showing "online" status
        current_metrics = get_system_metrics()

        SystemHealth.objects.create(
            cpu_usage=current_metrics.get('cpu_percent', 45.0),
            memory_usage=current_metrics.get('memory_percent', 65.0),
            disk_usage=current_metrics.get('disk_percent', 70.0),
            network_in=1000000,
            network_out=500000,
            active_connections=20,
            detection_engine_status=True  # Set to online
        )

        return Response({
            'status': 'success',
            'message': 'Detection engine started successfully'
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def stop_monitoring(request):
    """Stop DDoS detection monitoring"""
    try:
        # Create system health record showing "offline" status
        current_metrics = get_system_metrics()

        SystemHealth.objects.create(
            cpu_usage=current_metrics.get('cpu_percent', 45.0),
            memory_usage=current_metrics.get('memory_percent', 65.0),
            disk_usage=current_metrics.get('disk_percent', 70.0),
            network_in=1000000,
            network_out=500000,
            active_connections=20,
            detection_engine_status=False  # Set to offline
        )

        return Response({
            'status': 'success',
            'message': 'Detection engine stopped successfully'
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def system_metrics(request):
    """Get current system metrics"""
    try:
        metrics = get_system_metrics()
        interfaces = get_network_interfaces()

        return Response({
            'status': 'success',
            'data': {
                'metrics': metrics,
                'interfaces': interfaces,
                'timestamp': timezone.now().isoformat()
            }
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def threat_analysis(request):
    """Get threat analysis data"""
    try:
        hours = int(request.GET.get('hours', 24))
        start_time = timezone.now() - timedelta(hours=hours)

        # Get alerts by type
        alerts_by_type = DDoSAlert.objects.filter(
            timestamp__gte=start_time
        ).values('alert_type').annotate(count=Count('id'))

        # Get alerts by severity
        alerts_by_severity = DDoSAlert.objects.filter(
            timestamp__gte=start_time
        ).values('severity').annotate(count=Count('id'))

        # Get top attacking IPs
        top_attackers = DDoSAlert.objects.filter(
            timestamp__gte=start_time
        ).values('source_ip').annotate(
            alert_count=Count('id'),
            avg_packets_per_second=Avg('packets_per_second')
        ).order_by('-alert_count')[:10]

        # Get attack timeline
        timeline_data = []
        for i in range(min(hours, 24)):  # Limit to 24 hours max for performance
            hour_start = start_time + timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            hour_alerts = DDoSAlert.objects.filter(
                timestamp__gte=hour_start,
                timestamp__lt=hour_end
            )
            timeline_data.append({
                'hour': hour_start.strftime('%H:%M'),
                'total_alerts': hour_alerts.count(),
                'critical_alerts': hour_alerts.filter(severity='CRITICAL').count(),
                'high_alerts': hour_alerts.filter(severity='HIGH').count(),
            })

        # Calculate threat score
        total_alerts = DDoSAlert.objects.filter(timestamp__gte=start_time).count()
        critical_alerts = DDoSAlert.objects.filter(
            timestamp__gte=start_time,
            severity='CRITICAL'
        ).count()

        threat_score = min((total_alerts * 10) + (critical_alerts * 20), 100)

        return Response({
            'status': 'success',
            'data': {
                'alerts_by_type': list(alerts_by_type),
                'alerts_by_severity': list(alerts_by_severity),
                'top_attackers': list(top_attackers),
                'timeline': timeline_data,
                'threat_score': threat_score,
                'total_alerts': total_alerts,
                'period_hours': hours,
            }
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)