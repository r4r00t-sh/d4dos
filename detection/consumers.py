import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from datetime import timedelta
from .models import DDoSAlert, NetworkTrafficLog, SystemHealth


class DetectionConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time detection updates"""

    async def connect(self):
        await self.channel_layer.group_add("detection_updates", self.channel_name)
        await self.accept()

        # Start sending periodic updates
        asyncio.create_task(self.send_periodic_updates())

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("detection_updates", self.channel_name)

    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type')

            if message_type == 'get_status':
                await self.send_detection_status()
            elif message_type == 'get_dashboard_data':
                await self.send_dashboard_data()
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))

    async def send_periodic_updates(self):
        """Send periodic updates every 5 seconds"""
        while True:
            try:
                await self.send_dashboard_data()
                await asyncio.sleep(5)
            except Exception as e:
                print(f"Error sending periodic updates: {e}")
                break

    async def send_detection_status(self):
        """Send detection engine status"""
        try:
            from .detection_engine import DDoSDetectionEngine
            engine = DDoSDetectionEngine()
            status = engine.get_status()

            await self.send(text_data=json.dumps({
                'type': 'detection_status',
                'data': status
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Error getting detection status: {str(e)}'
            }))

    async def send_dashboard_data(self):
        """Send dashboard data"""
        try:
            dashboard_data = await self.get_dashboard_data()
            await self.send(text_data=json.dumps({
                'type': 'dashboard_update',
                'data': dashboard_data
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Error getting dashboard data: {str(e)}'
            }))

    @database_sync_to_async
    def get_dashboard_data(self):
        """Get dashboard data from database"""
        try:
            current_time = timezone.now()

            # Get recent alerts
            recent_alerts = DDoSAlert.objects.filter(
                timestamp__gte=current_time - timedelta(hours=24)
            )

            # Get recent traffic
            recent_traffic = NetworkTrafficLog.objects.filter(
                timestamp__gte=current_time - timedelta(hours=1)
            )

            # Get latest system health
            latest_health = SystemHealth.objects.first()

            return {
                'alerts': {
                    'total': recent_alerts.count(),
                    'critical': recent_alerts.filter(severity='CRITICAL').count(),
                    'high': recent_alerts.filter(severity='HIGH').count(),
                    'medium': recent_alerts.filter(severity='MEDIUM').count(),
                    'low': recent_alerts.filter(severity='LOW').count(),
                    'unresolved': recent_alerts.filter(is_resolved=False).count(),
                },
                'traffic': {
                    'total_packets': recent_traffic.count(),
                    'suspicious_packets': recent_traffic.filter(is_suspicious=True).count(),
                    'unique_sources': recent_traffic.values('source_ip').distinct().count(),
                    'tcp_packets': recent_traffic.filter(protocol='TCP').count(),
                    'udp_packets': recent_traffic.filter(protocol='UDP').count(),
                    'icmp_packets': recent_traffic.filter(protocol='ICMP').count(),
                },
                'system': {
                    'cpu_usage': latest_health.cpu_usage if latest_health else 0,
                    'memory_usage': latest_health.memory_usage if latest_health else 0,
                    'disk_usage': latest_health.disk_usage if latest_health else 0,
                    'active_connections': latest_health.active_connections if latest_health else 0,
                    'detection_status': latest_health.detection_engine_status if latest_health else False,
                },
                'timestamp': current_time.isoformat(),
            }
        except Exception as e:
            return {'error': str(e)}

    async def detection_alert(self, event):
        """Handle detection alert messages"""
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'data': event['data']
        }))


class AlertConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time alert updates"""

    async def connect(self):
        await self.channel_layer.group_add("alerts", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("alerts", self.channel_name)

    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type')

            if message_type == 'get_recent_alerts':
                await self.send_recent_alerts()
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))

    async def send_recent_alerts(self):
        """Send recent alerts"""
        try:
            alerts_data = await self.get_recent_alerts()
            await self.send(text_data=json.dumps({
                'type': 'recent_alerts',
                'data': alerts_data
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Error getting recent alerts: {str(e)}'
            }))

    @database_sync_to_async
    def get_recent_alerts(self):
        """Get recent alerts from database"""
        alerts = DDoSAlert.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).order_by('-timestamp')[:20]

        alerts_data = []
        for alert in alerts:
            alerts_data.append({
                'id': alert.id,
                'timestamp': alert.timestamp.isoformat(),
                'type': alert.alert_type,
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip,
                'severity': alert.severity,
                'description': alert.description,
                'is_resolved': alert.is_resolved,
            })

        return alerts_data

    async def new_alert(self, event):
        """Handle new alert notifications"""
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'data': event['data']
        }))


class TrafficConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time traffic updates"""

    async def connect(self):
        await self.channel_layer.group_add("traffic", self.channel_name)
        await self.accept()

        # Start sending periodic traffic updates
        asyncio.create_task(self.send_periodic_traffic_updates())

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("traffic", self.channel_name)

    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type')

            if message_type == 'get_traffic_stats':
                await self.send_traffic_stats()
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))

    async def send_periodic_traffic_updates(self):
        """Send periodic traffic updates every 10 seconds"""
        while True:
            try:
                await self.send_traffic_stats()
                await asyncio.sleep(10)
            except Exception as e:
                print(f"Error sending traffic updates: {e}")
                break

    async def send_traffic_stats(self):
        """Send traffic statistics"""
        try:
            traffic_data = await self.get_traffic_stats()
            await self.send(text_data=json.dumps({
                'type': 'traffic_update',
                'data': traffic_data
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Error getting traffic stats: {str(e)}'
            }))

    @database_sync_to_async
    def get_traffic_stats(self):
        """Get traffic statistics from database"""
        current_time = timezone.now()
        recent_traffic = NetworkTrafficLog.objects.filter(
            timestamp__gte=current_time - timedelta(minutes=5)
        )

        # Protocol distribution
        protocols = {}
        for protocol in ['TCP', 'UDP', 'ICMP']:
            protocols[protocol] = recent_traffic.filter(protocol=protocol).count()

        # Top source IPs
        top_sources = list(recent_traffic.values('source_ip').annotate(
            count=models.Count('id')
        ).order_by('-count')[:10])

        return {
            'total_packets': recent_traffic.count(),
            'suspicious_packets': recent_traffic.filter(is_suspicious=True).count(),
            'unique_sources': recent_traffic.values('source_ip').distinct().count(),
            'protocols': protocols,
            'top_sources': top_sources,
            'timestamp': current_time.isoformat(),
        }

    async def traffic_update(self, event):
        """Handle traffic update messages"""
        await self.send(text_data=json.dumps({
            'type': 'traffic_update',
            'data': event['data']
        }))