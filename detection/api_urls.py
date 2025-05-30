from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import api_views

router = DefaultRouter()
router.register(r'traffic-logs', api_views.NetworkTrafficLogViewSet)
router.register(r'alerts', api_views.DDoSAlertViewSet)
router.register(r'statistics', api_views.NetworkStatisticsViewSet)
router.register(r'blocked-ips', api_views.BlockedIPViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('detection-status/', api_views.detection_status, name='detection_status'),
    path('start-monitoring/', api_views.start_monitoring, name='start_monitoring'),
    path('stop-monitoring/', api_views.stop_monitoring, name='stop_monitoring'),
    path('system-metrics/', api_views.system_metrics, name='system_metrics'),
    path('threat-analysis/', api_views.threat_analysis, name='threat_analysis'),
]