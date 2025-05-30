from django.urls import path
from . import views

app_name = 'detection'

urlpatterns = [
    # Main dashboard
    path('', views.dashboard, name='dashboard'),

    # Web interface pages
    path('alerts/', views.alerts_view, name='alerts'),
    path('traffic/', views.traffic_analysis_view, name='traffic_analysis'),
    path('status/', views.system_status_view, name='system_status'),

    # AJAX/API endpoints for web interface
    path('api/dashboard-data/', views.get_dashboard_data, name='dashboard_data'),
    path('api/alerts-data/', views.get_alerts_data, name='alerts_data'),
    path('api/traffic-data/', views.get_traffic_data, name='traffic_data'),
    path('api/system-status/', views.get_system_status, name='system_status_data'),
    path('api/blocked-ips/', views.get_blocked_ips, name='blocked_ips'),

    # Action endpoints
    path('api/resolve-alert/<int:alert_id>/', views.resolve_alert, name='resolve_alert'),
    path('api/block-ip/', views.block_ip, name='block_ip'),
]