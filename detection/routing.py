from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/detection/$', consumers.DetectionConsumer.as_asgi()),
    re_path(r'ws/alerts/$', consumers.AlertConsumer.as_asgi()),
    re_path(r'ws/traffic/$', consumers.TrafficConsumer.as_asgi()),
]