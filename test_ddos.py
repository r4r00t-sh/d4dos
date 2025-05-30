#!/usr/bin/env python3
"""
D4DoS Detection System - Test Script
This script tests all components and creates sample data
"""

import os
import sys
import django
import random
from datetime import datetime, timedelta

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'd4dos_detection.settings')
django.setup()

from django.utils import timezone
from detection.models import NetworkTrafficLog, DDoSAlert, SystemHealth, BlockedIP
from detection.utils import get_system_metrics


def create_sample_traffic_data():
    """Create sample network traffic data"""
    print("📊 Creating sample traffic data...")

    # Clear existing data
    NetworkTrafficLog.objects.all().delete()

    # Create normal traffic
    normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]

    for i in range(100):
        NetworkTrafficLog.objects.create(
            source_ip=random.choice(normal_ips),
            destination_ip="192.168.1.1",
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443, 22, 25]),
            protocol=random.choice(['TCP', 'UDP', 'ICMP']),
            packet_size=random.randint(64, 1500),
            is_suspicious=False,
            threat_level='LOW',
            timestamp=timezone.now() - timedelta(minutes=random.randint(0, 60))
        )

    # Create suspicious traffic
    suspicious_ip = "10.0.0.100"

    for i in range(50):
        NetworkTrafficLog.objects.create(
            source_ip=suspicious_ip,
            destination_ip="192.168.1.1",
            source_port=random.randint(1024, 65535),
            destination_port=80,
            protocol='TCP',
            packet_size=random.randint(64, 512),  # Smaller packets
            is_suspicious=True,
            threat_level=random.choice(['MEDIUM', 'HIGH']),
            timestamp=timezone.now() - timedelta(minutes=random.randint(0, 30))
        )

    print(f"✅ Created {NetworkTrafficLog.objects.count()} traffic log entries")


def create_sample_alerts():
    """Create sample DDoS alerts"""
    print("🚨 Creating sample alerts...")

    # Clear existing alerts
    DDoSAlert.objects.all().delete()

    # Create various types of alerts
    alert_types = ['SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'VOLUMETRIC', 'HTTP_FLOOD']
    severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    for i in range(10):
        alert_type = random.choice(alert_types)
        severity = random.choice(severities)

        DDoSAlert.objects.create(
            alert_type=alert_type,
            source_ip=f"10.0.0.{random.randint(100, 200)}",
            target_ip="192.168.1.1",
            severity=severity,
            packets_per_second=random.randint(100, 10000),
            bytes_per_second=random.randint(10000, 1000000),
            duration=random.randint(10, 300),
            description=f"{alert_type} attack detected from suspicious IP",
            is_resolved=random.choice([True, False]),
            timestamp=timezone.now() - timedelta(hours=random.randint(0, 24))
        )

    print(f"✅ Created {DDoSAlert.objects.count()} alert entries")


def create_system_health_data():
    """Create system health monitoring data"""
    print("💻 Creating system health data...")

    # Clear existing health data
    SystemHealth.objects.all().delete()

    try:
        # Get real system metrics
        metrics = get_system_metrics()

        # Create current health record (online)
        SystemHealth.objects.create(
            cpu_usage=metrics.get('cpu_percent', 45.0),
            memory_usage=metrics.get('memory_percent', 65.0),
            disk_usage=metrics.get('disk_percent', 70.0),
            network_in=random.randint(1000000, 5000000),
            network_out=random.randint(500000, 2000000),
            active_connections=random.randint(20, 100),
            detection_engine_status=True  # Set as online
        )

        # Create historical data
        for i in range(24):  # 24 hours of data
            SystemHealth.objects.create(
                cpu_usage=random.uniform(20.0, 80.0),
                memory_usage=random.uniform(40.0, 90.0),
                disk_usage=random.uniform(60.0, 85.0),
                network_in=random.randint(1000000, 5000000),
                network_out=random.randint(500000, 2000000),
                active_connections=random.randint(15, 150),
                detection_engine_status=random.choice([True, False]),
                timestamp=timezone.now() - timedelta(hours=i)
            )

        print(f"✅ Created {SystemHealth.objects.count()} system health records")

    except Exception as e:
        print(f"⚠️ Warning: Could not get real system metrics: {e}")

        # Create fake data
        SystemHealth.objects.create(
            cpu_usage=45.0,
            memory_usage=65.0,
            disk_usage=70.0,
            network_in=2000000,
            network_out=1000000,
            active_connections=50,
            detection_engine_status=True
        )
        print("✅ Created fallback system health record")


def create_blocked_ips():
    """Create sample blocked IPs"""
    print("🚫 Creating blocked IP data...")

    # Clear existing blocked IPs
    BlockedIP.objects.all().delete()

    # Create some blocked IPs
    malicious_ips = [
        "10.0.0.100", "192.168.100.50", "172.16.0.99",
        "203.0.113.195", "198.51.100.178"
    ]

    for ip in malicious_ips:
        BlockedIP.objects.create(
            ip_address=ip,
            reason=f"DDoS attack detected from {ip}",
            blocked_at=timezone.now() - timedelta(hours=random.randint(0, 48)),
            is_permanent=random.choice([True, False]),
            blocked_until=timezone.now() + timedelta(hours=random.randint(1, 72)) if random.choice(
                [True, False]) else None,
            block_count=random.randint(1, 5),
            last_activity=timezone.now() - timedelta(minutes=random.randint(0, 120))
        )

    print(f"✅ Created {BlockedIP.objects.count()} blocked IP entries")


def test_api_endpoints():
    """Test API endpoints"""
    print("🔌 Testing API endpoints...")

    import requests

    base_url = "http://127.0.0.1:8000"

    # Test endpoints
    endpoints = [
        "/api/dashboard-data/",
        "/api/detection-status/",
        "/api/system-metrics/",
        "/api/alerts/",
        "/api/traffic-logs/",
        "/api/blocked-ips/"
    ]

    results = []

    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            status = "✅ OK" if response.status_code == 200 else f"❌ {response.status_code}"
            results.append(f"{endpoint}: {status}")
        except requests.exceptions.RequestException as e:
            results.append(f"{endpoint}: ❌ ERROR - {str(e)}")

    print("API Test Results:")
    for result in results:
        print(f"  {result}")

    return results


def print_summary():
    """Print summary of created data"""
    print("\n" + "=" * 50)
    print("📊 DATA SUMMARY")
    print("=" * 50)

    try:
        traffic_count = NetworkTrafficLog.objects.count()
        suspicious_count = NetworkTrafficLog.objects.filter(is_suspicious=True).count()
        alert_count = DDoSAlert.objects.count()
        active_alerts = DDoSAlert.objects.filter(is_resolved=False).count()
        health_count = SystemHealth.objects.count()
        blocked_count = BlockedIP.objects.count()

        print(f"📈 Traffic Logs: {traffic_count} total ({suspicious_count} suspicious)")
        print(f"🚨 Alerts: {alert_count} total ({active_alerts} active)")
        print(f"💻 System Health Records: {health_count}")
        print(f"🚫 Blocked IPs: {blocked_count}")

        # Get latest system status
        latest_health = SystemHealth.objects.first()
        if latest_health:
            status = "🟢 ONLINE" if latest_health.detection_engine_status else "🔴 OFFLINE"
            print(f"🔍 Detection Engine: {status}")
            print(f"💾 CPU: {latest_health.cpu_usage:.1f}% | Memory: {latest_health.memory_usage:.1f}%")

    except Exception as e:
        print(f"❌ Error getting summary: {e}")

    print("=" * 50)
    print("🌐 DASHBOARD LINKS")
    print("=" * 50)
    print("🖥️  Dashboard: http://127.0.0.1:8000/")
    print("⚙️  Admin Panel: http://127.0.0.1:8000/admin/")
    print("🔌 API Status: http://127.0.0.1:8000/api/detection-status/")
    print("=" * 50)


def main():
    """Main test function"""
    print("🚀 D4DoS Detection System - Test Script")
    print("=" * 50)

    try:
        # Create all sample data
        create_sample_traffic_data()
        create_sample_alerts()
        create_system_health_data()
        create_blocked_ips()

        print("\n🧪 Testing API endpoints...")
        test_api_endpoints()

        # Print summary
        print_summary()

        print("\n✅ Test script completed successfully!")
        print("💡 Start your Django server and check the dashboard:")
        print("   python manage.py runserver")

    except Exception as e:
        print(f"\n❌ Error running test script: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()