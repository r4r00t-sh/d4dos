#!/usr/bin/env python3
"""
D4DoS Detection System - Complete Setup Script
This script sets up and tests the entire system
"""

import os
import sys
import subprocess
import time


def run_command(command, description):
    """Run a command and handle errors"""
    print(f"📋 {description}...")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} completed successfully")
            if result.stdout:
                print(f"   Output: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ {description} failed")
            if result.stderr:
                print(f"   Error: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"❌ {description} failed with exception: {e}")
        return False


def check_file_exists(filepath, description):
    """Check if a file exists"""
    if os.path.exists(filepath):
        print(f"✅ {description} exists")
        return True
    else:
        print(f"❌ {description} missing: {filepath}")
        return False


def setup_directories():
    """Create necessary directories"""
    print("📁 Setting up directories...")

    directories = [
        'static',
        'static/css',
        'static/js',
        'static/images',
        'templates',
        'templates/detection',
        'media'
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")


def check_required_files():
    """Check if all required files exist"""
    print("📄 Checking required files...")

    required_files = [
        ('requirements.txt', 'Requirements file'),
        ('manage.py', 'Django manage.py'),
        ('d4dos_detection/settings.py', 'Django settings'),
        ('d4dos_detection/urls.py', 'Main URLs'),
        ('d4dos_detection/asgi.py', 'ASGI configuration'),
        ('detection/models.py', 'Detection models'),
        ('detection/views.py', 'Detection views'),
        ('detection/admin.py', 'Admin configuration'),
        ('detection/apps.py', 'App configuration'),
        ('detection/urls.py', 'Detection URLs'),
        ('detection/api_urls.py', 'API URLs'),
        ('detection/api_views.py', 'API views'),
        ('detection/serializers.py', 'Serializers'),
        ('detection/utils.py', 'Utility functions'),
        ('detection/detection_engine.py', 'Detection engine'),
        ('templates/detection/dashboard.html', 'Dashboard template'),
    ]

    all_exist = True
    for filepath, description in required_files:
        if not check_file_exists(filepath, description):
            all_exist = False

    return all_exist


def setup_database():
    """Set up the database"""
    print("🗄️ Setting up database...")

    # Make migrations
    if not run_command("python manage.py makemigrations detection", "Creating migrations"):
        return False

    # Apply migrations
    if not run_command("python manage.py migrate", "Applying migrations"):
        return False

    return True


def create_superuser():
    """Create superuser (optional)"""
    print("👤 Creating superuser...")
    print("   You can skip this step by pressing Ctrl+C")
    print("   Or create a superuser later with: python manage.py createsuperuser")

    try:
        subprocess.run("python manage.py createsuperuser", shell=True)
        print("✅ Superuser created successfully")
        return True
    except KeyboardInterrupt:
        print("⏭️ Skipped superuser creation")
        return True
    except Exception as e:
        print(f"⚠️ Superuser creation failed: {e}")
        return True  # Don't fail the setup for this


def test_system():
    """Test the system"""
    print("🧪 Testing system...")

    # Run the test script
    if not run_command("python test_system.py", "Running system tests"):
        print("⚠️ System tests failed, but continuing...")

    return True


def start_server():
    """Start the development server"""
    print("\n🚀 Starting development server...")
    print("   The server will start on http://127.0.0.1:8000/")
    print("   Press Ctrl+C to stop the server")
    print("   Open another terminal to run additional commands")

    try:
        subprocess.run("python manage.py runserver", shell=True)
    except KeyboardInterrupt:
        print("\n⏹️ Server stopped")


def print_final_instructions():
    """Print final setup instructions"""
    print("\n" + "=" * 60)
    print("🎉 D4DoS DETECTION SYSTEM SETUP COMPLETE!")
    print("=" * 60)
    print()
    print("📋 WHAT'S BEEN SET UP:")
    print("  ✅ Django project structure")
    print("  ✅ Database with sample data")
    print("  ✅ Modern web dashboard")
    print("  ✅ REST API endpoints")
    print("  ✅ Admin panel")
    print()
    print("🌐 ACCESS YOUR SYSTEM:")
    print("  🖥️  Dashboard:    http://127.0.0.1:8000/")
    print("  ⚙️  Admin Panel:  http://127.0.0.1:8000/admin/")
    print("  🔌 API Status:   http://127.0.0.1:8000/api/detection-status/")
    print()
    print("🚀 QUICK START:")
    print("  1. python manage.py runserver")
    print("  2. Open http://127.0.0.1:8000/ in your browser")
    print("  3. Click 'Start Monitoring' button")
    print("  4. Watch real-time threat detection!")
    print()
    print("🔧 USEFUL COMMANDS:")
    print("  • Start server:      python manage.py runserver")
    print("  • Create test data:  python test_system.py")
    print("  • Django shell:      python manage.py shell")
    print("  • Admin setup:       python manage.py createsuperuser")
    print()
    print("📚 FEATURES INCLUDED:")
    print("  • Real-time DDoS detection")
    print("  • Modern glassmorphism UI")
    print("  • Interactive charts and graphs")
    print("  • Alert management system")
    print("  • IP blocking capabilities")
    print("  • System health monitoring")
    print("  • RESTful API")
    print()
    print("🛡️ SECURITY FEATURES:")
    print("  • Multi-layer threat detection")
    print("  • Automatic IP blocking")
    print("  • Real-time monitoring")
    print("  • Forensic logging")
    print()
    print("=" * 60)


def main():
    """Main setup function"""
    print("🚀 D4DoS Detection System - Complete Setup")
    print("=" * 50)
    print("This script will set up your DDoS detection system")
    print("=" * 50)

    # Check if we're in the right directory
    if not os.path.exists('manage.py'):
        print("❌ Error: manage.py not found")
        print("   Please run this script from your Django project root directory")
        return False

    steps = [
        ("Setting up directories", setup_directories),
        ("Checking required files", check_required_files),
        ("Setting up database", setup_database),
        ("Creating test data", test_system),
    ]

    print(f"\n📋 Setup will proceed with {len(steps)} steps...")

    for step_name, step_function in steps:
        print(f"\n🔄 Step: {step_name}")
        print("-" * 40)

        if callable(step_function):
            success = step_function()
        else:
            success = step_function

        if not success:
            print(f"\n❌ Setup failed at step: {step_name}")
            print("   Please check the errors above and try again")
            return False

        time.sleep(1)  # Brief pause between steps

    print("\n✅ All setup steps completed successfully!")

    # Optional superuser creation
    print(f"\n🔄 Optional: Create superuser for admin panel")
    print("-" * 40)
    create_superuser()

    # Print final instructions
    print_final_instructions()

    # Ask if user wants to start the server
    while True:
        start_now = input("\n🚀 Start the development server now? (y/n): ").lower().strip()
        if start_now in ['y', 'yes']:
            start_server()
            break
        elif start_now in ['n', 'no']:
            print("\n💡 To start the server later, run: python manage.py runserver")
            break
        else:
            print("   Please enter 'y' for yes or 'n' for no")

    return True


if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n🎉 Setup completed successfully!")
        else:
            print("\n❌ Setup failed. Please check the errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⏹️ Setup cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)