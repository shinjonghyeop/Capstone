#!/bin/bash
echo "🎯 Starting Complete Hacklipse Victim Environment..."
echo "================================================="

# 기존 컨테이너 정리
echo "🧹 Cleaning up existing containers..."
docker compose down 2>/dev/null || true

# Docker Compose로 전체 환경 실행
echo "🐳 Building and starting containers..."
docker compose up --build -d

echo ""
echo "⏳ Waiting for services to start..."
sleep 20

echo ""
echo "🔍 Checking service status..."
docker compose ps

echo ""
echo "✅ Victim environment is now running!"
echo ""
echo "🌐 Web Services:"
echo "  - Apache (vulnerable):     http://localhost:8080"
echo "  - Nginx (secondary):       http://localhost:8081"
echo "  - WordPress 4.7.1:         http://localhost:8082"
echo "  - Drupal 7.67:             http://localhost:8083"
echo "  - Custom vulnerable:       http://localhost:9999"
echo "  - Dashboard:               http://localhost:8084"
echo ""
echo "🔌 Network Services:"
echo "  - MySQL (main):     localhost:3306 (admin/admin)"
echo "  - MySQL (WP):       localhost:3307 (wordpress/wordpress)"  
echo "  - PostgreSQL:       localhost:5432 (drupal/drupal)"
echo "  - SSH:              localhost:2222 (admin/admin123)"
echo "  - FTP:              localhost:2121 (anonymous)"
echo "  - Redis:            localhost:6379 (no auth)"
echo "  - SNMP:             localhost:1161 (public/private)"
echo ""
echo "🔍 OSINT Testing:"
echo "  python3 osint_collector.py http://localhost:8080"
echo ""
echo "📊 Monitor: http://localhost:8084"
echo "🛑 Stop: ./stop-all.sh"
