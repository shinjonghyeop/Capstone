#!/bin/bash
echo "🛑 Stopping Hacklipse Victim Environment..."
docker compose down -v
docker system prune -f
echo "✅ Environment stopped and cleaned up!"
