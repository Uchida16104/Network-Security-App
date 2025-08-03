#!/bin/bash
set -e

echo "=== Network Security App Starting ==="
echo "Author: Hirotoshi Uchida"
echo "Homepage: https://hirotoshiuchida.onrender.com"
echo "======================================"

# Wait for network interface to be ready
sleep 2

# Detect network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1 || echo "eth0")
echo "Detected network interface: $INTERFACE"
export NETWORK_INTERFACE=$INTERFACE

mkdir -p /app/storage/logs /app/storage/framework/cache /app/storage/framework/sessions /app/storage/framework/views /app/bootstrap/cache
chown -R appuser:appuser /app/storage /app/bootstrap/cache 2>/dev/null || true
chmod -R 755 /app/storage /app/bootstrap/cache 2>/dev/null || true

# Laravel optimizations
echo "Optimizing Laravel..."
php artisan config:cache
php artisan route:cache
php artisan view:cache

# Run database migrations
echo "Running database migrations..."
php artisan migrate --force

# Create storage link
php artisan storage:link

# Initialize network monitoring
echo "Initializing network monitoring..."
php artisan network:initialize --interface=$INTERFACE || true

# Start services with supervisor
echo "Starting services..."
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
