#!/bin/bash
set -e

echo "=== Network Security App Starting ==="

# Create database if it doesn't exist
touch /app/storage/database.sqlite
php artisan migrate --force

# Start background network monitoring
php artisan queue:work --daemon &

# Start HHVM with network monitoring
hhvm -m server -p 8080 -c /app/hhvm.ini &

# Start PHP-FPM with Laravel
php-fpm &

# Start Nginx (keep in foreground)
nginx -g "daemon off;"
