#!/bin/bash

# Check if services are running
if ! pgrep -f "php-fpm" > /dev/null; then
    echo "PHP-FPM is not running"
    exit 1
fi

if ! pgrep -f "nginx" > /dev/null; then
    echo "Nginx is not running"
    exit 1
fi

# Check API endpoint
if ! curl -f -s http://127.0.0.1:8080/api/health-check > /dev/null; then
    echo "API health check failed"
    exit 1
fi

echo "All services are healthy"
exit 0
