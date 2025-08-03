#!/bin/bash

echo "Starting network monitoring daemon..."

while true; do
    # Run network discovery
    php /app/artisan network:discover 2>/dev/null || true
    
    # Run security monitoring
    php /app/artisan security:monitor 2>/dev/null || true
    
    # Run traffic analysis
    php /app/artisan traffic:analyze 2>/dev/null || true
    
    # Wait 30 seconds before next iteration
    sleep 30
done
