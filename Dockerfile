# Network Security App Dockerfile
# Multi-stage build for optimized production deployment
# Author: Hirotoshi Uchida
# Project: Network Security App
# Homepage: https://hirotoshiuchida.onrender.com

# Build Stage
FROM ubuntu:22.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV PHP_VERSION=8.1
ENV NODE_VERSION=18

# Set working directory
WORKDIR /app

# Install system dependencies and network tools
RUN apt-get update && apt-get install -y \
    # Basic system tools
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg2 \
    curl \
    wget \
    unzip \
    git \
    supervisor \
    cron \
    logrotate \
    # Network monitoring tools
    nmap \
    tcpdump \
    tshark \
    wireshark \
    net-tools \
    iproute2 \
    arp-scan \
    traceroute \
    dnsutils \
    iputils-ping \
    netcat \
    iftop \
    iotop \
    htop \
    lsof \
    strace \
    procps \
    psmisc \
    # Web server and PHP
    nginx \
    php${PHP_VERSION}-fpm \
    php${PHP_VERSION}-cli \
    php${PHP_VERSION}-common \
    php${PHP_VERSION}-mysql \
    php${PHP_VERSION}-sqlite3 \
    php${PHP_VERSION}-redis \
    php${PHP_VERSION}-xml \
    php${PHP_VERSION}-mbstring \
    php${PHP_VERSION}-curl \
    php${PHP_VERSION}-zip \
    php${PHP_VERSION}-gd \
    php${PHP_VERSION}-bcmath \
    php${PHP_VERSION}-intl \
    php${PHP_VERSION}-soap \
    php${PHP_VERSION}-xsl \
    php${PHP_VERSION}-opcache \
    && rm -rf /var/lib/apt/lists/*

# Install HHVM
RUN wget -O - https://dl.hhvm.com/conf/hhvm.gpg.key | apt-key add - \
    && echo "deb https://dl.hhvm.com/ubuntu $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/hhvm.list \
    && apt-get update \
    && apt-get install -y hhvm \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js and npm
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && chmod +x /usr/local/bin/composer

# Configure network tools permissions for non-root execution
RUN chmod u+s /usr/bin/nmap \
    && chmod u+s /usr/bin/tcpdump \
    && chmod u+s /usr/sbin/arp-scan \
    && chmod u+s /bin/ping \
    && chmod u+s /usr/bin/traceroute \
    && chmod u+s /usr/bin/tshark

# Create application user and directories
RUN useradd -m -s /bin/bash -u 1001 appuser \
    && mkdir -p /app/storage/logs \
    && mkdir -p /app/storage/app/public \
    && mkdir -p /app/storage/framework/cache \
    && mkdir -p /app/storage/framework/sessions \
    && mkdir -p /app/storage/framework/views \
    && mkdir -p /app/bootstrap/cache \
    && mkdir -p /app/public/assets \
    && mkdir -p /var/log/supervisor

# Copy application files
COPY --chown=appuser:appuser . /app/

# Install PHP dependencies
RUN cd /app && composer install --no-dev --optimize-autoloader --no-interaction

# Install Node.js dependencies and build assets
RUN cd /app && npm ci --only=production \
    && npm run production \
    && rm -rf node_modules

# Production Stage
FROM ubuntu:22.04 AS production

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV PHP_VERSION=8.1
ENV APP_ENV=production
ENV APP_DEBUG=false

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    # Network monitoring tools
    nmap \
    tcpdump \
    tshark \
    net-tools \
    iproute2 \
    arp-scan \
    traceroute \
    dnsutils \
    iputils-ping \
    netcat \
    # Web server and PHP runtime
    nginx \
    php${PHP_VERSION}-fpm \
    php${PHP_VERSION}-cli \
    php${PHP_VERSION}-common \
    php${PHP_VERSION}-mysql \
    php${PHP_VERSION}-sqlite3 \
    php${PHP_VERSION}-redis \
    php${PHP_VERSION}-xml \
    php${PHP_VERSION}-mbstring \
    php${PHP_VERSION}-curl \
    php${PHP_VERSION}-zip \
    php${PHP_VERSION}-gd \
    php${PHP_VERSION}-bcmath \
    php${PHP_VERSION}-intl \
    php${PHP_VERSION}-opcache \
    # HHVM
    hhvm \
    # System utilities
    supervisor \
    cron \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -m -s /bin/bash -u 1001 appuser

# Set working directory
WORKDIR /app

# Copy application from builder stage
COPY --from=builder --chown=appuser:appuser /app /app

# Copy configuration files
COPY --chown=root:root config/nginx.conf /etc/nginx/sites-available/default
COPY --chown=root:root config/hhvm.ini /etc/hhvm/hhvm.ini
COPY --chown=root:root config/php-fpm.conf /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
COPY --chown=root:root config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Configure network tools permissions
RUN chmod u+s /usr/bin/nmap \
    && chmod u+s /usr/bin/tcpdump \
    && chmod u+s /usr/sbin/arp-scan \
    && chmod u+s /bin/ping \
    && chmod u+s /usr/bin/traceroute \
    && chmod u+s /usr/bin/tshark

# Set directory permissions
RUN chown -R appuser:appuser /app/storage \
    && chown -R appuser:appuser /app/bootstrap/cache \
    && chmod -R 755 /app/storage \
    && chmod -R 755 /app/bootstrap/cache \
    && chmod -R 755 /app/public

# Create SQLite database
RUN touch /app/storage/database.sqlite \
    && chown appuser:appuser /app/storage/database.sqlite \
    && chmod 664 /app/storage/database.sqlite

# Configure PHP-FPM
RUN sed -i 's/listen = \/run\/php\/php8.1-fpm.sock/listen = 127.0.0.1:9000/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf \
    && sed -i 's/;listen.mode = 0660/listen.mode = 0660/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# Configure Nginx
RUN rm -f /etc/nginx/sites-enabled/default \
    && ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Create startup script
RUN cat > /app/start.sh << 'EOF'
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
EOF

RUN chmod +x /app/start.sh

# Create health check script
RUN cat > /app/health-check.sh << 'EOF'
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
EOF

RUN chmod +x /app/health-check.sh

# Create network monitoring script
RUN cat > /app/network-monitor.sh << 'EOF'
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
EOF

RUN chmod +x /app/network-monitor.sh

# Create log directory and set permissions
RUN mkdir -p /var/log/network-security \
    && chown -R appuser:appuser /var/log/network-security \
    && chmod -R 755 /var/log/network-security

# Set up log rotation
RUN cat > /etc/logrotate.d/network-security << 'EOF'
/app/storage/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su appuser appuser
}

/var/log/network-security/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    su appuser appuser
}
EOF

# Expose ports
EXPOSE 8080 9000

# Set up volume for persistent data
VOLUME ["/app/storage"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/health-check.sh

# Switch to application user
USER appuser

# Set environment variables for the application
ENV PATH="/app:${PATH}"
ENV APP_KEY=""
ENV APP_URL="http://localhost:8080"
ENV LOG_CHANNEL=stderr
ENV LOG_LEVEL=info
ENV DB_CONNECTION=sqlite
ENV DB_DATABASE=/app/storage/database.sqlite
ENV CACHE_DRIVER=file
ENV SESSION_DRIVER=file
ENV QUEUE_CONNECTION=sync
ENV NETWORK_INTERFACE=eth0
ENV SCAN_TIMEOUT=30
ENV MONITOR_INTERVAL=5
ENV MAX_SCAN_RANGE=254
ENV ENABLE_REAL_TIME=true
ENV SECURITY_ALERTS=true

# Default command
CMD ["/app/start.sh"]

# Build information
LABEL maintainer="Hirotoshi Uchida <admin@hirotoshiuchida.onrender.com>"
LABEL description="Network Security Monitoring Application"
LABEL version="1.0.0"
LABEL homepage="https://hirotoshiuchida.onrender.com"
LABEL repository="https://github.com/Uchida16104/Network-Security-App"
LABEL documentation="https://github.com/Uchida16104/Network-Security-App/README.md"
LABEL license="MIT"

# Additional build arguments for customization
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Network Security App" \
      org.label-schema.description="Real-time network security monitoring and analysis" \
      org.label-schema.url="https://hirotoshiuchida.onrender.com" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/Uchida16104/Network-Security-App" \
      org.label-schema.vendor="Hirotoshi Uchida" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"
