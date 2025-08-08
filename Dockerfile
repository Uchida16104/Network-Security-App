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
ENV NODE_VERSION=24

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

# Create minimal composer.json if it doesn't exist
RUN if [ ! -f /app/composer.json ]; then \
        echo '{' > /app/composer.json && \
        echo '  "name": "uchida16104/network-security-app",' >> /app/composer.json && \
        echo '  "description": "Network Security Monitoring Application",' >> /app/composer.json && \
        echo '  "type": "project",' >> /app/composer.json && \
        echo '  "require": {' >> /app/composer.json && \
        echo '    "php": "^8.1"' >> /app/composer.json && \
        echo '  },' >> /app/composer.json && \
        echo '  "autoload": {' >> /app/composer.json && \
        echo '    "psr-4": {' >> /app/composer.json && \
        echo '      "App\\\\": "app/"' >> /app/composer.json && \
        echo '    }' >> /app/composer.json && \
        echo '  },' >> /app/composer.json && \
        echo '  "minimum-stability": "stable"' >> /app/composer.json && \
        echo '}' >> /app/composer.json; \
    fi && \
    composer install --no-dev --optimize-autoloader --no-scripts || echo "Composer install completed with warnings"

# Create minimal package.json and install Node.js dependencies if needed
RUN cd /app && \
    if [ ! -f package.json ]; then \
        echo '{"name": "network-security-app", "version": "1.0.0", "scripts": {"production": "echo Production build completed"}}' > package.json; \
    fi && \
    if [ ! -f package-lock.json ]; then \
        npm install --package-lock-only; \
    fi && \
    (npm ci --omit=dev || npm install --production) && \
    (npm run production || echo "Production build skipped - no build script found") && \
    rm -rf node_modules

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

# Configure network tools permissions
RUN chmod u+s /usr/bin/nmap \
    && chmod u+s /usr/bin/tcpdump \
    && chmod u+s /usr/sbin/arp-scan \
    && chmod u+s /bin/ping \
    && chmod u+s /usr/bin/traceroute \
    && chmod u+s /usr/bin/tshark

# Set directory permissions including supervisor logs
RUN chown -R appuser:appuser /app/storage \
    && chown -R appuser:appuser /app/bootstrap/cache \
    && chown -R appuser:appuser /var/log/supervisor \
    && chmod -R 755 /app/storage \
    && chmod -R 755 /app/bootstrap/cache \
    && chmod -R 755 /app/public \
    && chmod -R 755 /var/log/supervisor

# Create comprehensive public/index.php with embedded NetworkController and NetworkMonitor
RUN mkdir -p /app/public

COPY index.php /app/public/index.php

RUN chown appuser:appuser /app/public/index.php

# Create nginx configuration
RUN echo 'server {' > /etc/nginx/sites-available/default && \
    echo '    listen       8080;' >> /etc/nginx/sites-available/default && \
    echo '    server_name  _;' >> /etc/nginx/sites-available/default && \
    echo '    root         /app/public;' >> /etc/nginx/sites-available/default && \
    echo '    index        index.php;' >> /etc/nginx/sites-available/default && \
    echo '' >> /etc/nginx/sites-available/default && \
    echo '    location / {' >> /etc/nginx/sites-available/default && \
    echo '        try_files $uri $uri/ /index.php?$query_string;' >> /etc/nginx/sites-available/default && \
    echo '    }' >> /etc/nginx/sites-available/default && \
    echo '' >> /etc/nginx/sites-available/default && \
    echo '    location ~ \.php$ {' >> /etc/nginx/sites-available/default && \
    echo '        fastcgi_pass   127.0.0.1:9000;' >> /etc/nginx/sites-available/default && \
    echo '        fastcgi_index  index.php;' >> /etc/nginx/sites-available/default && \
    echo '        include        fastcgi_params;' >> /etc/nginx/sites-available/default && \
    echo '        fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;' >> /etc/nginx/sites-available/default && \
    echo '    }' >> /etc/nginx/sites-available/default && \
    echo '}' >> /etc/nginx/sites-available/default

# Create PHP-FPM configuration
RUN echo '[www]' > /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'user = appuser' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'group = appuser' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'listen = 127.0.0.1:9000' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm = dynamic' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.max_children = 10' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.start_servers = 2' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.min_spare_servers = 1' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.max_spare_servers = 3' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# Create supervisor configuration
RUN echo '[supervisord]' > /etc/supervisor/conf.d/supervisord.conf && \
    echo 'nodaemon = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'logfile = /var/log/supervisor/supervisord.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'pidfile = /var/run/supervisord.pid' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'user = root' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '[program:nginx]' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'command = /usr/sbin/nginx -g "daemon off;"' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autostart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autorestart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stdout_logfile = /var/log/supervisor/nginx.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stderr_logfile = /var/log/supervisor/nginx_error.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '[program:php-fpm]' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'command = /usr/sbin/php-fpm8.1 -F' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autostart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autorestart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stdout_logfile = /var/log/supervisor/php-fpm.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stderr_logfile = /var/log/supervisor/php-fpm_error.log' >> /etc/supervisor/conf.d/supervisord.conf

# Create start script
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'set -e' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo 'echo "=== Network Security App Starting ==="' >> /app/start.sh && \
    echo 'echo "Author: Hirotoshi Uchida"' >> /app/start.sh && \
    echo 'echo "Homepage: https://hirotoshiuchida.onrender.com"' >> /app/start.sh && \
    echo 'echo "======================================"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Wait for network interface to be ready' >> /app/start.sh && \
    echo 'sleep 2' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Detect network interface' >> /app/start.sh && \
    echo 'INTERFACE=$(ip route | grep default | awk "{print \$5}" | head -1 || echo "eth0")' >> /app/start.sh && \
    echo 'echo "Detected network interface: $INTERFACE"' >> /app/start.sh && \
    echo 'export NETWORK_INTERFACE=$INTERFACE' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Ensure directories exist and have correct permissions' >> /app/start.sh && \
    echo 'mkdir -p /app/storage/logs /app/storage/framework/cache /app/storage/framework/sessions /app/storage/framework/views /app/bootstrap/cache' >> /app/start.sh && \
    echo 'chown -R appuser:appuser /app/storage /app/bootstrap/cache 2>/dev/null || true' >> /app/start.sh && \
    echo 'chmod -R 755 /app/storage /app/bootstrap/cache 2>/dev/null || true' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Start services with supervisor' >> /app/start.sh && \
    echo 'echo "Starting services..."' >> /app/start.sh && \
    echo 'exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf' >> /app/start.sh && \
    chmod +x /app/start.sh

# Create health check script
RUN echo '#!/bin/bash' > /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo '# Check if services are running' >> /app/health-check.sh && \
    echo 'if ! pgrep -f "php-fpm" > /dev/null; then' >> /app/health-check.sh && \
    echo '    echo "PHP-FPM is not running"' >> /app/health-check.sh && \
    echo '    exit 1' >> /app/health-check.sh && \
    echo 'fi' >> /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo 'if ! pgrep -f "nginx" > /dev/null; then' >> /app/health-check.sh && \
    echo '    echo "Nginx is not running"' >> /app/health-check.sh && \
    echo '    exit 1' >> /app/health-check.sh && \
    echo 'fi' >> /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo '# Check API endpoint' >> /app/health-check.sh && \
    echo 'if ! curl -f -s http://127.0.0.1:8080/api/health-check > /dev/null; then' >> /app/health-check.sh && \
    echo '    echo "API health check failed"' >> /app/health-check.sh && \
    echo '    exit 1' >> /app/health-check.sh && \
    echo 'fi' >> /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo 'echo "All services are healthy"' >> /app/health-check.sh && \
    echo 'exit 0' >> /app/health-check.sh && \
    chmod +x /app/health-check.sh

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

# Create log directory and set permissions
RUN mkdir -p /var/log/network-security \
    && chown -R appuser:appuser /var/log/network-security \
    && chmod -R 755 /var/log/network-security

# Expose ports
EXPOSE 8080 9000

# Set up volume for persistent data
VOLUME ["/app/storage"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

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
LABEL maintainer="Hirotoshi Uchida <contact.hirotoshiuchida@gmail.com>"
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
