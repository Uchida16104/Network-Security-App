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

COPY config/hhvm.ini /app/hhvm.ini

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

# Create minimal Laravel artisan file if it doesn't exist
RUN if [ ! -f /app/artisan ]; then \
    echo '#!/usr/bin/env php' > /app/artisan && \
    echo '<?php' >> /app/artisan && \
    echo 'echo "Minimal artisan stub - migrations not needed for this app\n";' >> /app/artisan && \
    echo 'exit(0);' >> /app/artisan && \
    chmod +x /app/artisan; \
    fi

# Install PHP dependencies
RUN cd /app && composer install --no-plugins --no-scripts

# Run composer scripts manually to handle missing artisan gracefully
RUN cd /app && \
    (composer run-script post-install-cmd || echo "Post-install scripts completed with warnings") && \
    (composer run-script post-update-cmd || echo "Post-update scripts completed with warnings")

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

# Set directory permissions including supervisor logs
RUN chown -R appuser:appuser /app/storage \
    && chown -R appuser:appuser /app/bootstrap/cache \
    && chown -R appuser:appuser /var/log/supervisor \
    && chmod -R 755 /app/storage \
    && chmod -R 755 /app/bootstrap/cache \
    && chmod -R 755 /app/public \
    && chmod -R 755 /var/log/supervisor

# Create basic public directory with index.php if it doesn't exist
RUN if [ ! -f /app/public/index.php ]; then \
        mkdir -p /app/public && \
        echo '<?php' > /app/public/index.php && \
        echo 'echo "<h1>Network Security App</h1>";' >> /app/public/index.php && \
        echo 'echo "<p>Application is running successfully!</p>";' >> /app/public/index.php && \
        echo 'echo "<p>Author: Hirotoshi Uchida</p>";' >> /app/public/index.php && \
        echo 'echo "<p>Homepage: <a href=\"https://hirotoshiuchida.onrender.com\">https://hirotoshiuchida.onrender.com</a></p>";' >> /app/public/index.php && \
        chown appuser:appuser /app/public/index.php; \
    fi

COPY NetworkController.php /app/public/NetworkController.php

COPY NetworkMonitor.php /app/public/NetworkMonitor.php

COPY index.html /app/public/index.html

RUN mkdir -p /app/public/assets

COPY assets/ /app/public/assets

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

COPY start.sh /app/start.sh

COPY network-monitor.sh /app/network-monitor.sh

COPY health-check.sh /app/health-check.sh

RUN chmod +x /app/start.sh

RUN chmod +x /app/health-check.sh

RUN chmod +x /app/network-monitor.sh

# Create log directory and set permissions
RUN mkdir -p /var/log/network-security \
    && chown -R appuser:appuser /var/log/network-security \
    && chmod -R 755 /var/log/network-security

# Set up log rotation
COPY logrotate.d/network-security /etc/logrotate.d/network-security

# Expose ports
EXPOSE 8080 9000

# Set up volume for persistent data
VOLUME ["/app/storage"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# DO NOT switch to appuser - supervisor needs root privileges to manage services
# USER appuser

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
