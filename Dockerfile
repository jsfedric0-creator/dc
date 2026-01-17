FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    nginx \
    ffmpeg \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    curl \
    git \
    sqlite3 \
    supervisor && \
    apt-get clean

# Create directories
RUN mkdir -p /var/www/iptv /etc/nginx/sites-enabled /var/log/nginx /var/log/supervisor

# Copy application files
COPY . /app
WORKDIR /app

# Install Python requirements
RUN pip3 install -r requirements.txt

# Copy configuration files
COPY nginx.conf /etc/nginx/
COPY supervisord.conf /etc/supervisor/conf.d/

# Set permissions
RUN chmod +x /app/start.sh

# Expose ports
EXPOSE 80 8080 1935 8000-8100

CMD ["/app/start.sh"]
