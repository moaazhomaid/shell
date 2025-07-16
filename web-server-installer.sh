#!/bin/bash

# Laravel 11 Stack Installation Script for AlmaLinux 9
# PHP 8.2 + MySQL 8.0 + Redis + Nginx + Composer + Node.js
# Author: Moaaz Homaid @moaazhomaid
# Version: 1.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
DB_ROOT_PASSWORD="SecureRootPass123!"
DB_NAME="laravel_db"
DB_USER="laravel_user"
DB_PASSWORD="LaravelPass123!"
REDIS_PASSWORD="RedisPass123!"
DOMAIN="laravel.local"
LARAVEL_PATH="/var/www/laravel"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons."
        exit 1
    fi
}

# Function to check if user has sudo privileges
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges. Please run: sudo visudo"
        exit 1
    fi
}

# Function to update system
update_system() {
    print_header "Updating System Packages"
    sudo dnf update -y
    sudo dnf install -y epel-release
    sudo dnf install -y dnf-utils curl wget unzip git vim nano
    print_status "System updated successfully"
}

# Function to install and configure repositories
setup_repositories() {
    print_header "Setting up Repositories"
    
    # Install Remi repository for PHP 8.2
    sudo dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
    
    # Enable PowerTools repository
    sudo dnf config-manager --set-enabled crb
    
    # Enable Remi PHP 8.2 repository
    sudo dnf module reset php -y
    sudo dnf module enable php:remi-8.2 -y
    
    print_status "Repositories configured successfully"
}

# Function to install PHP 8.2 and extensions
install_php() {
    print_header "Installing PHP 8.2 and Extensions"
    
    # Install PHP 8.2 with all required extensions for Laravel 11
    sudo dnf install -y \
        php \
        php-cli \
        php-fpm \
        php-common \
        php-mysqlnd \
        php-pdo \
        php-gd \
        php-mbstring \
        php-curl \
        php-xml \
        php-bcmath \
        php-json \
        php-tokenizer \
        php-fileinfo \
        php-ctype \
        php-dom \
        php-intl \
        php-soap \
        php-xmlrpc \
        php-xsl \
        php-opcache \
        php-readline \
        php-zip \
        php-process \
        php-pecl-redis \
        php-pecl-memcached \
        php-sqlite3 \
        php-ldap \
        php-imap \
        php-pecl-imagick \
        php-devel \
        php-pecl-xdebug
    
    # Configure PHP
    configure_php
    
    # Start and enable PHP-FPM
    sudo systemctl start php-fpm
    sudo systemctl enable php-fpm
    
    print_status "PHP 8.2 installed and configured successfully"
}

# Function to configure PHP settings
configure_php() {
    print_status "Configuring PHP settings"
    
    # Backup original php.ini
    sudo cp /etc/php.ini /etc/php.ini.backup
    
    # Configure PHP settings for Laravel
    sudo tee /etc/php.d/99-laravel.ini > /dev/null <<EOF
; Laravel optimized PHP configuration
memory_limit = 256M
upload_max_filesize = 64M
post_max_size = 64M
max_execution_time = 300
max_input_vars = 3000
max_input_time = 300
date.timezone = UTC

; OPcache settings
opcache.enable = 1
opcache.enable_cli = 1
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 8
opcache.max_accelerated_files = 4000
opcache.revalidate_freq = 2
opcache.fast_shutdown = 1
opcache.validate_timestamps = 1

; Session settings
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1

; Security settings
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
EOF

    # Configure PHP-FPM
    sudo cp /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf.backup
    
    # Update PHP-FPM pool configuration
    sudo sed -i 's/user = apache/user = nginx/g' /etc/php-fpm.d/www.conf
    sudo sed -i 's/group = apache/group = nginx/g' /etc/php-fpm.d/www.conf
    sudo sed -i 's/listen.owner = nobody/listen.owner = nginx/g' /etc/php-fpm.d/www.conf
    sudo sed -i 's/listen.group = nobody/listen.group = nginx/g' /etc/php-fpm.d/www.conf
    
    # Restart PHP-FPM
    sudo systemctl restart php-fpm
}

# Function to install MySQL 8.0
install_mysql() {
    print_header "Installing MySQL 8.0"
    
    # Install MySQL server
    sudo dnf install -y mysql-server mysql
    
    # Start and enable MySQL
    sudo systemctl start mysqld
    sudo systemctl enable mysqld
    
    # Configure MySQL
    configure_mysql
    
    print_status "MySQL 8.0 installed and configured successfully"
}

# Function to configure MySQL
configure_mysql() {
    print_status "Configuring MySQL"
    
    # Set root password and secure installation
    sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_ROOT_PASSWORD}';"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "DELETE FROM mysql.user WHERE User='';"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "DROP DATABASE IF EXISTS test;"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "FLUSH PRIVILEGES;"
    
    # Create Laravel database and user
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
    sudo mysql -u root -p${DB_ROOT_PASSWORD} -e "FLUSH PRIVILEGES;"
    
    print_status "MySQL configured with database: ${DB_NAME}, user: ${DB_USER}"
}

# Function to install Redis
install_redis() {
    print_header "Installing Redis"
    
    # Install Redis
    sudo dnf install -y redis
    
    # Configure Redis
    configure_redis
    
    # Start and enable Redis
    sudo systemctl start redis
    sudo systemctl enable redis
    
    print_status "Redis installed and configured successfully"
}

# Function to configure Redis
configure_redis() {
    print_status "Configuring Redis"
    
    # Backup original configuration
    sudo cp /etc/redis/redis.conf /etc/redis/redis.conf.backup
    
    # Configure Redis settings
    sudo sed -i "s/# requirepass foobared/requirepass ${REDIS_PASSWORD}/" /etc/redis/redis.conf
    sudo sed -i "s/# maxmemory <bytes>/maxmemory 256mb/" /etc/redis/redis.conf
    sudo sed -i "s/# maxmemory-policy noeviction/maxmemory-policy allkeys-lru/" /etc/redis/redis.conf
    
    # Enable persistence
    sudo sed -i "s/save 900 1/save 900 1/" /etc/redis/redis.conf
    sudo sed -i "s/save 300 10/save 300 10/" /etc/redis/redis.conf
    sudo sed -i "s/save 60 10000/save 60 10000/" /etc/redis/redis.conf
    
    # Security settings
    sudo sed -i "s/bind 127.0.0.1/bind 127.0.0.1/" /etc/redis/redis.conf
    sudo sed -i "s/protected-mode yes/protected-mode yes/" /etc/redis/redis.conf
}

# Function to install Composer
install_composer() {
    print_header "Installing Composer"
    
    # Download and install Composer
    curl -sS https://getcomposer.org/installer | php
    sudo mv composer.phar /usr/local/bin/composer
    sudo chmod +x /usr/local/bin/composer
    
    # Verify installation
    composer --version
    
    print_status "Composer installed successfully"
}

# Function to install Node.js and npm
install_nodejs() {
    print_header "Installing Node.js and npm"
    
    # Install Node.js LTS from NodeSource repository
    curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
    sudo dnf install -y nodejs
    
    # Verify installation
    node --version
    npm --version
    
    print_status "Node.js and npm installed successfully"
}

# Function to install and configure Nginx
install_nginx() {
    print_header "Installing Nginx"
    
    # Install Nginx
    sudo dnf install -y nginx
    
    # Configure Nginx for Laravel
    configure_nginx
    
    # Start and enable Nginx
    sudo systemctl start nginx
    sudo systemctl enable nginx
    
    print_status "Nginx installed and configured successfully"
}

# Function to configure Nginx
configure_nginx() {
    print_status "Configuring Nginx for Laravel"
    
    # Create Laravel site configuration
    sudo tee /etc/nginx/conf.d/${DOMAIN}.conf > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    root ${LARAVEL_PATH}/public;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";

    index index.php index.html index.htm;

    charset utf-8;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }

    error_page 404 /index.php;

    location ~ \.php\$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOF

    # Test Nginx configuration
    sudo nginx -t
}

# Function to configure SELinux
configure_selinux() {
    print_header "Configuring SELinux"
    
    # Set SELinux booleans for web server
    sudo setsebool -P httpd_can_network_connect 1
    sudo setsebool -P httpd_can_network_connect_db 1
    sudo setsebool -P httpd_can_network_relay 1
    sudo setsebool -P httpd_can_sendmail 1
    sudo setsebool -P httpd_execmem 1
    sudo setsebool -P httpd_unified 1
    
    # Set SELinux context for Laravel directories
    if [ -d "${LARAVEL_PATH}" ]; then
        sudo semanage fcontext -a -t httpd_exec_t "${LARAVEL_PATH}/public(/.*)?"
        sudo semanage fcontext -a -t httpd_exec_t "${LARAVEL_PATH}/storage(/.*)?"
        sudo semanage fcontext -a -t httpd_exec_t "${LARAVEL_PATH}/bootstrap/cache(/.*)?"
        sudo restorecon -R ${LARAVEL_PATH}
    fi
    
    print_status "SELinux configured for web applications"
}

# Function to configure firewall
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Configure firewalld
    sudo systemctl start firewalld
    sudo systemctl enable firewalld
    
    # Allow HTTP and HTTPS
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --permanent --add-service=ssh
    
    # Allow MySQL (if needed for external connections)
    # sudo firewall-cmd --permanent --add-port=3306/tcp
    
    # Allow Redis (if needed for external connections)
    # sudo firewall-cmd --permanent --add-port=6379/tcp
    
    # Reload firewall
    sudo firewall-cmd --reload
    
    print_status "Firewall configured successfully"
}

# Function to create Laravel project
create_laravel_project() {
    print_header "Creating Laravel 11 Project"
    
    # Create project directory
    sudo mkdir -p ${LARAVEL_PATH}
    sudo chown -R $USER:$USER ${LARAVEL_PATH}
    
    # Create Laravel project
    cd /tmp
    composer create-project laravel/laravel:^11.0 laravel-temp
    
    # Move to target directory
    sudo mv laravel-temp/* ${LARAVEL_PATH}/
    sudo mv laravel-temp/.* ${LARAVEL_PATH}/ 2>/dev/null || true
    rm -rf laravel-temp
    
    # Set proper permissions
    sudo chown -R nginx:nginx ${LARAVEL_PATH}
    sudo chmod -R 755 ${LARAVEL_PATH}
    sudo chmod -R 775 ${LARAVEL_PATH}/storage
    sudo chmod -R 775 ${LARAVEL_PATH}/bootstrap/cache
    
    # Configure environment
    cd ${LARAVEL_PATH}
    sudo -u nginx cp .env.example .env
    sudo -u nginx php artisan key:generate
    
    # Update .env file
    configure_laravel_env
    
    print_status "Laravel 11 project created successfully"
}

# Function to configure Laravel environment
configure_laravel_env() {
    print_status "Configuring Laravel environment"
    
    # Update .env file with database and Redis settings
    sudo sed -i "s/DB_CONNECTION=sqlite/DB_CONNECTION=mysql/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_HOST=127.0.0.1/DB_HOST=127.0.0.1/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_PORT=3306/DB_PORT=3306/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_DATABASE=laravel/DB_DATABASE=${DB_NAME}/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_USERNAME=root/DB_USERNAME=${DB_USER}/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_PASSWORD=/DB_PASSWORD=${DB_PASSWORD}/" ${LARAVEL_PATH}/.env
    
    # Configure Redis
    sudo sed -i "s/REDIS_HOST=127.0.0.1/REDIS_HOST=127.0.0.1/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/REDIS_PASSWORD=null/REDIS_PASSWORD=${REDIS_PASSWORD}/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/REDIS_PORT=6379/REDIS_PORT=6379/" ${LARAVEL_PATH}/.env
    
    # Set application URL
    sudo sed -i "s|APP_URL=http://localhost|APP_URL=http://${DOMAIN}|" ${LARAVEL_PATH}/.env
    
    # Run migrations
    cd ${LARAVEL_PATH}
    sudo -u nginx php artisan migrate --force
    
    print_status "Laravel environment configured successfully"
}

# Function to run system verification
verify_installation() {
    print_header "Verifying Installation"
    
    echo "=== PHP Version ==="
    php -v
    
    echo -e "\n=== PHP Extensions ==="
    php -m | grep -E "(redis|mysql|mbstring|xml|curl|json|tokenizer|bcmath|ctype|fileinfo|pdo|gd|zip)"
    
    echo -e "\n=== MySQL Status ==="
    sudo systemctl is-active mysqld
    mysql -u${DB_USER} -p${DB_PASSWORD} -e "SELECT VERSION();"
    
    echo -e "\n=== Redis Status ==="
    sudo systemctl is-active redis
    redis-cli -a ${REDIS_PASSWORD} ping
    
    echo -e "\n=== Nginx Status ==="
    sudo systemctl is-active nginx
    
    echo -e "\n=== Composer Version ==="
    composer --version
    
    echo -e "\n=== Node.js Version ==="
    node --version
    npm --version
    
    echo -e "\n=== Laravel Status ==="
    if [ -d "${LARAVEL_PATH}" ]; then
        cd ${LARAVEL_PATH}
        php artisan --version
    fi
    
    print_status "Verification completed"
}

# Function to display final information
display_final_info() {
    print_header "Installation Complete!"
    
    echo -e "${GREEN}Your Laravel 11 development environment is ready!${NC}"
    echo ""
    echo -e "${YELLOW}Database Information:${NC}"
    echo "  Database: ${DB_NAME}"
    echo "  Username: ${DB_USER}"
    echo "  Password: ${DB_PASSWORD}"
    echo "  Root Password: ${DB_ROOT_PASSWORD}"
    echo ""
    echo -e "${YELLOW}Redis Information:${NC}"
    echo "  Host: 127.0.0.1"
    echo "  Port: 6379"
    echo "  Password: ${REDIS_PASSWORD}"
    echo ""
    echo -e "${YELLOW}Laravel Project:${NC}"
    echo "  Path: ${LARAVEL_PATH}"
    echo "  URL: http://${DOMAIN}"
    echo "  Add '127.0.0.1 ${DOMAIN}' to your /etc/hosts file"
    echo ""
    echo -e "${YELLOW}Useful Commands:${NC}"
    echo "  Start development server: cd ${LARAVEL_PATH} && php artisan serve"
    echo "  Check logs: sudo tail -f /var/log/nginx/error.log"
    echo "  PHP-FPM status: sudo systemctl status php-fpm"
    echo "  MySQL access: mysql -u${DB_USER} -p${DB_PASSWORD} ${DB_NAME}"
    echo "  Redis access: redis-cli -a ${REDIS_PASSWORD}"
    echo ""
    echo -e "${GREEN}Installation log saved to: /tmp/laravel_install.log${NC}"
}

# Main installation function
main() {
    print_header "Laravel 11 Stack Installation for AlmaLinux 9"
    
    # Pre-installation checks
    check_root
    check_sudo
    
    # Create log file
    exec > >(tee -a /tmp/laravel_install.log)
    exec 2>&1
    
    # Installation steps
    update_system
    setup_repositories
    install_php
    install_mysql
    install_redis
    install_composer
    install_nodejs
    install_nginx
    configure_selinux
    configure_firewall
    create_laravel_project
    verify_installation
    display_final_info
    
    print_status "Installation completed successfully!"
}

# Run main function
main "$@"
