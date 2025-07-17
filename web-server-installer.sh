#!/bin/bash

# Laravel 11 Stack Installation Script for AlmaLinux 9
# PHP 8.2 + MySQL 8.0 + Redis + Nginx + Composer + Node.js + phpMyAdmin
# Author: Full-Stack Developer (@moaazhomaid)
# Version: 2.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration variables
DEFAULT_PKG_MANAGER="dnf"
DEFAULT_DB_ROOT_PASSWORD="SecureRootPass123!"
DEFAULT_DB_NAME="laravel_db"
DEFAULT_DB_USER="laravel_user"
DEFAULT_DB_PASSWORD="LaravelPass123!"
DEFAULT_REDIS_PASSWORD="RedisPass123!"
DEFAULT_DOMAIN="laravel.local"
DEFAULT_LARAVEL_PATH="/var/www/laravel"
DEFAULT_PHPMYADMIN_PORT="8888"
DEFAULT_TIMEZONE="UTC"

# User configuration variables (will be set by user input)
PKG_MANAGER=""
DB_ROOT_PASSWORD=""
DB_NAME=""
DB_USER=""
DB_PASSWORD=""
REDIS_PASSWORD=""
DOMAIN=""
LARAVEL_PATH=""
PHPMYADMIN_PORT=""
TIMEZONE=""

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

print_question() {
    echo -e "${CYAN}[QUESTION]${NC} $1"
}

# Function to get user input with timeout and default value
get_input_with_timeout() {
    local prompt="$1"
    local default="$2"
    local timeout="$3"
    local result=""
    
    print_question "${prompt}"
    echo -e "${YELLOW}Default: ${default} ${NC}(Auto-select in ${timeout}s if no input)"
    
    if read -t ${timeout} -p "Enter value: " result; then
        if [[ -z "$result" ]]; then
            result="$default"
            echo -e "${GREEN}Using default: ${result}${NC}"
        fi
    else
        echo -e "\n${YELLOW}Timeout reached. Using default: ${default}${NC}"
        result="$default"
    fi
    
    echo "$result"
}

# Function to get package manager selection
select_package_manager() {
    print_header "Package Manager Selection"
    
    echo "Select package manager for your system:"
    echo "1) dnf (Default - for RHEL/CentOS/AlmaLinux/Rocky)"
    echo "2) yum (Legacy - for older RHEL/CentOS)"
    echo "3) apt (for Debian/Ubuntu - will exit as this script is for AlmaLinux)"
    
    local choice=$(get_input_with_timeout "Choose package manager (1-3)" "1" 5)
    
    case $choice in
        1|"")
            PKG_MANAGER="dnf"
            print_status "Selected: dnf (recommended for AlmaLinux 9)"
            ;;
        2)
            PKG_MANAGER="yum"
            print_status "Selected: yum (legacy)"
            ;;
        3)
            print_error "This script is specifically designed for AlmaLinux 9. For Debian/Ubuntu, please use a different script."
            exit 1
            ;;
        *)
            print_warning "Invalid selection. Using default: dnf"
            PKG_MANAGER="dnf"
            ;;
    esac
}

# Function to collect user configuration
collect_user_config() {
    print_header "Configuration Setup"
    print_status "Please provide configuration details or press Enter for defaults"
    echo ""
    
    # Database configuration
    print_header "Database Configuration"
    DB_ROOT_PASSWORD=$(get_input_with_timeout "MySQL root password" "$DEFAULT_DB_ROOT_PASSWORD" 5)
    DB_NAME=$(get_input_with_timeout "Laravel database name" "$DEFAULT_DB_NAME" 5)
    DB_USER=$(get_input_with_timeout "Laravel database username" "$DEFAULT_DB_USER" 5)
    DB_PASSWORD=$(get_input_with_timeout "Laravel database password" "$DEFAULT_DB_PASSWORD" 5)
    
    # Redis configuration
    print_header "Redis Configuration"
    REDIS_PASSWORD=$(get_input_with_timeout "Redis password" "$DEFAULT_REDIS_PASSWORD" 5)
    
    # Web server configuration
    print_header "Web Server Configuration"
    DOMAIN=$(get_input_with_timeout "Domain name for Laravel site" "$DEFAULT_DOMAIN" 5)
    LARAVEL_PATH=$(get_input_with_timeout "Laravel installation path" "$DEFAULT_LARAVEL_PATH" 5)
    
    # phpMyAdmin configuration
    print_header "phpMyAdmin Configuration"
    PHPMYADMIN_PORT=$(get_input_with_timeout "phpMyAdmin port" "$DEFAULT_PHPMYADMIN_PORT" 5)
    
    # System configuration
    print_header "System Configuration"
    TIMEZONE=$(get_input_with_timeout "System timezone" "$DEFAULT_TIMEZONE" 5)
    
    # Display configuration summary
    display_config_summary
}

# Function to display configuration summary
display_config_summary() {
    print_header "Configuration Summary"
    echo -e "${YELLOW}Package Manager:${NC} $PKG_MANAGER"
    echo -e "${YELLOW}MySQL Root Password:${NC} $DB_ROOT_PASSWORD"
    echo -e "${YELLOW}Database Name:${NC} $DB_NAME"
    echo -e "${YELLOW}Database User:${NC} $DB_USER"
    echo -e "${YELLOW}Database Password:${NC} $DB_PASSWORD"
    echo -e "${YELLOW}Redis Password:${NC} $REDIS_PASSWORD"
    echo -e "${YELLOW}Domain:${NC} $DOMAIN"
    echo -e "${YELLOW}Laravel Path:${NC} $LARAVEL_PATH"
    echo -e "${YELLOW}phpMyAdmin Port:${NC} $PHPMYADMIN_PORT"
    echo -e "${YELLOW}Timezone:${NC} $TIMEZONE"
    echo ""
    
    local confirm=$(get_input_with_timeout "Proceed with this configuration? (y/n)" "y" 10)
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_error "Installation cancelled by user"
        exit 1
    fi
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
    sudo $PKG_MANAGER update -y
    sudo $PKG_MANAGER install -y epel-release
    sudo $PKG_MANAGER install -y ${PKG_MANAGER}-utils curl wget unzip git vim nano htop tree
    print_status "System updated successfully"
}

# Function to set system timezone
set_timezone() {
    print_header "Setting System Timezone"
    sudo timedatectl set-timezone $TIMEZONE
    print_status "Timezone set to: $TIMEZONE"
}

# Function to install and configure repositories
setup_repositories() {
    print_header "Setting up Repositories"
    
    # Install Remi repository for PHP 8.2
    sudo $PKG_MANAGER install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
    
    # Enable PowerTools repository
    sudo $PKG_MANAGER config-manager --set-enabled crb
    
    # Enable Remi PHP 8.2 repository
    sudo $PKG_MANAGER module reset php -y
    sudo $PKG_MANAGER module enable php:remi-8.2 -y
    
    print_status "Repositories configured successfully"
}

# Function to install PHP 8.2 and extensions
install_php() {
    print_header "Installing PHP 8.2 and Extensions"
    
    # Install PHP 8.2 with all required extensions for Laravel 11
    sudo $PKG_MANAGER install -y \
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
date.timezone = $TIMEZONE

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

; File uploads
file_uploads = On
max_file_uploads = 20
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
    sudo $PKG_MANAGER install -y mysql-server mysql
    
    # Start and enable MySQL
    sudo systemctl start mysqld
    sudo systemctl enable mysqld
    
    # Configure MySQL
    configure_mysql
    
    print_status "MySQL 8.0 installed and configured successfully"
}

# Function to configure MySQL root user properly
configure_mysql() {
    print_status "Configuring MySQL"
    
    # Check if MySQL has a temporary root password
    TEMP_PASSWORD=$(sudo grep 'temporary password' /var/log/mysqld.log 2>/dev/null | tail -1 | awk '{print $NF}' || echo "")
    
    if [[ -n "$TEMP_PASSWORD" ]]; then
        print_status "Found temporary MySQL root password, configuring..."
        
        # Change root password using temporary password
        mysql -u root -p"$TEMP_PASSWORD" --connect-expired-password -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';" 2>/dev/null || {
            # If temporary password doesn't work, try without password
            mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';" 2>/dev/null || {
                print_warning "Could not set root password automatically. Setting up MySQL without password first..."
                sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';"
            }
        }
    else
        # No temporary password, try to set root password directly
        mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';" 2>/dev/null || {
            sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';"
        }
    fi
    
    # Secure MySQL installation
    mysql -u root -p${DB_ROOT_PASSWORD} -e "DELETE FROM mysql.user WHERE User='';"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "DROP DATABASE IF EXISTS test;"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "FLUSH PRIVILEGES;"
    
    # Create Laravel database and user
    mysql -u root -p${DB_ROOT_PASSWORD} -e "CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
    mysql -u root -p${DB_ROOT_PASSWORD} -e "FLUSH PRIVILEGES;"
    
    # Configure MySQL settings
    sudo tee /etc/mysql/conf.d/laravel.cnf > /dev/null <<EOF
[mysqld]
# Laravel optimized settings
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
query_cache_type = 1
query_cache_size = 64M
max_connections = 200
max_allowed_packet = 64M
tmp_table_size = 64M
max_heap_table_size = 64M

# Character set settings
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
EOF
    
    # Restart MySQL to apply configuration
    sudo systemctl restart mysqld
    
    print_status "MySQL configured with database: ${DB_NAME}, user: ${DB_USER}"
}

# Function to install phpMyAdmin
install_phpmyadmin() {
    print_header "Installing phpMyAdmin"
    
    # Download latest phpMyAdmin
    cd /tmp
    PHPMYADMIN_VERSION=$(curl -s https://api.github.com/repos/phpmyadmin/phpmyadmin/releases/latest | grep '"tag_name"' | cut -d '"' -f 4)
    print_status "Downloading phpMyAdmin version: $PHPMYADMIN_VERSION"
    
    wget "https://files.phpmyadmin.net/phpMyAdmin/${PHPMYADMIN_VERSION}/phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages.tar.gz"
    
    # Extract and install
    sudo mkdir -p /var/www/phpmyadmin
    tar -xzf "phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages.tar.gz"
    sudo mv "phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages"/* /var/www/phpmyadmin/
    
    # Set permissions
    sudo chown -R nginx:nginx /var/www/phpmyadmin
    sudo chmod -R 755 /var/www/phpmyadmin
    
    # Configure phpMyAdmin
    configure_phpmyadmin
    
    # Clean up
    rm -rf /tmp/phpMyAdmin-*
    
    print_status "phpMyAdmin installed successfully"
}

# Function to configure phpMyAdmin
configure_phpmyadmin() {
    print_status "Configuring phpMyAdmin"
    
    # Create phpMyAdmin configuration
    sudo tee /var/www/phpmyadmin/config.inc.php > /dev/null <<EOF
<?php
/**
 * phpMyAdmin configuration file
 */

// Generate a random secret
\$cfg['blowfish_secret'] = '$(openssl rand -base64 32)';

// Server configuration
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;

// Directories for saving/loading files from server
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';

// Security settings
\$cfg['ForceSSL'] = false;
\$cfg['CheckConfigurationPermissions'] = false;
\$cfg['DefaultLang'] = 'en';
\$cfg['ServerDefault'] = 1;
\$cfg['VersionCheck'] = false;

// Theme
\$cfg['ThemeDefault'] = 'pmahomme';

// Session settings
\$cfg['LoginCookieValidity'] = 3600;
\$cfg['LoginCookieStore'] = 0;
\$cfg['LoginCookieDeleteAll'] = true;

// Memory and time limits
\$cfg['MemoryLimit'] = '256M';
\$cfg['ExecTimeLimit'] = 300;

// Import/Export settings
\$cfg['MaxSizeForInputField'] = 50000;
\$cfg['MinSizeForInputField'] = 4;
\$cfg['TextareaRows'] = 15;
\$cfg['TextareaCols'] = 40;
\$cfg['LongtextDoubleTextarea'] = true;
\$cfg['TextareaAutoSelect'] = false;

// Navigation settings
\$cfg['MaxNavigationItems'] = 50;
\$cfg['NavigationTreeEnableGrouping'] = true;
\$cfg['NavigationTreeDbSeparator'] = '_';
\$cfg['NavigationTreeTableSeparator'] = '__';
\$cfg['NavigationTreeTableLevel'] = 1;

// SQL query settings
\$cfg['SQLQuery']['Edit'] = true;
\$cfg['SQLQuery']['Explain'] = true;
\$cfg['SQLQuery']['ShowAsPHP'] = true;
\$cfg['SQLQuery']['Validate'] = false;
\$cfg['SQLQuery']['Refresh'] = true;

// Browse settings
\$cfg['MaxRows'] = 25;
\$cfg['Order'] = 'ASC';
\$cfg['DisplayServersList'] = false;
\$cfg['DisplayDatabasesList'] = true;
\$cfg['DefaultDisplay'] = 'horizontal';
\$cfg['RepeatCells'] = 100;

// Editing settings
\$cfg['ProtectBinary'] = 'blob';
\$cfg['ShowFunctionFields'] = true;
\$cfg['ShowFieldTypesInDataEditView'] = true;
\$cfg['InsertRows'] = 2;
\$cfg['ForeignKeyDropdownOrder'] = 'content-id';
\$cfg['ForeignKeyMaxLimit'] = 100;

// Export settings
\$cfg['Export']['lock_tables'] = false;
\$cfg['Export']['asfile'] = true;
\$cfg['Export']['compression'] = 'none';
\$cfg['Export']['onserver'] = false;
\$cfg['Export']['onserver_overwrite'] = false;
\$cfg['Export']['remember_file_template'] = true;

// Import settings
\$cfg['Import']['allow_interrupt'] = true;
\$cfg['Import']['skip_queries'] = 0;
\$cfg['Import']['sql_compatibility'] = 'NONE';
\$cfg['Import']['ldi_replace'] = false;
\$cfg['Import']['ldi_ignore'] = false;
\$cfg['Import']['ldi_terminated'] = ';';
\$cfg['Import']['ldi_enclosed'] = '"';
\$cfg['Import']['ldi_escaped'] = '\\\\';
\$cfg['Import']['ldi_local_option'] = false;

// Security
\$cfg['CaptchaLoginPublicKey'] = '';
\$cfg['CaptchaLoginPrivateKey'] = '';
\$cfg['reCaptchaV2SiteKey'] = '';
\$cfg['reCaptchaV2SecretKey'] = '';

// Console settings
\$cfg['Console']['StartHistory'] = false;
\$cfg['Console']['AlwaysExpand'] = false;
\$cfg['Console']['CurrentQuery'] = true;
\$cfg['Console']['EnterExecutes'] = false;
\$cfg['Console']['DarkTheme'] = false;
\$cfg['Console']['Mode'] = 'show';
\$cfg['Console']['Height'] = 92;
\$cfg['Console']['GroupQueries'] = false;
\$cfg['Console']['OrderBy'] = 'exec';
\$cfg['Console']['Order'] = 'asc';

?>
EOF

    # Create Nginx configuration for phpMyAdmin
    sudo tee /etc/nginx/conf.d/phpmyadmin.conf > /dev/null <<EOF
server {
    listen ${PHPMYADMIN_PORT};
    server_name localhost;
    root /var/www/phpmyadmin;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    index index.php index.html index.htm;

    charset utf-8;

    # Disable access to setup and other sensitive directories
    location ~ ^/(setup|examples|test)/ {
        deny all;
    }

    # Deny access to configuration files
    location ~ /\\.ht {
        deny all;
    }

    location ~ /config\\.inc\\.php {
        deny all;
    }

    # Main location block
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    # Handle .php files
    location ~ \\.php\$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_intercept_errors on;
        fastcgi_ignore_client_abort off;
        fastcgi_connect_timeout 60;
        fastcgi_send_timeout 180;
        fastcgi_read_timeout 180;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;
    }

    # Favicon and robots
    location = /favicon.ico { 
        access_log off; 
        log_not_found off; 
    }
    location = /robots.txt  { 
        access_log off; 
        log_not_found off; 
    }

    # Static files caching
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/javascript
        application/xml+rss
        application/json;
}
EOF

    # Create tmp directory for phpMyAdmin
    sudo mkdir -p /var/www/phpmyadmin/tmp
    sudo chown nginx:nginx /var/www/phpmyadmin/tmp
    sudo chmod 755 /var/www/phpmyadmin/tmp
    
    print_status "phpMyAdmin configured on port ${PHPMYADMIN_PORT}"
}

# Function to install Redis
install_redis() {
    print_header "Installing Redis"
    
    # Install Redis
    sudo $PKG_MANAGER install -y redis
    
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
    
    # Performance tuning
    echo "tcp-keepalive 300" | sudo tee -a /etc/redis/redis.conf
    echo "timeout 0" | sudo tee -a /etc/redis/redis.conf
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
    
    # Configure Composer globally
    composer global require laravel/installer
    
    print_status "Composer installed successfully"
}

# Function to install Node.js and npm
install_nodejs() {
    print_header "Installing Node.js and npm"
    
    # Install Node.js LTS from NodeSource repository
    curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
    sudo $PKG_MANAGER install -y nodejs
    
    # Install additional development tools
    sudo npm install -g yarn pm2 nodemon
    
    # Verify installation
    node --version
    npm --version
    yarn --version
    
    print_status "Node.js and npm installed successfully"
}

# Function to install and configure Nginx
install_nginx() {
    print_header "Installing Nginx"
    
    # Install Nginx
    sudo $PKG_MANAGER install -y nginx
    
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
    
    # Backup original configuration
    sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Create optimized nginx.conf
    sudo tee /etc/nginx/nginx.conf > /dev/null <<EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/javascript
        application/atom+xml
        application/rss+xml
        application/xhtml+xml
        application/xml
        application/json
        image/svg+xml;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone \$binary_remote_addr zone=global:10m rate=100r/s;

    # Include additional configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Create Laravel site configuration
    sudo tee /etc/nginx/conf.d/${DOMAIN}.conf > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    root ${LARAVEL_PATH}/public;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    index index.php index.html index.htm;

    charset utf-8;

    # Rate limiting
    limit_req zone=global burst=20 nodelay;

    # Main location block
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    # Handle .php files
    location ~ \\.php\$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
        
        # PHP-FPM optimizations
        fastcgi_connect_timeout 60s;
        fastcgi_send_timeout 60s;
        fastcgi_read_timeout 60s;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
    }

    # Static files caching
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Security
    location = /favicon.ico { 
        access_log off; 
        log_not_found off; 
    }
    
    location = /robots.txt  { 
        access_log off; 
        log_not_found off; 
    }

    location ~ /\\.(?!well-known).* {
        deny all;
    }

    # Laravel specific
    location ~ /\\.env {
        deny all;
    }

    location ~ /storage/.* {
        deny all;
    }

    location ~ /bootstrap/cache/.* {
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
    
    # Allow Nginx to listen on custom ports
    sudo semanage port -a -t http_port_t -p tcp ${PHPMYADMIN_PORT} 2>/dev/null || sudo semanage port -m -t http_port_t -p tcp ${PHPMYADMIN_PORT}
    
    # Set SELinux context for Laravel directories
    if [ -d "${LARAVEL_PATH}" ]; then
        sudo semanage fcontext -a -t httpd_exec_t "${LARAVEL_PATH}/public(/.*)?" 2>/dev/null || true
        sudo semanage fcontext -a -t httpd_exec_t "${LARAVEL_PATH}/storage(/.*)?" 2>/dev/null || true
        sudo semanage fcontext -a -t httpd_exec_t "${LARAVEL_PATH}/bootstrap/cache(/.*)?" 2>/dev/null || true
        sudo restorecon -R ${LARAVEL_PATH} 2>/dev/null || true
    fi
    
    # Set SELinux context for phpMyAdmin
    sudo semanage fcontext -a -t httpd_exec_t "/var/www/phpmyadmin(/.*)?" 2>/dev/null || true
    sudo restorecon -R /var/www/phpmyadmin 2>/dev/null || true
    
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
    
    # Allow custom phpMyAdmin port
    sudo firewall-cmd --permanent --add-port=${PHPMYADMIN_PORT}/tcp
    
    # Allow MySQL (commented out for security - enable if needed)
    # sudo firewall-cmd --permanent --add-port=3306/tcp
    
    # Allow Redis (commented out for security - enable if needed)
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
    sudo sed -i "s/APP_NAME=Laravel/APP_NAME=\"Laravel App\"/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/APP_ENV=local/APP_ENV=production/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/APP_DEBUG=true/APP_DEBUG=false/" ${LARAVEL_PATH}/.env
    sudo sed -i "s|APP_URL=http://localhost|APP_URL=http://${DOMAIN}|" ${LARAVEL_PATH}/.env
    sudo sed -i "s/APP_TIMEZONE=UTC/APP_TIMEZONE=${TIMEZONE}/" ${LARAVEL_PATH}/.env
    
    # Database configuration
    sudo sed -i "s/DB_CONNECTION=sqlite/DB_CONNECTION=mysql/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_HOST=127.0.0.1/DB_HOST=127.0.0.1/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_PORT=3306/DB_PORT=3306/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_DATABASE=laravel/DB_DATABASE=${DB_NAME}/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_USERNAME=root/DB_USERNAME=${DB_USER}/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/DB_PASSWORD=/DB_PASSWORD=${DB_PASSWORD}/" ${LARAVEL_PATH}/.env
    
    # Redis configuration
    sudo sed -i "s/REDIS_HOST=127.0.0.1/REDIS_HOST=127.0.0.1/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/REDIS_PASSWORD=null/REDIS_PASSWORD=${REDIS_PASSWORD}/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/REDIS_PORT=6379/REDIS_PORT=6379/" ${LARAVEL_PATH}/.env
    
    # Cache and Session configuration
    sudo sed -i "s/CACHE_STORE=database/CACHE_STORE=redis/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/SESSION_DRIVER=database/SESSION_DRIVER=redis/" ${LARAVEL_PATH}/.env
    sudo sed -i "s/QUEUE_CONNECTION=database/QUEUE_CONNECTION=redis/" ${LARAVEL_PATH}/.env
    
    # Run migrations
    cd ${LARAVEL_PATH}
    sudo -u nginx php artisan migrate --force
    sudo -u nginx php artisan config:cache
    sudo -u nginx php artisan route:cache
    sudo -u nginx php artisan view:cache
    
    print_status "Laravel environment configured successfully"
}

# Function to install additional development tools
install_dev_tools() {
    print_header "Installing Development Tools"
    
    # Install additional PHP tools
    sudo $PKG_MANAGER install -y php-pecl-xhprof
    
    # Install global Composer packages
    sudo -u $USER composer global require friendsofphp/php-cs-fixer
    sudo -u $USER composer global require phpstan/phpstan
    sudo -u $USER composer global require squizlabs/php_codesniffer
    
    # Install global npm packages
    sudo npm install -g @vue/cli create-react-app
    
    print_status "Development tools installed successfully"
}

# Function to create useful scripts
create_scripts() {
    print_header "Creating Utility Scripts"
    
    # Create Laravel artisan wrapper script
    sudo tee /usr/local/bin/laravel-artisan > /dev/null <<EOF
#!/bin/bash
cd ${LARAVEL_PATH}
sudo -u nginx php artisan "\$@"
EOF
    sudo chmod +x /usr/local/bin/laravel-artisan
    
    # Create database backup script
    sudo tee /usr/local/bin/backup-mysql > /dev/null <<EOF
#!/bin/bash
BACKUP_DIR="/backup/mysql"
DATE=\$(date +%Y%m%d_%H%M%S)
sudo mkdir -p \$BACKUP_DIR
mysqldump -u root -p${DB_ROOT_PASSWORD} --all-databases > "\$BACKUP_DIR/all_databases_\$DATE.sql"
echo "MySQL backup completed: \$BACKUP_DIR/all_databases_\$DATE.sql"
EOF
    sudo chmod +x /usr/local/bin/backup-mysql
    
    # Create Laravel deployment script
    sudo tee /usr/local/bin/deploy-laravel > /dev/null <<EOF
#!/bin/bash
cd ${LARAVEL_PATH}
echo "Pulling latest changes..."
git pull origin main 2>/dev/null || echo "No git repository found"
echo "Installing dependencies..."
sudo -u nginx composer install --no-dev --optimize-autoloader
echo "Running migrations..."
sudo -u nginx php artisan migrate --force
echo "Clearing caches..."
sudo -u nginx php artisan config:cache
sudo -u nginx php artisan route:cache
sudo -u nginx php artisan view:cache
sudo -u nginx php artisan queue:restart
echo "Deployment completed!"
EOF
    sudo chmod +x /usr/local/bin/deploy-laravel
    
    print_status "Utility scripts created successfully"
}

# Function to run system verification
verify_installation() {
    print_header "Verifying Installation"
    
    echo "=== System Information ==="
    hostnamectl
    echo ""
    
    echo "=== Package Manager ==="
    echo "Using: $PKG_MANAGER"
    $PKG_MANAGER --version
    echo ""
    
    echo "=== PHP Version ==="
    php -v
    echo ""
    
    echo "=== PHP Extensions ==="
    php -m | grep -E "(redis|mysql|mbstring|xml|curl|json|tokenizer|bcmath|ctype|fileinfo|pdo|gd|zip|opcache)"
    echo ""
    
    echo "=== MySQL Status ==="
    sudo systemctl is-active mysqld
    mysql -u${DB_USER} -p${DB_PASSWORD} -e "SELECT VERSION();" 2>/dev/null
    echo ""
    
    echo "=== Redis Status ==="
    sudo systemctl is-active redis
    redis-cli -a ${REDIS_PASSWORD} ping 2>/dev/null
    echo ""
    
    echo "=== Nginx Status ==="
    sudo systemctl is-active nginx
    nginx -v
    echo ""
    
    echo "=== PHP-FPM Status ==="
    sudo systemctl is-active php-fpm
    echo ""
    
    echo "=== Composer Version ==="
    composer --version
    echo ""
    
    echo "=== Node.js Version ==="
    node --version
    npm --version
    echo ""
    
    echo "=== Laravel Status ==="
    if [ -d "${LARAVEL_PATH}" ]; then
        cd ${LARAVEL_PATH}
        php artisan --version
        php artisan route:list --compact 2>/dev/null | head -10
    fi
    echo ""
    
    echo "=== phpMyAdmin Status ==="
    if [ -d "/var/www/phpmyadmin" ]; then
        echo "phpMyAdmin installed at: http://localhost:${PHPMYADMIN_PORT}"
        curl -s -o /dev/null -w "HTTP Status: %{http_code}" "http://localhost:${PHPMYADMIN_PORT}" || echo "phpMyAdmin not accessible"
    fi
    echo ""
    
    echo "=== Service Status ==="
    sudo systemctl status nginx php-fpm mysqld redis --no-pager -l
    
    print_status "Verification completed"
}

# Function to display final information
display_final_info() {
    print_header "🎉 Installation Complete! 🎉"
    
    echo -e "${GREEN}Your Laravel 11 development environment is ready!${NC}"
    echo ""
    
    echo -e "${CYAN}=== Access Information ===${NC}"
    echo -e "${YELLOW}Laravel Application:${NC}"
    echo "  🌐 URL: http://${DOMAIN}"
    echo "  📁 Path: ${LARAVEL_PATH}"
    echo "  💡 Add '127.0.0.1 ${DOMAIN}' to your /etc/hosts file"
    echo ""
    
    echo -e "${YELLOW}phpMyAdmin:${NC}"
    echo "  🌐 URL: http://localhost:${PHPMYADMIN_PORT}"
    echo "  👤 Username: root"
    echo "  🔑 Password: ${DB_ROOT_PASSWORD}"
    echo ""
    
    echo -e "${CYAN}=== Database Information ===${NC}"
    echo -e "${YELLOW}MySQL:${NC}"
    echo "  🏠 Host: localhost"
    echo "  🗄️  Database: ${DB_NAME}"
    echo "  👤 Username: ${DB_USER}"
    echo "  🔑 Password: ${DB_PASSWORD}"
    echo "  🔐 Root Password: ${DB_ROOT_PASSWORD}"
    echo ""
    
    echo -e "${YELLOW}Redis:${NC}"
    echo "  🏠 Host: 127.0.0.1"
    echo "  🚪 Port: 6379"
    echo "  🔑 Password: ${REDIS_PASSWORD}"
    echo ""
    
    echo -e "${CYAN}=== System Information ===${NC}"
    echo -e "${YELLOW}Package Manager:${NC} $PKG_MANAGER"
    echo -e "${YELLOW}Timezone:${NC} $TIMEZONE"
    echo -e "${YELLOW}PHP Version:${NC} $(php -r 'echo PHP_VERSION;')"
    echo -e "${YELLOW}Laravel Version:${NC} $(cd ${LARAVEL_PATH} && php artisan --version 2>/dev/null | cut -d' ' -f3 || echo 'N/A')"
    echo ""
    
    echo -e "${CYAN}=== Useful Commands ===${NC}"
    echo -e "${YELLOW}Laravel:${NC}"
    echo "  🚀 Start dev server: cd ${LARAVEL_PATH} && php artisan serve"
    echo "  🎨 Laravel commands: laravel-artisan [command]"
    echo "  🚀 Deploy changes: deploy-laravel"
    echo ""
    
    echo -e "${YELLOW}Services:${NC}"
    echo "  📊 Check status: sudo systemctl status nginx php-fpm mysqld redis"
    echo "  🔄 Restart services: sudo systemctl restart nginx php-fpm"
    echo ""
    
    echo -e "${YELLOW}Database:${NC}"
    echo "  🗄️  MySQL access: mysql -u${DB_USER} -p${DB_PASSWORD} ${DB_NAME}"
    echo "  🗄️  Root access: mysql -uroot -p${DB_ROOT_PASSWORD}"
    echo "  💾 Backup: backup-mysql"
    echo ""
    
    echo -e "${YELLOW}Redis:${NC}"
    echo "  🔴 Redis CLI: redis-cli -a ${REDIS_PASSWORD}"
    echo ""
    
    echo -e "${YELLOW}Logs:${NC}"
    echo "  📊 Nginx: sudo tail -f /var/log/nginx/error.log"
    echo "  📊 PHP-FPM: sudo tail -f /var/log/php-fpm/www-error.log"
    echo "  📊 MySQL: sudo tail -f /var/log/mysqld.log"
    echo ""
    
    echo -e "${CYAN}=== Next Steps ===${NC}"
    echo "1. 📝 Add '127.0.0.1 ${DOMAIN}' to your /etc/hosts file"
    echo "2. 🌐 Visit http://${DOMAIN} to see your Laravel application"
    echo "3. 🗄️  Access phpMyAdmin at http://localhost:${PHPMYADMIN_PORT}"
    echo "4. 📖 Read Laravel documentation: https://laravel.com/docs"
    echo "5. 🔧 Customize your application in ${LARAVEL_PATH}"
    echo ""
    
    echo -e "${YELLOW}📁 Important Files:${NC}"
    echo "  Laravel env: ${LARAVEL_PATH}/.env"
    echo "  Nginx config: /etc/nginx/conf.d/${DOMAIN}.conf"
    echo "  PHP config: /etc/php.d/99-laravel.ini"
    echo "  MySQL config: /etc/mysql/conf.d/laravel.cnf"
    echo ""
    
    echo -e "${GREEN}📋 Installation log saved to: /tmp/laravel_install_$(date +%Y%m%d_%H%M%S).log${NC}"
    echo ""
    
    echo -e "${BLUE}🎯 Happy coding with Laravel 11! 🎯${NC}"
}

# Main installation function
main() {
    print_header "🚀 Laravel 11 Stack Installation for AlmaLinux 9 🚀"
    print_status "Starting automated installation with user configuration..."
    echo ""
    
    # Pre-installation checks
    check_root
    check_sudo
    
    # User configuration
    select_package_manager
    collect_user_config
    
    # Create log file with timestamp
    LOG_FILE="/tmp/laravel_install_$(date +%Y%m%d_%H%M%S).log"
    exec > >(tee -a "$LOG_FILE")
    exec 2>&1
    
    print_status "Installation log: $LOG_FILE"
    echo ""
    
    # Installation steps
    update_system
    set_timezone
    setup_repositories
    install_php
    install_mysql
    install_redis
    install_composer
    install_nodejs
    install_nginx
    install_phpmyadmin
    configure_selinux
    configure_firewall
    create_laravel_project
    install_dev_tools
    create_scripts
    verify_installation
    display_final_info
    
    print_status "🎉 Installation completed successfully! 🎉"
}

# Run main function with all arguments
main "$@"
