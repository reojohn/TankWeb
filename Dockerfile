# Use official PHP image with Apache
FROM php:8.2-apache

# Install dependencies for PostgreSQL and PHP extensions
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Copy project files to Apache root
COPY . /var/www/html/

# Set working directory
WORKDIR /var/www/html/

# Expose port (Render uses 10000-10099)
EXPOSE 10000

# Start Apache in foreground
CMD ["apache2-foreground"]
