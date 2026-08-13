FROM php:8.4-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev \
    && docker-php-ext-install pdo_pgsql \
    && rm -rf /var/lib/apt/lists/*

COPY php.ini /usr/local/etc/php/conf.d/fortressauth.ini
COPY . /var/www/html/

RUN a2enmod rewrite headers \
    && printf '%s\n' \
       'ServerTokens Prod' \
       'ServerSignature Off' \
       '<Directory /var/www/html/public>' \
       '    AllowOverride All' \
       '    Options -Indexes' \
       '    Require all granted' \
       '</Directory>' \
       > /etc/apache2/conf-available/fortressauth-security.conf \
    && a2enconf fortressauth-security \
    && sed -i 's#DocumentRoot /var/www/html#DocumentRoot /var/www/html/public#' /etc/apache2/sites-available/000-default.conf \
    && mkdir -p /var/www/html/data /var/www/html/logs \
    && chown -R www-data:www-data /var/www/html/data /var/www/html/logs \
    && chmod 750 /var/www/html/data /var/www/html/logs

WORKDIR /var/www/html
EXPOSE 80
CMD ["apache2-foreground"]
