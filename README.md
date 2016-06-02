# EcommStatusTuning
Python to collect daemon and application configuration information

# Information pooled as of June 2, 2016
Information is dynamically discovered, instead of using static names or paths. It is saved to a json file, so it is easy to save the raw information for cross reference.
ecommStackStatus should be run on the web nodes, and it will attempt to connect to other services over the network as needed, such as MySQL, memcache and redis.

nginx & apache
URL, document root, configuration file, log files, and listening ports

php-fpm
Pool information for php-fpm.

Memory profile for nginx, apache and php-fpm. This is most useful for the php process, either mod_php or php-fpm.

Magento queries for each document root
Database configuration, cache configuration for session, objects and full page cache, and whether the cache is enabled in the Magento configuration portal.

For each Magento document root:
MySQL host, port and credential information
Memcache host and port information
Redis host and port information
Magento's MySQL table for cache configuration (enabled or disabled)

Additional memcache and redis information

