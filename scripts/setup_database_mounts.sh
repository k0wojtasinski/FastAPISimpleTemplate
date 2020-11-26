#/bin/bash
# This script creates directories to bind containers with database and database_management and sets correct permissions to database data directory

if [ ! -d "database_management/data/" ]; then
    mkdir database_management/data/
fi

if [ ! -d "database/data/" ]; then
    mkdir database/data/
fi

chown -R 5050:5050 database_management/data/