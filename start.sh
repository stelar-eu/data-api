#!/bin/sh


# Check if the first argument is 'start-server'
if [ "$1" = 'start-server' ]; then
    # Create MinIO alias
    echo "Configuring MinIO client alias 'myminio'..."
    
    # Validate that the necessary environment variables are set
    if [ -z "$MINIO_DOMAIN" ] || [ -z "$MINIO_ROOT_USER" ] || [ -z "$MINIO_ROOT_PASSWORD" ]; then
        echo "Error: One or more required environment variables (MINIO_DOMAIN, MINIO_ROOT_USER, MINIO_ROOT_PASSWORD) are not set."
        exit 1
    fi

    # Check if the MC_INSECURE environment variable is set to True
    if [ "${MC_INSECURE,,}" = "true" ]; then
        echo "Entering insecure mode for mc"
    elif [ "${MC_INSECURE,,}" = "false" ]; then
        echo "Operating in secure mode for mc"
    else
        echo "Invalid value for MC_INSECURE. Please set it to true or false."
        exit 1
    fi
    
    
    mc alias set myminio $MINIO_DOMAIN $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD  

    if [ $? -ne 0 ]; then
        echo "Error: Failed to configure MinIO client alias."
        exit 1
    else
        echo "MinIO client alias 'myminio' configured successfully."
    fi
    
    echo "Starting the server with Gunicorn..."
    gunicorn -w 4 -b 0.0.0.0:80 'data_api:create_app()'
# Check if the first argument is 'setup-db'
elif [ "$1" = 'setup-db' ]; then
    
    echo "Creating Organization in CKAN..."

    # Create an organization in CKAN
    curl -X POST http://ckan:5000/api/3/action/organization_create \
    -H "Authorization: $CKAN_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "stelar-klms",
        "title": "STELAR KLMS",
        "description": "Organization for STELAR KLMS",
        "state": "active"
    }'

    echo "Setting up the database..."

    # Construct the PostgreSQL URL
    psql='/usr/bin/psql'  # psql executable
    URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}/${POSTGRES_DB}"  # Constructing the db URI

    # Check if psql is executable
    if ! [ -x "$psql" ]; then
        echo "Error: $psql cannot be executed, skipping SQL execution"
        exit 1
    fi

    # Loop over all .sql files in /schemas and execute them
    for sql_file in /schemas/*.sql; do
        if [ -f "$sql_file" ]; then  # Check if the file exists
            echo "Executing $sql_file..."
            psql "$URL" "-v" "ON_ERROR_STOP=on" "-f" "$sql_file"
            
            # Check the exit status
            if [ $? -ne 0 ]; then
                echo "Error executing $sql_file"
                exit 1
            fi
        else
            echo "No SQL files found in /schemas."
        fi
    done
else
    echo "Invalid command. Use 'start-server' or 'setup-db'."
    exit 1
fi
