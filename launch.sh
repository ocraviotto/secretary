#!/bin/sh
set -e

# Decrypt secrets
if [ "$SERVICE_PRIVATE_KEY" != "" ]; then
	SECRETS=$(secretary decrypt -e "--service-key=$SERVICE_PRIVATE_KEY")
else
	SECRETS=$(secretary decrypt -e)
fi

eval "$SECRETS"
unset SECRETS

# Execute the CMD
exec "$@"
