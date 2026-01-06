#!/bin/sh

# create/load secret from file if env variable not set
SECRET_FILE_PATH=data/.django_secret
if [ -z "${DJANGO_SECRET}" ]; then
    if [ -f "${SECRET_FILE_PATH}" ]; then
        echo "using DJANGO_SECRET from file"
        DJANGO_SECRET=$(cat ${SECRET_FILE_PATH})
    else
        echo "creating DJANGO_SECRET file"
        DJANGO_SECRET=$(openssl rand -base64 24)
        echo "${DJANGO_SECRET}" > ${SECRET_FILE_PATH}
    fi
else
    echo "using DJANGO_SECRET from environment"
fi

python manage.py migrate --no-input
python manage.py collectstatic --no-input

DJANGO_SUPERUSER_PASSWORD=$SUPER_USER_PASSWORD python manage.py createsuperuser --username $SUPER_USER_NAME --email $SUPER_USER_EMAIL --noinput
echo "💡 Superuser Username: ${SUPER_USER_NAME}, E-Mail: ${SUPER_USER_EMAIL}"

# run django
gunicorn django_project.wsgi:application --bind 0.0.0.0:8000 &
# run caddy to serve static files
caddy run &

wait