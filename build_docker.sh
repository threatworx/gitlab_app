#!/bin/bash
# Install gitlab app dependencies
pip install -r /tmp/requirements.txt
# Setup twigs update script
printf "#!/bin/bash\n/usr/share/gitlab_app/gen_def_cert.sh\n/usr/local/bin/uwsgi --ini /opt/tw_gitlab_app/config/uwsgi.ini" > /usr/local/bin/run-app.sh
chmod +x /usr/local/bin/run-app.sh
# Cleanup /tmp
rm -f /tmp/*
