import os
import sys
import json
import traceback

from flask import Flask
from flask import request, redirect

from . import utils

app = Flask(__name__)
utils.set_requests_verify(os.path.dirname(os.path.realpath(__file__)) + os.sep + 'gd-ca-bundle.crt')

@app.route('/')
def index_page():
    rurl = request.host_url+'configure'
    return redirect(rurl, code=302)

@app.route("/configure")
def handle_configure_gitlab_app():
    print("Configure app service")
    config = utils.get_config()
    if config['gitlab_app'].getboolean('setup_done'):
        print("Warning app aervice is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/gitlab_app_config.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/save_config", methods=['POST'])
def handle_save_gitlab_app_config():
    print("Save app service configuration")
    config = utils.get_config()
    if config['gitlab_app'].getboolean('setup_done'):
        print("Warning app service is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    # update configuration
    tw_handle = request.values.get('tw_handle')
    tw_api_key = request.values.get('tw_api_key')
    tw_instance = request.values.get('tw_instance')
    sast_enabled = request.values.get('sast_enabled')
    iac_enabled = request.values.get('iac_enabled')
    secrets_enabled = request.values.get('secrets_enabled')
    custom_password_file = request.values.get('custom_password_file')
    code_sharing_enabled = request.values.get('code_sharing_enabled')
    tw_gl_host = request.values.get('tw_gl_host')
    tw_gl_user = request.values.get('tw_gl_user')
    tw_gl_access_token = request.values.get('tw_gl_access_token')
    webhook_secret = request.values.get('tw_gl_webhook_secret')
    tw_user_tags = request.values.get('tw_user_tags')
    config['threatworx']['handle'] = tw_handle
    config['threatworx']['token'] = tw_api_key
    config['threatworx']['instance'] = tw_instance
    config['gitlab_app']['gitlab_host'] = tw_gl_host
    config['gitlab_app']['gitlab_user'] = tw_gl_user
    config['gitlab_app']['gitlab_access_token'] = tw_gl_access_token
    config['gitlab_app']['user_tags'] = tw_user_tags
    config['gitlab_app']['custom_password_file'] = custom_password_file.strip() if custom_password_file is not None else ""
    config['gitlab_app']['sast_checks_enabled'] = 'true' if sast_enabled == 'yes' else 'false'
    config['gitlab_app']['iac_checks_enabled'] = 'true' if iac_enabled == 'yes' else 'false'
    config['gitlab_app']['secrets_checks_enabled'] = 'true' if secrets_enabled == 'yes' else 'false'
    config['gitlab_app']['code_sharing'] = 'true' if code_sharing_enabled == 'yes' else 'false'
    config['gitlab_app']['setup_done'] = 'true'
    config['gitlab_app']['webhook_secret'] = webhook_secret
    utils.write_config(config)
    config = utils.get_config(True)

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/success.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/webhook", methods=['POST'])
def webhook():
    try:
        gitlab_token = None
        secret = None
        config = utils.get_config()
        if 'webhook_secret' in config['gitlab_app']:
            secret = config['gitlab_app']['webhook_secret']
        if 'X-Gitlab-Token' in request.headers:
            gitlab_token = request.headers['X-Gitlab-Token']

        if gitlab_token and not secret:
            print('Cannot verify GitLab webhook - missing secret')
            return "Cannot verify GitLab webhook - missing secret", 400, {'Content-Type': 'text/plain'}
        if gitlab_token and (gitlab_token != secret):
            print('Webhook request failed verification')
            return "Webhook request failed verification", 400, {'Content-Type': 'text/plain'}

        #base_discovery_enabled = config['gitlab_app'].getboolean('base_discovery_enabled')
        event = json.loads(request.data)
        if event['event_name'] == 'push':
            utils.process_push_request(event)

        return "", 200, {'Content-Type': 'text/plain'}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int("80"))
