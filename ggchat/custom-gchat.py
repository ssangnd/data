#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import sys
import time
import os
import requests


# Global vars
GCHAT_URI = 'https://chat.googleapis.com/v1/spaces/AAAA0Ep7FDA/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=m8G4XFfKYitR3Of-CITl7b_Qx6yKP0QZMDW0RRDkHGI'
# debug_enabled = False
debug_enabled = True

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)

def main(args):
    debug("# Starting")

    # Read args
    alert_file_location = args[1]
    webhook = GCHAT_URI

    debug("# Webhook")
    debug(webhook)

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    debug("# Generating message")
    msg = generate_msg(json_alert)
    debug(msg)

    debug("# Sending message")
    send_msg(msg, webhook)

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file, "a")
        f.write(msg)
        f.close()

def generate_msg(alert):
    title  = alert['rule']['description']
    subtitle = 'Rule: {}, Level: {}, Agent: {}'.format(alert['rule']['id'],alert['rule']['level'],alert['agent']['name'])
    text = '<font color="#ff0000"><b>{title}</b></font>\n<font color="#00a9e5">{subtitle}</font>\n<b>Full alert:</b>{alert}'.format(title=title,subtitle=subtitle,alert=json.dumps(alert,indent=4))
    cards = {"cards": [{"sections": [{"widgets": [{"textParagraph": {"text": text}}]}]}]}
    return json.dumps(cards)

def send_msg(msg, url):
    headers = {'Content-Type': 'application/json; charset=UTF-8'}
    response = requests.post(url=url,headers=headers,data=msg)
    debug(response.text)

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3],
                sys.argv[4] if len(sys.argv) > 4 else '',
            )
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(msg + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise