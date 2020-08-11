import base64
import csv
import io
import json
import os
import re
import sys
from xml.etree import ElementTree as tree

import boto3
import dominate
import geoip2.models
from dominate import tags
from geoip2.webservice import Client

session = boto3.session.Session(region_name='us-east-1')
kms_client = session.client('kms')


def decrypt_kms_value(ciphertext: str):
    return kms_client.decrypt(
        CiphertextBlob=base64.b64decode(ciphertext),
        KeyId=os.environ.get('kms_key_id'),
        EncryptionAlgorithm='SYMMETRIC_DEFAULT'
    ).get('Plaintext').decode('utf8')


user_cipher = os.environ.get('geoip_user')
pass_cipher = os.environ.get('geoip_pass')
raw_pass = decrypt_kms_value(pass_cipher)
raw_username = decrypt_kms_value(user_cipher)
client = Client(raw_username, raw_pass)

with open("./index.html") as _fd:
    index_html = _fd.read()
html_content_type = {
    'Content-Type': 'text/html'
}
json_content_type = {
    'Content-Type': 'application/json'
}

_headers = {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "*",
    "access-control-allow-methods": "*"
}


def root_handler(event, context):
    try:
        ident = event.get('requestContext').get('identity')
        source_ip = ident.get('sourceIp')
        agent = ident.get('userAgent')
        requested_type = (event.get('headers') or {}).get('accept') or None

        plain_text_requested = bool(requested_type and any(re.findall(r'plain/text', requested_type, re.IGNORECASE))
                                    or (agent and 'curl' in agent.lower()))
        print(f"IP: {source_ip};"
              f" user agent: {agent};"
              f" requested plaintext: {plain_text_requested},"
              f" requested mime-type: {requested_type}")
        if plain_text_requested:
            return {
                'statusCode': 200,
                'body': f'{source_ip}\n',
                'headers': {**_headers, **json_content_type}
            }
        return {
            'statusCode': 200,
            'body': create_root_html(),
            'headers': {**_headers, **html_content_type}
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error_type': str(type(e)),
                'line_number': sys.exc_info()[-1].tb_lineno,
                'error': str(e),
                'event': event
            })
        }


def api_handler(event, context):
    source_ip = event.get('requestContext').get('identity').get('sourceIp')
    path = event.get('requestContext').get('path')
    if path.endswith('xml'):
        root = tree.Element('root')
        ip = tree.SubElement(root, 'ip')
        ip.text = source_ip
        return {
            'statusCode': 200,
            'body': tree.tostring(root, encoding='UTF-8'),
            'headers': _headers
        }
    elif path.endswith('json'):
        return {
            'statusCode': 200,
            'body': json.dumps({'ip': source_ip}),
            'headers': _headers
        }
    elif path.endswith('csv'):
        csvfile = io.StringIO()
        fieldnames = ['ip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerow({'ip': source_ip})
        return {
            'statusCode': 200,
            'body': csvfile.getvalue()
        }
    return {
        'statusCode': 400,
        'body': 'unknown request'
    }


def geo_handler(event, context):
    source_ip = event.get('requestContext').get('identity').get('sourceIp')
    try:
        insights: geoip2.models.Insights = client.insights(source_ip)
        remaining_ = f'IP: {source_ip}, city: {insights.city.names},' \
                     f' remaining queries: {insights.maxmind.queries_remaining}'
        print(remaining_)
        cleaned = insights.raw.copy()
        cleaned.pop('maxmind')
        return {
            'statusCode': 200,
            'body': json.dumps({
                'ip': source_ip,
                'insights': cleaned
            }),
            'headers': _headers
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error_type': str(type(e)),
                'error': str(e)
            }),
            'headers': _headers
        }


def create_root_html():
    doc = dominate.document(title='URIP.io')
    script = """
fetch('https://urip.io/json')
    .then(function (response) {
        return response.json();
    })
    .then(function (myJson) {
        console.log('Found ip address: ' + myJson.ip);
        var lookup = document.getElementById('ipLookingText');
        var found = document.getElementById('foundIp');
        lookup.style.display = 'none';
        found.style.display = 'block';
        document.querySelector('#ipText').innerHTML = myJson.ip;
    })
    .catch(function (error) {
        console.log('Error: ' + error);
    });"""
    copy_ip_script = """
function copyIpAddr() {
    var text = document.getElementById('ipText');
    text.select();
    text.setSelectionRange(0, 100);
    document.execCommand('copy');
    console.log(text.value);
}
"""
    with doc.head:
        tags.meta(charset="UTF-8")
    with doc.body:
        styles = {
            'text-align': 'center',
            'align-items': 'center',
            'display': 'flex',
            'justify-content': 'center',
            'width': '100vw',
            'height': '100vw'
        }
        with tags.div(style=";".join(styles)):
            tags.h1("Looking for URIP address...", id='ipLookingText')
            tags.h1("URIP address is:", id='foundIp', style='display:none')
            tags.br()
            tags.h1(id='ipText', onclick='copyIpAddr()')

        tags.script(script)
        tags.script(copy_ip_script)

    return doc.render(pretty=True)


if __name__ == '__main__':
    print(api_handler({
        'requestContext': {
            'identity': {
                'sourceIp': '172.217.4.46'
            }
        }
    }, {}))


def __main__(*args, **kwargs):
    print(f"Main: {args}; {kwargs}")