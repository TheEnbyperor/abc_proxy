from celery import shared_task, group
from celery.result import allow_join_result
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random.OSRNG.fallback import PythonOSURandomRNG
from . import models
from django.conf import settings
import hmac
import jwt
import json
import requests
import datetime
import backoff
import codecs
import binascii
import base64


def make_jwt():
    return jwt.encode({
        "iat": datetime.datetime.utcnow(),
        "iss": settings.ABC_MSP_ID
    }, settings.ABC_MSP_SECRET, algorithm='HS256').decode()


@shared_task
def add_attachment_values(attachment, biz_id):
    data = get_attachment(attachment, biz_id)

    if data.get("contents"):
        data["contents"] = base64.b64encode(data["contents"]).decode()
    data["name"] = attachment.get("name")
    data["mime-type"] = attachment.get("mimeType")

    return data


@shared_task
def process_message(aid: int, onwards_data: dict, body: dict):
    account = models.ABCAccount.objects.get(id=aid)

    attachments = body.get("attachments", [])
    attachments_group = group(add_attachment_values.s(a, account.account_id) for a in attachments)
    attachments_res = attachments_group.apply_async()

    onwards_data["locale"] = body.get("locale")
    onwards_data["group"] = body.get("group")
    onwards_data["intent"] = body.get("intent")
    onwards_data["contents"] = {}

    msg_type = body.get("type")
    if msg_type == "text":
        onwards_data["contents"]["text"] = body.get("body")
    elif msg_type == "interactive":
        if body.get("interactiveDataRef"):
            data_ref = body.get("interactiveDataRef")

            @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=300)
            def download(download_data):
                r = requests.post("https://mspgw.push.apple.com/v1/decodePayload", headers={
                    "Authorization": f"Bearer {make_jwt()}",
                    "source-id": account.account_id,
                    "bid": data_ref.get("bid")
                }, data=download_data)
                r.raise_for_status()
                return r.json()

            data = get_attachment(data_ref, account.account_id)
            if not data.get("contents"):
                onwards_data["contents"]["data"] = data
            else:
                try:
                    data = download(data["contents"])
                except requests.exceptions.RequestException:
                    onwards_data["contents"]["data"] = {
                        "error": "failed"
                    }
                else:
                    onwards_data["contents"]["data"] = data.get("interactiveData")
        else:
            onwards_data["contents"]["data"] = body.get("interactiveData")
    elif msg_type == "typing_start":
        onwards_data["contents"]["action"] = "typing_start"
    elif msg_type == "typing_end":
        onwards_data["contents"]["action"] = "typing_end"
    elif msg_type == "close":
        onwards_data["contents"]["action"] = "close"
    else:
        return

    with allow_join_result():
        onwards_data["attachments"] = attachments_res.join()

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=600)
    def send_onwards(req_body: str):
        req_body = req_body.encode()
        digest = hmac.new(key=account.api_key.encode(), msg=req_body, digestmod='sha512')
        r = requests.post(f"{account.forward_url}/message", headers={
            "X-Body-Signature": digest.hexdigest(),
            "Content-Type": "application/json"
        }, data=req_body)
        r.raise_for_status()

    send_onwards(json.dumps(onwards_data))


def get_attachment(attachment: dict, biz_id: str):
    try:
        signature = codecs.decode(attachment.get("signature"), "hex")
    except binascii.Error:
        return {
            "error": "invalid-signature"
        }
    key = attachment.get("key")
    if not key.startswith("00"):
        return {
            "error": "invalid-key"
        }
    try:
        key = codecs.decode(key[2:], "hex")
    except binascii.Error:
        return {
            "error": "invalid-key"
        }

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=300)
    def get_url():
        r = requests.get("https://mspgw.push.apple.com/v1/preDownload", headers={
            "Authorization": f"Bearer {make_jwt()}",
            "owner": attachment.get("owner"),
            "signature": base64.b64encode(signature),
            "url": attachment.get("url"),
            "source-id": biz_id
        })
        r.raise_for_status()
        return r.json().get("download-url")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=300)
    def download(download_url):
        r = requests.get(download_url)
        r.raise_for_status()
        ctr = Counter.new(128, initial_value=0)
        cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(r.content)

    try:
        url = get_url()
    except requests.exceptions.RequestException:
        return {
            "error": "failed"
        }
    try:
        data = download(url)
    except requests.exceptions.RequestException:
        return {
            "error": "failed"
        }

    return {
        "contents": data,
    }


@shared_task
def send_message(aid: int, msg_id: str, msg_to: str, msg_locale: str, msg_contents: dict, msg_attachments: [dict],
                 msg_auto_reply: bool):
    account = models.ABCAccount.objects.get(id=aid)

    attachments_group = group(send_attachment.s(a, account.account_id) for a in msg_attachments)
    attachments_res = attachments_group.apply_async()

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=600)
    def send_notification(status: str):
        req_body = json.dumps({
            "id": msg_id,
            "status": status
        })
        digest = hmac.new(key=account.api_key.encode(), msg=req_body.encode(), digestmod='sha512')
        r = requests.post(f"{account.forward_url}/notification", headers={
            "X-Body-Signature": digest.hexdigest(),
            "Content-Type": "application/json"
        }, data=req_body)
        r.raise_for_status()

    msg = {
        "v": 1,
        "id": msg_id,
        "sourceId": str(account.account_id),
        "locale": msg_locale,
        "destinationId": msg_to
    }

    if msg_contents.get("text"):
        msg["type"] = "text"
        msg["body"] = msg_contents["text"] + ("\uFFFC" * len(msg_attachments))
    elif msg_contents.get("action"):
        action = msg_contents["action"]
        if action == "typing_start":
            msg["type"] = "typing_start"
        elif action == "typing_end":
            msg["type"] = "typing_start"
        else:
            send_notification("failed")
            return
    elif msg_contents.get("rich-link"):
        msg["type"] = "richLink"
        msg["richLinkData"] = msg_contents["rich-link"]
    elif msg_contents.get("data"):
        msg["type"] = "interactive"
        msg["interactiveData"] = msg_contents["data"]
    else:
        send_notification("failed")
        return
    with allow_join_result():
        attachments = attachments_res.join()
        if any(map(lambda a: a is False, attachments)):
            send_notification("failed")
            return
        msg["attachments"] = attachments

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=300)
    def send_onwards(req_body: dict):
        r = requests.post("https://mspgw.push.apple.com/v1/message", headers={
            "Authorization": f"Bearer {make_jwt()}",
            "source-id": str(account.account_id),
            "destination-id": msg_to,
            "id": msg_id,
            "auto-reply": str(msg_auto_reply).lower()
        }, json=req_body)
        r.raise_for_status()

    try:
        send_onwards(msg)
        send_notification("sent")
    except requests.exceptions.RequestException:
        send_notification("failed")


@shared_task
def send_attachment(attachment: dict, biz_id: str):
    rand = PythonOSURandomRNG()
    key = rand.read(32)
    key_hex = "00" + codecs.encode(key, "hex").decode()

    file_data = base64.b64decode(attachment["data"])
    ctr = Counter.new(128, initial_value=0)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    enc_file_data = cipher.encrypt(file_data)

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=300)
    def get_url():
        r = requests.get("https://mspgw.push.apple.com/v1/preUpload", headers={
            "Authorization": f"Bearer {make_jwt()}",
            "size": str(len(file_data)),
            "source-id": biz_id
        })
        r.raise_for_status()
        return r.json()

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_time=300)
    def upload(upload_url):
        r = requests.post(upload_url.get("upload-url"), data=enc_file_data)
        r.raise_for_status()
        return r.json()

    try:
        url = get_url()
    except requests.exceptions.RequestException:
        return False
    except json.JSONDecodeError:
        return False
    try:
        data = upload(url)
    except requests.exceptions.RequestException:
        return False
    except json.JSONDecodeError:
        return False

    if not url.get("mmcs-owner"):
        return False
    if not url.get("mmcs-url"):
        return False
    if not data.get("singleFile"):
        return False
    if not data["singleFile"].get("fileChecksum"):
        return False

    return {
        "name": attachment["name"],
        "file-size": str(len(file_data)),
        "mime-type": attachment["mime-type"],
        "signature-base64": data["singleFile"]["fileChecksum"],
        "decryption-key": key_hex,
        "mmcs-url": url["mmcs-url"],
        "mmcs-owner": url["mmcs-owner"],
    }
