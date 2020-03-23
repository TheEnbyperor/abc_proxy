import json
import base64
import zlib
import uuid
import jwt
from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from . import models
from . import tasks


def get_body(request):
    http_encoding = request.META.get("HTTP_CONTENT_ENCODING")
    if http_encoding == "gzip":
        try:
            return zlib.decompress(request.body, 16+zlib.MAX_WBITS)
        except zlib.error:
            return None
    return request.body


@require_POST
@csrf_exempt
def message(request):
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth_header.startswith("Bearer "):
        return HttpResponseForbidden()
    auth_header = auth_header[len("Bearer "):].strip()
    try:
        jwt.decode(
            auth_header, settings.ABC_MSP_SECRET, algorithms=['HS256'], audience=settings.ABC_MSP_ID
        )
    except jwt.exceptions.InvalidTokenError:
        return HttpResponseForbidden()

    body = get_body(request)
    if not body:
        return HttpResponseBadRequest()
    try:
        body = json.loads(body)
    except json.JSONDecodeError:
        return HttpResponseBadRequest()

    if body.get("v") != 1:
        return HttpResponseBadRequest()

    try:
        account = models.ABCAccount.objects.get(account_id=request.META.get("HTTP_DESTINATION_ID"))
    except models.ABCAccount.DoesNotExist:
        return HttpResponseNotFound()

    onwards_data = {
        "from": request.META.get("HTTP_SOURCE_ID"),
        "id": request.META.get("HTTP_ID"),
        "device": request.META.get("HTTP_DEVICE_AGENT"),
        "capabilities": list(map(lambda c: c.lower(), request.META.get("HTTP_CAPABILITIES", "").split(","))),
    }
    tasks.process_message.delay(account.id, onwards_data, body)

    return HttpResponse("")


@require_POST
@csrf_exempt
def send_message(request):
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth_header.startswith("Bearer "):
        return HttpResponseForbidden()
    auth_header = auth_header[len("Bearer "):].strip()
    try:
        account = models.ABCAccount.objects.get(api_key=auth_header)
    except models.ABCAccount.DoesNotExist:
        return HttpResponseForbidden()

    if request.content_type == "application/json":
        body = get_body(request)
        if not body:
            return HttpResponseBadRequest()
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return HttpResponseBadRequest()
    else:
        try:
            body = json.loads(request.POST.get("data"))
        except json.JSONDecodeError:
            return HttpResponseBadRequest()

    msg_to = body.get("to")
    msg_id = body.get("id")
    msg_locale = body.get("locale")
    msg_contents = body.get("contents")
    msg_auto_reply = bool(body.get("auto-reply", False))
    msg_attachments = []

    for file in request.FILES.getlist("file"):
        if file.size > 104857600:  # 100MiB
            return HttpResponseBadRequest()
        msg_attachments.append({
            "name": file.name,
            "mime-type": file.content_type,
            "data": base64.b64encode(file.read()).decode()
        })

    if not msg_id:
        msg_id = str(uuid.uuid4())
    if not (msg_to and msg_id and msg_locale and msg_contents):
        return HttpResponseBadRequest()
    if type(msg_contents) != dict:
        return HttpResponseBadRequest()
    if not (msg_contents.get("text") or msg_contents.get("action") or msg_contents.get("data") or
            msg_contents.get("rich-link")):
        return HttpResponseBadRequest()

    try:
        msg_id = str(uuid.UUID(msg_id))
    except ValueError:
        return HttpResponseBadRequest()

    tasks.send_message.delay(account.id, msg_id, msg_to, msg_locale, msg_contents, msg_attachments, msg_auto_reply)

    return HttpResponse("")
