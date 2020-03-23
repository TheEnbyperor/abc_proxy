from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
import sentry_sdk
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.redis import RedisIntegration

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "abc_proxy.settings")
from django.conf import settings

# if not settings.DEBUG:
#     sentry_sdk.init(
#         "https://518037d272e5426895df091967e1b949@sentry.io/1821508",
#         environment=os.getenv("SENTRY_ENVIRONMENT", "dev"),
#         integrations=[CeleryIntegration(), DjangoIntegration(), RedisIntegration()],
#         release=os.getenv("RELEASE", None),
#     )

app = Celery("abc_proxy")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
