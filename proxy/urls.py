from django.urls import path
from . import views

app_name = "proxy"
urlpatterns = [
    path("abc-msp/message", views.message),
    path("api/message", views.send_message),
]
