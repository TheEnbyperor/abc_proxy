from django.db import models
import secrets


def create_secret():
    return secrets.token_urlsafe(100)


class ABCAccount(models.Model):
    name = models.CharField(max_length=255, blank=False)
    account_id = models.UUIDField(blank=False)
    forward_url = models.TextField(blank=False)
    api_key = models.CharField(max_length=255, default=create_secret)

    class Meta:
        verbose_name = "ABC Account"
        verbose_name_plural = "ABC Accounts"

    def __str__(self):
        return self.name
