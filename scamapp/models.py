from django.db import models
# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from django.db import models

class User(AbstractUser):

    ROLE_CHOICES = (
        ('USER', 'User'),
        ('ADMIN', 'Admin'),
    )

    full_name = models.CharField(max_length=150)

    email = models.EmailField(unique=True)

    phone = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^\+?\d{10,15}$',
                message="Enter a valid phone number."
            )
        ]
    )

    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default='USER'
    )
    address=models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.username

# models.py

from django.conf import settings
from django.db import models


class ScanHistory(models.Model):

    RESULT_CHOICES = (
        ('Legitimate', 'Legitimate'),
        ('Scam / Phishing', 'Scam / Phishing'),
        ('Spam', 'Spam'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scan_histories'
    )

    message = models.TextField()

    result = models.CharField(
        max_length=30,
        choices=RESULT_CHOICES
    )

    confidence = models.FloatField(default=0)

    probabilities = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.result}"


class URLScanHistory(models.Model):

    RESULT_CHOICES = (
        ('Low Risk', 'Low Risk'),
        ('Suspicious', 'Suspicious'),
        ('High Risk', 'High Risk'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='url_scan_histories'
    )

    url = models.URLField(max_length=2048)

    domain = models.CharField(max_length=255)

    risk_score = models.PositiveSmallIntegerField(default=0)

    result = models.CharField(
        max_length=20,
        choices=RESULT_CHOICES
    )

    reasons = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.result}"
