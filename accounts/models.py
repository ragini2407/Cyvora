from django.db import models
from django.contrib.auth.models import User


class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    severity = models.CharField(max_length=20, blank=True, null=True)  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score = models.FloatField(blank=True, null=True)
    published_date = models.DateTimeField(blank=True, null=True)
    ai_summary = models.TextField(blank=True, null=True)
    ai_recommendation = models.TextField(blank=True, null=True)
    priority_score = models.FloatField(blank=True, null=True)
    fetched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.cve_id


class Technology(models.Model):
    CATEGORY_CHOICES = [
        ('os', 'Operating Systems'),
        ('web', 'Web Technologies'),
        ('database', 'Databases'),
        ('language', 'Programming Languages'),
        ('cloud', 'Cloud Platforms'),
        ('security', 'Security Tools'),
    ]

    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='os')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.version:
            return f"{self.name} {self.version}"
        return self.name


class OrganizationTechStack(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    technology = models.ForeignKey(Technology, on_delete=models.CASCADE)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'technology')

    def __str__(self):
        return f"{self.user.username} - {self.technology.name}"