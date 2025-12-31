from django.db import models
import uuid
from django.contrib.auth.models import User


class Package(models.Model):
    """Represents a package in any ecosystem"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    ecosystem = models.CharField(max_length=50, choices=[
        ('npm', 'NPM'),
        ('pypi', 'PyPI'),
        ('maven', 'Maven'),
        ('go', 'Go'),
    ])
    version = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    author = models.CharField(max_length=255, null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['name', 'ecosystem']

    def __str__(self):
        return f"{self.ecosystem}/{self.name}"


class Vulnerability(models.Model):
    """Known vulnerability for a package"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cve_id = models.CharField(max_length=50, unique=True)
    severity = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ])
    description = models.TextField()
    affected_versions = models.JSONField(default=list)
    published_date = models.DateTimeField()
    is_patched = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.cve_id


class ScanRequest(models.Model):
    """A request to scan packages"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    source = models.CharField(max_length=50, choices=[
        ('cli', 'CLI'),
        ('web', 'Web'),
        ('ide', 'IDE'),
        ('ci', 'CI/CD'),
    ])
    target = models.TextField()  # Could be file path, repo URL, or package list
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Scan {self.id} - {self.status}"


class ScanResult(models.Model):
    """Results of a scan"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_request = models.OneToOneField(ScanRequest, on_delete=models.CASCADE)
    overall_risk_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    report_path = models.CharField(max_length=500, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Result for {self.scan_request.id}"


class PackageScanResult(models.Model):
    """Individual package scan result"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='package_results')
    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    risk_score = models.DecimalField(max_digits=5, decimal_places=2)
    vulnerabilities_found = models.IntegerField(default=0)
    is_deprecated = models.BooleanField(default=False)
    is_unmaintained = models.BooleanField(default=False)
    raw_data = models.JSONField(default=dict)  # Store raw API response
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'core_packagescanresult'
        unique_together = ['scan_result', 'package']

    def __str__(self):
        return f"{self.package.name} - Score: {self.risk_score}"