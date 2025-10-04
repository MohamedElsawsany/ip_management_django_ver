# ips/models.py - OPTIMIZED VERSION
from django.db import models
from django.core.validators import validate_ipv4_address
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User

class Branch(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'branches'
        verbose_name_plural = 'Branches'
        ordering = ['name']
        indexes = [
            models.Index(fields=['name'], name='branches_name_idx'),
        ]

    def __str__(self):
        return self.name

    @property
    def ip_count(self):
        return self.ips.count()


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True, related_name='users')
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"{self.user.username} - {'Admin' if self.is_admin else 'User'}"


class DeviceType(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'device_types'
        ordering = ['name']

    def __str__(self):
        return self.name


class Subnet(models.Model):
    prefix = models.PositiveSmallIntegerField()
    subnet_mask = models.CharField(max_length=255)
    total_addresses = models.BigIntegerField()
    usable_hosts = models.BigIntegerField()

    class Meta:
        db_table = 'subnets'
        ordering = ['prefix']

    def __str__(self):
        return f"/{self.prefix} ({self.subnet_mask})"


class IP(models.Model):
    ip_address = models.CharField(max_length=255, validators=[validate_ipv4_address], unique=True)
    subnet = models.ForeignKey(Subnet, on_delete=models.CASCADE, related_name='ips')
    device_name = models.CharField(max_length=255)
    device_type = models.ForeignKey(DeviceType, on_delete=models.CASCADE, related_name='ips')
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name='ips')
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'ips'
        ordering = ['ip_address']
        verbose_name = 'IP Address'
        verbose_name_plural = 'IP Addresses'
        indexes = [
            # Composite indexes for common queries
            models.Index(fields=['branch', 'ip_address'], name='ips_branch_ip_idx'),
            models.Index(fields=['branch', 'subnet'], name='ips_branch_subnet_idx'),
            # Single column indexes
            models.Index(fields=['device_name'], name='ips_device_name_idx'),
            models.Index(fields=['device_type'], name='ips_device_type_idx'),
            models.Index(fields=['ip_address'], name='ips_ip_address_idx'),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.device_name}"

    def clean(self):
        super().clean()
        if self.ip_address:
            try:
                validate_ipv4_address(self.ip_address)
            except ValidationError:
                raise ValidationError({'ip_address': 'Enter a valid IPv4 address.'})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    @staticmethod
    def ip_to_int(ip_str):
        """Convert IP address string to integer for sorting"""
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

    @staticmethod
    def int_to_ip(ip_int):
        """Convert integer to IP address string"""
        return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"