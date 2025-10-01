# ips/models.py
from django.db import models
from django.core.validators import validate_ipv4_address
from django.core.exceptions import ValidationError

class Branch(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'branches'
        verbose_name_plural = 'Branches'
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def ip_count(self):
        return self.ips.count()


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

    def __str__(self):
        return f"{self.ip_address} - {self.device_name}"

    def clean(self):
        super().clean()
        # Additional validation
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