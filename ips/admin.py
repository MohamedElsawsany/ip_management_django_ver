from django.contrib import admin
from .models import Branch, DeviceType, Subnet, IP

@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display = ['name', 'ip_count', 'created_at']
    search_fields = ['name']
    readonly_fields = ['created_at']

@admin.register(DeviceType)
class DeviceTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at']
    search_fields = ['name']
    readonly_fields = ['created_at']

@admin.register(Subnet)
class SubnetAdmin(admin.ModelAdmin):
    list_display = ['prefix', 'subnet_mask', 'total_addresses', 'usable_hosts']
    list_filter = ['prefix']
    ordering = ['prefix']

@admin.register(IP)
class IPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'device_name', 'device_type', 'branch', 'subnet', 'created_at']
    list_filter = ['branch', 'device_type', 'subnet']
    search_fields = ['ip_address', 'device_name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'