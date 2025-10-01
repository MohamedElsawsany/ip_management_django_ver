# ips/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import Branch, DeviceType, Subnet, IP, UserProfile

# Inline admin for UserProfile
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'

# Extend User admin
class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    list_display = ['username', 'email', 'first_name', 'last_name', 'is_staff', 'get_branch', 'get_is_admin']
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'profile__is_admin', 'profile__branch']
    
    def get_branch(self, obj):
        if hasattr(obj, 'profile') and obj.profile.branch:
            return obj.profile.branch.name
        return '-'
    get_branch.short_description = 'Branch'
    
    def get_is_admin(self, obj):
        if hasattr(obj, 'profile'):
            return obj.profile.is_admin
        return False
    get_is_admin.short_description = 'Is Admin'
    get_is_admin.boolean = True

# Unregister the default User admin and register our custom one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'branch', 'is_admin', 'created_at']
    list_filter = ['is_admin', 'branch']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['created_at']

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