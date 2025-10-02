# ips/forms.py
from django import forms
from .models import IP, Branch, DeviceType, Subnet


class IPForm(forms.ModelForm):
    class Meta:
        model = IP
        fields = ['ip_address', 'device_name', 'device_type', 'subnet', 'branch', 'description']
        widgets = {
            'ip_address': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '192.168.1.1',
                'required': True
            }),
            'device_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Server-01',
                'required': True
            }),
            'device_type': forms.Select(attrs={
                'class': 'form-select',
                'required': True
            }),
            'subnet': forms.Select(attrs={
                'class': 'form-select',
                'required': True
            }),
            'branch': forms.Select(attrs={
                'class': 'form-select',
                'required': True
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Optional description of the device or its purpose'
            }),
        }
        labels = {
            'ip_address': 'IP Address *',
            'device_name': 'Device Name *',
            'device_type': 'Device Type *',
            'subnet': 'Subnet *',
            'branch': 'Branch *',
            'description': 'Description',
        }

    def clean_ip_address(self):
        ip_address = self.cleaned_data.get('ip_address')
        instance_id = self.instance.id if self.instance else None
        
        # Check if IP already exists (excluding current instance when editing)
        existing = IP.objects.filter(ip_address=ip_address)
        if instance_id:
            existing = existing.exclude(id=instance_id)
        
        if existing.exists():
            raise forms.ValidationError('This IP address already exists.')
        
        return ip_address


class BranchForm(forms.ModelForm):
    class Meta:
        model = Branch
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter branch name',
                'required': True
            }),
        }
        labels = {
            'name': 'Branch Name *',
        }

    def clean_name(self):
        name = self.cleaned_data.get('name')
        instance_id = self.instance.id if self.instance else None
        
        # Check if branch name already exists (excluding current instance when editing)
        existing = Branch.objects.filter(name__iexact=name)
        if instance_id:
            existing = existing.exclude(id=instance_id)
        
        if existing.exists():
            raise forms.ValidationError('A branch with this name already exists.')
        
        return name


class BulkIPForm(forms.Form):
    start_ip = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '172.16.0.0',
            'required': True
        }),
        label='Start IP Address *'
    )
    end_ip = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '172.31.255.255',
            'required': True
        }),
        label='End IP Address *'
    )
    branch = forms.ModelChoiceField(
        queryset=Branch.objects.all(),
        widget=forms.Select(attrs={
            'class': 'form-select',
            'required': True
        }),
        label='Branch *'
    )
    subnet = forms.ModelChoiceField(
        queryset=Subnet.objects.all(),
        widget=forms.Select(attrs={
            'class': 'form-select',
            'required': True
        }),
        label='Subnet Mask *'
    )
    device_type = forms.ModelChoiceField(
        queryset=DeviceType.objects.all(),
        widget=forms.Select(attrs={
            'class': 'form-select',
            'required': True
        }),
        label='Device Type *'
    )
    device_name_prefix = forms.CharField(
        max_length=100,
        initial='Device',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'required': True
        }),
        label='Device Name Prefix *'
    )
    description = forms.CharField(
        required=False,
        initial='Bulk inserted IP range',
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': 'Optional description'
        }),
        label='Description'
    )
    skip_existing = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label='Skip existing IP addresses (recommended)'
    )

    def clean(self):
        cleaned_data = super().clean()
        start_ip = cleaned_data.get('start_ip')
        end_ip = cleaned_data.get('end_ip')

        if start_ip and end_ip:
            try:
                start_long = IP.ip_to_int(start_ip)
                end_long = IP.ip_to_int(end_ip)
                
                if start_long > end_long:
                    raise forms.ValidationError('Start IP must be less than or equal to End IP')
            except Exception as e:
                raise forms.ValidationError(f'Invalid IP address format: {str(e)}')

        return cleaned_data