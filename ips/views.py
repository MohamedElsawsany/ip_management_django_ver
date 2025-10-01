# ips/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q, Count
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.db import transaction
import json

from .models import Branch, DeviceType, Subnet, IP
from .forms import IPForm, BulkIPForm


def login_view(request):
    """User login view"""
    if request.user.is_authenticated:
        return redirect('index')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'index')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password')
    
    return render(request, 'ips/login.html')


def logout_view(request):
    """User logout view"""
    logout(request)
    messages.success(request, 'You have been logged out successfully')
    return redirect('login')


@login_required
def index(request):
    """Main dashboard view"""
    branches = Branch.objects.annotate(ip_count=Count('ips')).all()
    return render(request, 'ips/index.html', {'branches': branches})


@login_required
def get_networks(request):
    """API endpoint to get networks for a branch"""
    branch_id = request.GET.get('branch_id')
    
    if not branch_id:
        return JsonResponse({'error': 'Branch ID is required'}, status=400)
    
    try:
        networks = IP.objects.filter(branch_id=branch_id).values(
            'subnet__id', 'subnet__prefix', 'subnet__subnet_mask'
        ).annotate(
            ip_count=Count('id')
        ).order_by('subnet__prefix')
        
        # Group by network
        network_dict = {}
        for ip in IP.objects.filter(branch_id=branch_id).select_related('subnet'):
            network = '.'.join(ip.ip_address.split('.')[:-1]) + '.0'
            key = f"{network}_{ip.subnet.id}"
            
            if key not in network_dict:
                network_dict[key] = {
                    'network': network,
                    'subnet_id': ip.subnet.id,
                    'prefix': ip.subnet.prefix,
                    'subnet_mask': ip.subnet.subnet_mask,
                    'ip_count': 0
                }
            network_dict[key]['ip_count'] += 1
        
        networks_list = sorted(network_dict.values(), key=lambda x: IP.ip_to_int(x['network']))
        
        return JsonResponse(list(networks_list), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def get_ips_datatable(request):
    """DataTables server-side processing endpoint"""
    draw = int(request.POST.get('draw', 1))
    start = int(request.POST.get('start', 0))
    length = int(request.POST.get('length', 10))
    search_value = request.POST.get('search[value]', '')
    order_column = int(request.POST.get('order[0][column]', 0))
    order_dir = request.POST.get('order[0][dir]', 'asc')
    branch_id = request.POST.get('branch_id')
    network = request.POST.get('network', '')
    subnet_id = request.POST.get('subnet_id', '')

    if not branch_id:
        return JsonResponse({
            'draw': draw,
            'recordsTotal': 0,
            'recordsFiltered': 0,
            'data': []
        })

    # Base queryset
    queryset = IP.objects.filter(branch_id=branch_id).select_related('device_type', 'subnet')

    # Apply network filter
    if network:
        network_prefix = '.'.join(network.split('.')[:-1])
        queryset = queryset.filter(ip_address__startswith=network_prefix)

    # Apply subnet filter
    if subnet_id:
        queryset = queryset.filter(subnet_id=subnet_id)

    # Total records
    total_records = IP.objects.filter(branch_id=branch_id).count()

    # Apply search
    if search_value:
        queryset = queryset.filter(
            Q(ip_address__icontains=search_value) |
            Q(device_name__icontains=search_value) |
            Q(description__icontains=search_value) |
            Q(device_type__name__icontains=search_value)
        )

    filtered_records = queryset.count()

    # Apply ordering
    order_columns = ['ip_address', 'device_name', 'device_type__name', 'subnet__subnet_mask', 'description']
    order_by = order_columns[order_column] if order_column < len(order_columns) else 'ip_address'
    
    if order_dir == 'desc':
        order_by = f'-{order_by}'
    
    # For IP address, we need custom ordering
    if order_column == 0:
        ips = list(queryset)
        ips.sort(key=lambda x: IP.ip_to_int(x.ip_address), reverse=(order_dir == 'desc'))
        ips = ips[start:start + length]
    else:
        ips = queryset.order_by(order_by)[start:start + length]

    # Format data
    data = []
    for ip in ips:
        data.append({
            'id': ip.id,
            'ip_address': ip.ip_address,
            'device_name': ip.device_name,
            'device_type': ip.device_type.name,
            'device_type_id': ip.device_type.id,
            'subnet_mask': ip.subnet.subnet_mask,
            'subnet_id': ip.subnet.id,
            'description': ip.description or ''
        })

    return JsonResponse({
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': filtered_records,
        'data': data
    })


@login_required
@require_http_methods(["GET", "POST"])
def add_ip(request):
    """Add new IP address"""
    if request.method == 'POST':
        form = IPForm(request.POST)
        if form.is_valid():
            try:
                form.save()
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': True, 'message': 'IP address added successfully'})
                messages.success(request, 'IP address added successfully')
                return redirect('index')
            except Exception as e:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': False, 'error': str(e)}, status=400)
                messages.error(request, f'Error: {str(e)}')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'errors': form.errors}, status=400)
            messages.error(request, 'Please correct the errors below')
    else:
        form = IPForm()
    
    return render(request, 'ips/ip_form.html', {'form': form})


@login_required
@require_http_methods(["GET", "POST"])
def edit_ip(request, ip_id):
    """Edit existing IP address"""
    ip = get_object_or_404(IP, id=ip_id)
    
    if request.method == 'POST':
        form = IPForm(request.POST, instance=ip)
        if form.is_valid():
            try:
                form.save()
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': True, 'message': 'IP address updated successfully'})
                messages.success(request, 'IP address updated successfully')
                return redirect('index')
            except Exception as e:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': False, 'error': str(e)}, status=400)
                messages.error(request, f'Error: {str(e)}')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'errors': form.errors}, status=400)
    else:
        form = IPForm(instance=ip)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'ip': {
                'id': ip.id,
                'ip_address': ip.ip_address,
                'device_name': ip.device_name,
                'device_type_id': ip.device_type.id,
                'subnet_id': ip.subnet.id,
                'description': ip.description or ''
            }
        })
    
    return render(request, 'ips/ip_form.html', {'form': form, 'ip': ip})


@login_required
@require_http_methods(["POST", "DELETE"])
def delete_ip(request, ip_id):
    """Delete IP address"""
    ip = get_object_or_404(IP, id=ip_id)
    
    try:
        ip.delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': 'IP address deleted successfully'})
        messages.success(request, 'IP address deleted successfully')
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
        messages.error(request, f'Error: {str(e)}')
    
    return redirect('index')


@login_required
def bulk_insert(request):
    """Bulk IP insert view"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            start_ip = data.get('start_ip')
            end_ip = data.get('end_ip')
            branch_id = data.get('branch_id')
            subnet_id = data.get('subnet_id')
            device_type_id = data.get('device_type_id')
            device_name_prefix = data.get('device_name_prefix', 'Device')
            description = data.get('description', 'Bulk inserted IP')
            skip_existing = data.get('skip_existing', True)
            
            # Convert IPs to integers
            start_long = IP.ip_to_int(start_ip)
            end_long = IP.ip_to_int(end_ip)
            
            if start_long > end_long:
                return JsonResponse({'success': False, 'error': 'Start IP must be less than or equal to End IP'}, status=400)
            
            total_ips = end_long - start_long + 1
            
            if total_ips > 5000000:
                return JsonResponse({
                    'success': False,
                    'error': f'Range too large. Maximum 5,000,000 IPs. Requested: {total_ips:,}'
                }, status=400)
            
            # Get related objects
            branch = get_object_or_404(Branch, id=branch_id)
            subnet = get_object_or_404(Subnet, id=subnet_id)
            device_type = get_object_or_404(DeviceType, id=device_type_id)
            
            inserted = 0
            skipped = 0
            errors = []
            
            # Get existing IPs if skip_existing is True
            existing_ips = set()
            if skip_existing:
                existing_ips = set(
                    IP.objects.filter(
                        ip_address__in=[
                            IP.int_to_ip(i) for i in range(start_long, min(start_long + 10000, end_long + 1))
                        ]
                    ).values_list('ip_address', flat=True)
                )
            
            # Process in batches
            batch_size = 1000
            current_long = start_long
            
            with transaction.atomic():
                batch = []
                
                while current_long <= end_long:
                    ip_address = IP.int_to_ip(current_long)
                    
                    if skip_existing and ip_address in existing_ips:
                        skipped += 1
                        current_long += 1
                        continue
                    
                    ip_suffix = ip_address.replace('.', '-')
                    device_name = f"{device_name_prefix}-{ip_suffix}"
                    
                    batch.append(IP(
                        ip_address=ip_address,
                        subnet=subnet,
                        device_name=device_name,
                        device_type=device_type,
                        branch=branch,
                        description=description
                    ))
                    
                    if len(batch) >= batch_size:
                        try:
                            IP.objects.bulk_create(batch, ignore_conflicts=skip_existing)
                            inserted += len(batch)
                            batch = []
                        except Exception as e:
                            errors.append(str(e))
                    
                    current_long += 1
                
                # Insert remaining
                if batch:
                    try:
                        IP.objects.bulk_create(batch, ignore_conflicts=skip_existing)
                        inserted += len(batch)
                    except Exception as e:
                        errors.append(str(e))
            
            return JsonResponse({
                'success': True,
                'message': f'Successfully processed {total_ips:,} IP addresses',
                'inserted': inserted,
                'skipped': skipped,
                'total_processed': total_ips,
                'start_ip': start_ip,
                'end_ip': end_ip,
                'errors': errors
            })
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    branches = Branch.objects.all()
    device_types = DeviceType.objects.all()
    subnets = Subnet.objects.all()
    
    return render(request, 'ips/bulk_insert.html', {
        'branches': branches,
        'device_types': device_types,
        'subnets': subnets
    })


@login_required
def get_device_types(request):
    """API endpoint to get device types"""
    device_types = list(DeviceType.objects.values('id', 'name'))
    return JsonResponse(device_types, safe=False)


@login_required
def get_subnets(request):
    """API endpoint to get subnets"""
    subnets = list(Subnet.objects.values('id', 'prefix', 'subnet_mask'))
    return JsonResponse(subnets, safe=False)


@login_required
def get_branches(request):
    """API endpoint to get branches"""
    branches = Branch.objects.annotate(ip_count=Count('ips')).values('id', 'name', 'ip_count')
    return JsonResponse(list(branches), safe=False)