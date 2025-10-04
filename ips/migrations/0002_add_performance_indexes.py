from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ips', '0001_initial'),
    ]

    operations = [
        # Add indexes to IP model for better query performance
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['branch', 'ip_address'], name='ips_branch_ip_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['branch', 'subnet'], name='ips_branch_subnet_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['device_name'], name='ips_device_name_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['device_type'], name='ips_device_type_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['ip_address'], name='ips_ip_address_idx'),
        ),
        # Add index to Branch model
        migrations.AddIndex(
            model_name='branch',
            index=models.Index(fields=['name'], name='branches_name_idx'),
        ),
    ]