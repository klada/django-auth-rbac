# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.contrib.auth.models
import django.utils.timezone
from django.conf import settings
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('auth', '0006_require_contenttypes_0002'),
    ]

    operations = [
        migrations.CreateModel(
            name='RbacUser',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(null=True, verbose_name='last login', blank=True)),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, max_length=30, validators=[django.core.validators.RegexValidator('^[\\w.@+-]+$', 'Enter a valid username. This value may contain only letters, numbers and @/./+/-/_ characters.', 'invalid')], help_text='Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.', unique=True, verbose_name='username')),
                ('first_name', models.CharField(max_length=30, verbose_name='first name', blank=True)),
                ('last_name', models.CharField(max_length=30, verbose_name='last name', blank=True)),
                ('email', models.EmailField(max_length=254, verbose_name='email address', blank=True)),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('groups', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Group', blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Permission', blank=True, help_text='Specific permissions for this user.', verbose_name='user permissions')),
            ],
            options={
                'swappable': 'AUTH_USER_MODEL',
                'db_table': 'auth_rbac_user',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='RbacPermission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=100, verbose_name='Name', db_index=True)),
                ('description', models.TextField(verbose_name='Description', blank=True)),
                ('content_type', models.ForeignKey(verbose_name='Model', on_delete=models.CASCADE, to='contenttypes.ContentType')),
            ],
            options={
                'ordering': ('content_type__app_label', 'content_type__model', 'name'),
                'db_table': 'auth_rbac_permission',
                'verbose_name': 'RBAC permission',
                'verbose_name_plural': 'RBAC permissions',
            },
        ),
        migrations.CreateModel(
            name='RbacPermissionProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('permission', models.ForeignKey(on_delete=models.CASCADE, to='rbac.RbacPermission')),
            ],
            options={
                'db_table': 'auth_rbac_permissionprofile',
                'verbose_name': 'RBAC role profile',
                'verbose_name_plural': 'RBAC role profiles',
            },
        ),
        migrations.CreateModel(
            name='RbacRole',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(unique=True, max_length=255, db_index=True)),
                ('description', models.TextField(blank=True)),
                ('displayName', models.CharField(max_length=254, verbose_name='Display name', blank=True)),
                ('children', models.ManyToManyField(to='rbac.RbacRole', blank=True)),
            ],
            options={
                'ordering': ['name'],
                'db_table': 'auth_rbac_role',
                'verbose_name': 'RBAC role',
                'verbose_name_plural': 'RBAC roles',
            },
        ),
        migrations.CreateModel(
            name='RbacRoleProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('child', models.ForeignKey(on_delete=models.CASCADE, related_name='rbacroleprofile_child', to='rbac.RbacRole')),
                ('parent', models.ForeignKey(on_delete=models.CASCADE, related_name='rbacroleprofile_parent', to='rbac.RbacRole')),
            ],
            options={
                'db_table': 'auth_rbac_roleprofile',
            },
        ),
        migrations.CreateModel(
            name='RbacSession',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('backend_session', models.NullBooleanField(default=True)),
                ('expire_date', models.DateTimeField(editable=False)),
                ('active_roles', models.ManyToManyField(to='rbac.RbacRole')),
                ('user', models.ForeignKey(on_delete=models.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'auth_rbac_session',
                'verbose_name': 'RBAC session',
                'verbose_name_plural': 'RBAC sessions',
            },
        ),
        migrations.CreateModel(
            name='RbacSsdSet',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(unique=True, max_length=255)),
                ('description', models.TextField(blank=True)),
                ('cardinality', models.PositiveIntegerField(default=2)),
                ('roles', models.ManyToManyField(to='rbac.RbacRole')),
            ],
            options={
                'db_table': 'auth_rbac_ssdset',
                'verbose_name': 'RBAC Static Separation of Duty Constraint',
                'verbose_name_plural': 'RBAC Static Separation of Duty Constraints',
            },
        ),
        migrations.CreateModel(
            name='RbacUserAssignment',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('touch_date', models.DateTimeField(auto_now_add=True)),
                ('create_date', models.DateTimeField(auto_now=True)),
                ('roles', models.ManyToManyField(to='rbac.RbacRole')),
                ('user', models.OneToOneField(on_delete=models.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'auth_rbac_userassignment',
                'verbose_name': 'RBAC user assignment',
                'verbose_name_plural': 'RBAC user assignments',
            },
        ),
        migrations.AddField(
            model_name='rbacrole',
            name='children_all',
            field=models.ManyToManyField(related_name='parents_all', editable=False, to='rbac.RbacRole', through='rbac.RbacRoleProfile', blank=True),
        ),
        migrations.AddField(
            model_name='rbacrole',
            name='permissions',
            field=models.ManyToManyField(to='rbac.RbacPermission', blank=True),
        ),
        migrations.AddField(
            model_name='rbacpermissionprofile',
            name='role',
            field=models.ForeignKey(on_delete=models.CASCADE, to='rbac.RbacRole'),
        ),
        migrations.AlterUniqueTogether(
            name='rbacsession',
            unique_together=set([('user', 'backend_session')]),
        ),
        migrations.AlterUniqueTogether(
            name='rbacroleprofile',
            unique_together=set([('parent', 'child')]),
        ),
        migrations.AlterUniqueTogether(
            name='rbacpermissionprofile',
            unique_together=set([('role', 'permission')]),
        ),
        migrations.AlterUniqueTogether(
            name='rbacpermission',
            unique_together=set([('content_type', 'name')]),
        ),
    ]
