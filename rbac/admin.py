# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from collections import OrderedDict
from django.conf.urls import url
from django.contrib import admin
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from django.template.response import TemplateResponse
from django.utils.translation import ugettext_lazy as _
from rbac import models
from rbac.forms import RbacRoleForm, EffectivePermissionFilterForm

class TopLevelRoleFilter(admin.SimpleListFilter):
    """
    Allows to select only top-level roles or only roles with at least one
    parent.
    """
    title = _('top-level roles')
    parameter_name = 'toplevelroles'
    
    def lookups(self, request, model_admin):
        return (
            ('1', _('Yes')),
            ('0', _('No')),
        )
        
    def queryset(self, request, queryset):
        if self.value() == '1':
            return queryset.filter(parents_all=None)
        elif self.value() == '0':
            return queryset.exclude(parents_all=None)

class RoleAdmin(admin.ModelAdmin):
    form = RbacRoleForm
    search_fields = ['name']
    list_filter = (TopLevelRoleFilter, )
    list_display = ('name', '_admin_effective_permissions')
    filter_horizontal = ('permissions', 'children' )
    change_form_template = 'rbac/change_form.html'
    change_list_template = 'rbac/change_list.html'
        
    def get_urls(self):
        urls = super(RoleAdmin, self).get_urls()
        my_urls = [
            url(r'^(\d+)/effective_permissions/$', self.view_effective_permissions),
            url(r'^modelpermissions/$', self.view_permissions_by_model, name='rbac_rbacrole_permissions_by_model')
        ]
        return my_urls + urls


    def view_effective_permissions(self, request, role_id):
        """
        View which displays the effective permissions of a role
        with support for filtering by app_label and model.
        """
        from django.utils.safestring import mark_safe
        from rbac.models import RbacPermissionProfile
        import json
        role = get_object_or_404(models.RbacRole, pk=role_id)
        
        permissions = {}
        for i in RbacPermissionProfile.objects.filter(
             role=role
         ).values_list(
             'permission__content_type__app_label',
             'permission__content_type__model',
             'permission__name'
         ):
            app_label = i[0]
            model = i[1]
            permission = i[2]
            if app_label not in permissions:
                permissions[app_label] = {}
            if model not in permissions[app_label]:
                permissions[app_label][model] = []
            permissions[app_label][model].append(permission)
        
        permissions = mark_safe(json.dumps(permissions, sort_keys=True))

        return TemplateResponse(
            request, 
            'rbac/admin_effective_permissions.html',
            {
                'permissions': permissions,
                 'role': role
            }
        )
    
    def view_permissions_by_model(self, request):
        """
        Renders a table which shows all of the model permissions
        which are assigned to roles.
        """
        permissions = models.RbacPermission.objects.all().order_by(
                        'content_type__app_label', 'content_type__model', 'name'
                    ).select_related(
                        'content_type'
                    ).prefetch_related(
                        # Prefetching prevents quering the database for each permission
                        Prefetch('rbacrole_set')
                    ).exclude(rbacrole=None)
    
        permissions_by_content_type = OrderedDict()
        for permission in permissions:
            if permission.content_type not in permissions_by_content_type:
                permissions_by_content_type[permission.content_type] = []
            permissions_by_content_type[permission.content_type].append(permission)
        
        return TemplateResponse(
            request,
            'rbac/admin_model_permissions.html', 
            {'permissions_by_ctype': permissions_by_content_type}
        )
    

class RbacSsdAdmin(admin.ModelAdmin):
    filter_horizontal = ('roles', )    


class UserAssignmentAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)
    search_fields = ['user__username', 'roles__name']
    filter_horizontal = ('roles', )


admin.site.register(models.RbacRole, RoleAdmin)
admin.site.register(models.RbacPermission)
admin.site.register(models.RbacUserAssignment, UserAssignmentAdmin)
admin.site.register(models.RbacSsdSet, RbacSsdAdmin)
#admin.site.register(models.RoleChildren, RoleHierarchyAdmin)
