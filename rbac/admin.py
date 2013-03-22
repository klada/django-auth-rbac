from django.contrib import admin
from django.utils.translation import ugettext_lazy as _
from rbac import models
from rbac.forms import RbacRoleForm, RbacUserAssignmentForm

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
    filter_horizontal = ('permissions', 'children' )
    

class RbacSsdAdmin(admin.ModelAdmin):
    filter_horizontal = ('roles', )    


class UserAssignmentAdmin(admin.ModelAdmin):
    form = RbacUserAssignmentForm
    filter_horizontal = ('roles', )


admin.site.register(models.RbacRole, RoleAdmin)
admin.site.register(models.RbacPermission)
admin.site.register(models.RbacUserAssignment, UserAssignmentAdmin)
admin.site.register(models.RbacSsdSet, RbacSsdAdmin)
#admin.site.register(models.RoleChildren, RoleHierarchyAdmin)
