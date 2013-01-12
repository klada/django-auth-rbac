from django.contrib import admin
from rbac import models
from rbac.forms import RbacRoleForm, RbacUserAssignmentForm

"""
class TestAdmin(admin.StackedInline):
    model = models.RbacRoleChildren
    fk_name = 'parent'
    
class RoleAdmin(admin.ModelAdmin):
    #fieldsets = (
    #    (None, {'fields': ('name', 'description')}),
    #    (_('Permissions'), {'fields': ('permissions')}),
    #)
    fields = ['name', 'description', 'permissions', ]
    filter_horizontal = ('permissions', )
    inlines = [
        TestAdmin,
    ]
""" 
class RoleAdmin(admin.ModelAdmin):
    form = RbacRoleForm
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
