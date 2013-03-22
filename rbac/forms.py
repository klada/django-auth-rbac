from django import forms
from django.contrib.auth import get_user_model
from django.db.models import Q
from rbac.models import RbacRole, RbacSession, RbacUserAssignment

class ActiveSessionRoleForm(forms.ModelForm):
    """
    Form for activation/deactivation of roles within a RBAC session.
    """

    def __init__(self, *args, **kwargs):
        """
        @raise AttributeError: When instance was not specified.
        @raise TypeError: When instance is not valid.
        """
        if not 'instance' in kwargs:
            raise AttributeError('You need to pass a valid instance to this form.')
        
        instance=kwargs['instance']
        if not isinstance(instance, RbacSession):
            raise TypeError('You need to pass a valid instance to this form.')

        valid_roles = instance.user.get_all_roles() 
        super(ActiveSessionRoleForm, self).__init__(*args, **kwargs)
        self.fields['active_roles'].queryset = valid_roles


    class Meta:
        model = RbacSession
        fields = ('active_roles', )
        widgets = {
            'active_roles': forms.CheckboxSelectMultiple(),
        }


class RbacRoleForm(forms.ModelForm):
    """
    This form is displayed in the Django admin page for modifying RBAC roles.
    """

    class Meta:
        model = RbacRole


    def __init__(self, *args, **kwargs):
        super(RbacRoleForm, self).__init__(*args, **kwargs)
        #filter out invalid choices for children
        if self.instance:
            exclude_ids = [self.instance.id, ]
            for parent in self.instance.get_all_parents():
                exclude_ids.append(parent.id)
            self.fields['children'].queryset = RbacRole.objects.exclude(pk__in=exclude_ids)


    def clean_children(self):
        for child_role in self.cleaned_data['children']:
            if self.instance == child_role:
                raise forms.ValidationError("Adding this child role would result in a cycle in the role graph!")

            if child_role in self.instance.get_all_parents():
                raise forms.ValidationError("Adding this child role would result in a cycle in the role graph!")
        return self.cleaned_data['children']
