# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django import forms
from rbac.models import RbacRole, RbacPermissionProfile


class ActiveSessionRoleForm(forms.Form):
    """
    Form for activation/deactivation of roles within a RBAC session.
    """
    active_roles = forms.MultipleChoiceField(
        widget = forms.CheckboxSelectMultiple()
    )

    def __init__(self, session, *args, **kwargs):
        """
        @raise AttributeError: When instance was not specified.
        @raise TypeError: When instance is not valid.
        """
        self.session = session
        valid_roles = session.user.get_all_roles()
        super(ActiveSessionRoleForm, self).__init__(*args, **kwargs)
        self.fields['active_roles'].choices = valid_roles.values_list('pk', 'name')
        self.fields['active_roles'].initial = self.session.get_active_role_ids()

    def clean_active_roles(self):
        return self.session.user.get_all_roles().filter(id__in=self.cleaned_data['active_roles'])

    def save(self, *args, **kwargs):
        self.session.active_roles = self.cleaned_data['active_roles']
        self.session.save()
        return self.session


def _get_app_label_choices():
    app_labels = RbacPermissionProfile.objects.all().values_list(
                    'permission__content_type__app_label',
                    flat=True
                 ).distinct()
    choices = [('', '---------')]
    choices.extend([(i,i) for i in app_labels])
    return choices

def _get_model_choices():
    models = RbacPermissionProfile.objects.all().values_list(
                 'permission__content_type__model',
                 flat=True
             ).distinct()
    choices = [('', '---------')]
    choices.extend([(i,i) for i in models])
    return choices

class EffectivePermissionFilterForm(forms.Form):
    app_label = forms.ChoiceField(label="App", required=False, choices=_get_app_label_choices)
    model = forms.ChoiceField(label="Model", required=False, choices=_get_model_choices)


class RbacRoleForm(forms.ModelForm):
    """
    This form is displayed in the Django admin page for modifying RBAC roles.
    """

    class Meta:
        model = RbacRole
        exclude = ('children_all', )


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
