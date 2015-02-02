from django import template
from django.template.base import TemplateSyntaxError

register = template.Library()

class HasPermNode(template.Node):   
    def __init__(self, nodelist, user, obj, perm):
        self.nodelist = nodelist
        self.user = template.Variable(user)
        self.obj = template.Variable(obj)
        self.perm = perm
    
    def render(self, context):
        user = self.user.resolve(context)
        obj = self.obj.resolve(context)
        
        if user.has_perm(self.perm, obj):
            return self.nodelist.render(context)
        else:
            return ''

@register.tag
def hasperm(parser, token):
    """
    Can be used for looking up per-object permissions. Example:
    
    {% hasperm user_obj instance_obj "change" %}
     The user has change permissions for {{instance_obj}}.
    {% endhasperm %}
    """
    nodelist = parser.parse(('endhasperm',))
    parser.delete_first_token()
    try:
        tag_name, user, obj, perm = token.split_contents()
    except:
        raise TemplateSyntaxError('This block requires exactly three arguments.')
    
    if not (perm[0] == perm[-1] and perm[0] in ('"', "'")):
        raise template.TemplateSyntaxError("%r tag's argument should be in quotes" % tag_name)
    
    return HasPermNode(nodelist, user, obj, perm[1:-1])
