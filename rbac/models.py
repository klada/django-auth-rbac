from datetime import datetime, timedelta
from logging import getLogger
import itertools
from Queue import Queue

from django.db import connection, models
from django.db.models import Q
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.utils.timezone import utc
from django.utils.translation import ugettext_lazy as _

logger = getLogger("rbac.models")

class AbstractBaseModel(models.Model):
    touch_date = models.DateTimeField(editable=False, auto_now=True, auto_now_add=True)
    create_date = models.DateTimeField(editable=False, auto_now=True)

    class Meta:
        abstract = True
    
    
    def save(self, *args, **kwargs):
        self.full_clean()
        super(AbstractBaseModel, self).save(*args, **kwargs)


class RbacPermissionManager(models.Manager):
    """
    Manager class which supports get_by_natural_key().
    """
    
    def get_by_natural_key(self, name, app_label, model):
        return self.get(
            name=name,
            content_type=ContentType.objects.get_by_natural_key(app_label,
                                                                model)
        )


class RbacPermission(AbstractBaseModel):
    name = models.CharField(max_length=100, db_index=True, verbose_name=_("Name"))
    description = models.TextField(blank=True, verbose_name=_("Description"))
    content_type = models.ForeignKey(ContentType, verbose_name=_("Model"))
    objects = RbacPermissionManager()


    def __unicode__(self):
        return u"%s | %s | %s" % (
            unicode(self.content_type.app_label),
            unicode(self.content_type),
            unicode(self.name))


    class Meta:
        app_label = 'rbac'
        db_table = 'auth_rbac_permission'
        verbose_name = _("RBAC permission")
        verbose_name_plural = _("RBAC permissions")
        ordering = [ 'name' ]
        unique_together = (('content_type', 'name'),)
        ordering = ('content_type__app_label', 'content_type__model',
                    'name')
   
    def clean(self):
        import re

        pattern = '^[a-z][a-z\-]+[a-z]$'
        if re.match(pattern, self.name ) is None:
            raise ValidationError("Only lowercase characters and \"-\" are allowed!")

    def natural_key(self):
        return (self.name,) + self.content_type.natural_key()
    natural_key.dependencies = ['contenttypes.contenttype']


class RbacRole(AbstractBaseModel):
    """
    A role that can be assigned to users and other roles.
    """
    name = models.CharField(max_length=255, db_index=True, unique=True)
    description = models.TextField(blank=True)
    children =  models.ManyToManyField( 'self', symmetrical=False, blank=True)
    permissions = models.ManyToManyField(RbacPermission, blank=True)
    children_all = models.ManyToManyField( 'self', symmetrical=False, blank=True, editable=False, through="RbacRoleProfile", related_name="parents_all")


    def __unicode__(self):
        return self.name

    def __init__(self, *args, **kwargs):
        super(RbacRole, self).__init__(*args, **kwargs)

    class Meta:
        app_label = 'rbac'
        db_table = 'auth_rbac_role'
        verbose_name = _("RBAC role")
        verbose_name_plural = _("RBAC roles")
        ordering = [ 'name' ]

    def _get_all_parents_uncached(self):
        """
        Returns a list of all the parents.

        B{Note:} This method is only used internally and should not be called from outside!

        @returns:   set
        """
        parents = []
        for i in RbacRole.objects.filter( children=self ):
            parents.append( i )
            parents.extend( i._get_all_parents_uncached() )

        return set( parents )
    
    
    def _get_all_children_uncached(self):
        children = [] 
        for i in self.children.all():
            children.append(i)
            children.extend(i._get_all_children_uncached())
        return set(children)

    def get_all_children(self):
        """
        Returns a QuerySet containing all (direct and indirect) child roles.
        Note: Depends on RbacRoleProfile 
        
        @rtype: QuerySet
        """
        return self.children_all.all()
    
    def get_direct_children(self):
        """
        @rtype: QuerySet
        """
        return self.children.all()

    def get_all_parents(self):
        """
        Returns a QuerySet containing all (direct and indirect) parent roles.
        Note: Depends on RbacRoleProfile 
        
        @rtype: QuerySet
        """
        return RbacRole.objects.filter(children_all=self)

    def get_direct_parents(self):
        """
        @rtype: QuerySet
        """
        return RbacRole.objects.filter(children=self)
 

class RbacRoleProfile(AbstractBaseModel):
    """
    This model acts as a flat role hierarchy and serves as a cache.
    
    It caches all (direct and indirect) children of a role and can be used for
    both child and parent lookup.
    """
    parent = models.ForeignKey(RbacRole, db_index=True, related_name="rbacroleprofile_parent")
    child = models.ForeignKey(RbacRole, db_index=True, related_name="rbacroleprofile_child")

    class Meta:
        db_table = 'auth_rbac_roleprofile'
        unique_together = ('parent', 'child')
  
    def __unicode__(self):
        return u"%s: %s" %(self.parent, self.child)
  
    @staticmethod
    def create():
        """
        Creates a new RbacRoleProfile.
        
        A role profile is a cache which speeds up child/parent lookups for
        roles.
        """
        from django.db import transaction

        logger.debug("Creating RbacRoleProfile")
        if settings.USE_TZ:
            currentTime = datetime.utcnow().replace(tzinfo=utc)
        else:
            currentTime = datetime.now()


        #We want to read the entire hierarchy with one sql query. Since Django
        # does not support this we need to run a custom query.
        hierarchy_db_table = RbacRole.children.through._meta.db_table
        sql = "SELECT \
               from_rbacrole_id,\
               to_rbacrole_id \
              FROM\
               "+hierarchy_db_table

        adj_list = {}    
        bulk_list = []

        with transaction.commit_manually():
            cursor = connection.cursor()
            cursor.execute(sql)
            
            #create a adjacency list of the role hierarchy
            for role_pair in cursor.fetchall():
                if role_pair[0] in adj_list:
                    adj_list[role_pair[0]].append(role_pair[1])
                else:
                    adj_list[role_pair[0]]=[role_pair[1],]
            
            #Search for all child nodes which can be reached from parent through
            # a breadth-first-search.
            #Instead of coloring we're using a dict which keeps track of the
            # discovered nodes (@see: BFS)
            for parent in adj_list:
                child_queue = Queue()
                found = {}
                
                for child in adj_list[parent]:
                    child_queue.put_nowait(child)
                    found[child]=True
                                   
                while not child_queue.empty():
                    node = child_queue.get_nowait()
                    bulk_list.append(
                       RbacRoleProfile(
                                       parent_id=parent,
                                       child_id=node,
                                       touch_date=currentTime,
                                       create_date=currentTime
                                      )
                                    )
                    if node in adj_list:
                        for child in adj_list[node]:
                            if child not in found:
                                child_queue.put_nowait(child)
       
            #clear previous cache
            RbacRoleProfile.objects.all().delete()
            RbacRoleProfile.objects.bulk_create(bulk_list)
            transaction.commit()
        
        logger.debug("Finished creating RbacRoleProfile")


class RbacPermissionProfile(AbstractBaseModel):
    """
    The RbacPermissionProfile serves as a cache for role <-> permission relations.
    
    It parses the role graph and stores a role's permissions B{including permissions from child roles}.
    This makes permission lookups pretty fast - even when dealing with complex role graphs.
    """
    role = models.ForeignKey(RbacRole, db_index=True)
    permission = models.ForeignKey(RbacPermission, db_index=True)
    
        
    class Meta:
        app_label = 'rbac'
        db_table = 'auth_rbac_permissionprofile'
        unique_together = ('role', 'permission')
        verbose_name = _("RBAC role profile")
        verbose_name_plural = _("RBAC role profiles")
   

    def __unicode__(self):
        return u'%s: %s' %(self.role.name, self.permission.name)

    
    @staticmethod
    def create():
        """
        Creates a new RbacPermissionProfile.
        
        A role profile basically is a cache which speeds up permission lookups.
        """
        from django.db import transaction
        
        logger.debug("Creating RbacPermissionProfile")
        if settings.USE_TZ:
            currentTime = datetime.utcnow().replace(tzinfo=utc)
        else:
            currentTime = datetime.now()

        with transaction.commit_manually():
            #clear current permission profile
            RbacPermissionProfile.objects.all().delete()
    
            bulk_list = []
            for role in RbacRole.objects.all():
                for permission in RbacPermission.objects.filter(
                    Q(rbacrole=role) |
                    Q(rbacrole__parents_all=role)
                   ).distinct():
                    bulk_list.append(
                       RbacPermissionProfile(
                                             role=role,
                                             permission=permission,
                                             touch_date=currentTime,
                                             create_date=currentTime
                                             )
                                     )
      
            RbacPermissionProfile.objects.bulk_create(bulk_list)
            transaction.commit()
        logger.debug("Finished creating RbacPermissionProfile")


class RbacSession(AbstractBaseModel):
    """
    This model represents the RBAC session for a user. It allows the user to
    set active roles for a session.

    The default set of roles for a session can be controlled through the
    setting 'RBAC_DEFAULT_ROLES'.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, db_index=True)
    backend_session = models.BooleanField(default=True)
    active_roles = models.ManyToManyField(RbacRole)
    expire_date = models.DateTimeField(editable=False, auto_now=True)


    class Meta:
        db_table = 'auth_rbac_session'
        verbose_name = _("RBAC session")
        verbose_name_plural = _("RBAC sessions")


    def _activate_default_roles(self):
        if not self.user:
            return

        if hasattr(settings, "RBAC_DEFAULT_ROLES"):
            default_roles = settings.RBAC_DEFAULT_ROLES
            if isinstance(default_roles, str) and\
               default_roles.lower() == 'all':
                pass
            elif len(default_roles) > 0:
                self.active_roles=self.user.get_all_roles().filter(name__in=default_roles)
                return

        # Activate all of the user's roles, if settinigs.RBAC_DEFAULT_ROLES
        # was not set.
        self.active_roles=self.user.get_all_roles()


    def _has_perm(self, permission):
        """
        Checks if the specified permission can be obtained within this session.
        
        @type permission: RbacPermission
        @rtype: bool
        """
        return RbacPermissionProfile.objects.filter(
                   permission=permission,
                   role__in=self.active_roles.all()
               ).count() > 0
    
    
    def clean(self):
        if RbacSession.objects.filter(user=self.user, backend_session=True).exclude(id=self.pk).count() > 0:
            raise ValidationError('Only one backend session is allowed per user!')


    @staticmethod
    def clear_expired():
        """
        Removes expired RBAC sessions from the database.
        """
        if settings.USE_TZ:
            now = datetime.utcnow().replace(tzinfo=utc)
        else:
            now = datetime.now()
        RbacSession.objects.filter(expire_date__lt=now).delete()
    

    def save(self, *args, **kwargs):
        """
        Saves the session and assigns the default set of active roles for
        new sessions.
        """
        if self.pk:
            new_session = False
        else:
            new_session = True
        self.full_clean()
        super(RbacSession, self).save(*args, **kwargs)

        if new_session:
            self._activate_default_roles()


class RbacSsdSet(AbstractBaseModel):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    roles = models.ManyToManyField(RbacRole)
    cardinality = models.PositiveIntegerField(default=2)

    class Meta:
        db_table = 'auth_rbac_ssdset'
        verbose_name = _("RBAC Static Separation of Duty Constraint")
        verbose_name_plural = _("RBAC Static Separation of Duty Constraints")

    def clean(self):
        if self.cardinality < 2:
            raise ValidationError("The cardinality must be greater than or equal to 2.")
        
        #also make sure we are calling the validation function which validates
        # the m2m relation
        if self.pk:
            _rbac_check_ssd_userassignment(self.roles.all().values_list(
                                               'id',
                                               flat=True),
                                               self.cardinality
                                          )


class RbacUserAssignment(AbstractBaseModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, unique=True, db_index=True)
    roles = models.ManyToManyField(RbacRole)

    def __unicode__(self):
        return u'RBAC role assignment for user "%s"' %self.user

    class Meta:
        db_table = 'auth_rbac_userassignment'
        verbose_name = _("RBAC user assignment")
        verbose_name_plural = _("RBAC user assignments")


def _rbac_check_ssd_userassignment(ssd_roles_set, ssd_cardinality):
    """
    Checks if any of the current RbacUserAssignments would violate a SSD set
    with ssd_roles and ssd_cardinality.
    
    We are using raw SQL right here to drastically reduce the database load.
    A pure Django equivalent could look like this:
    
        ssd_roles_id = ssd_roles.values_list('id', flat=True)
        for ua in RbacUserAssignment.objects.all():
            ua_roles_id = list(ua.roles.all().values_list('id', flat=True))
            effective_roles_id = RbacRole.objects.filter(
                                            parents_all__in=ua_roles_id
                                        ).distinct().values_list('id', flat=True)
            
            effective_roles_id = list(effective_roles_id)                            
            effective_roles_id.extend(ua_roles_id)
            intersection = set(effective_roles_id).intersection(set(ssd_roles_id))
            if len(intersection) >= ssd_cardinality:
                raise ValidationError("One or more RbacUserAssignments would be affected by this change!")
    
    @param ssd_roles: A set of RbacRole ids
    @type ssd_roles: set
    @type ssd_cardinality: int
    @raise ValidationError: When the SSD set specified by the provided
    parameters would break an existing RbacUserAssignment. 
    """
    #get the ids of the roles which apply to this SSD set
    ssd_roles_id = ', '.join(itertools.imap(lambda x: str(x), ssd_roles_set))

    sql = "SELECT\
            COUNT(role_id) AS ssd_cardinality\
           FROM\
            (\
             SELECT\
              rbacuserassignment_id,\
              auth_rbac_roleprofile.child_id AS role_id\
             FROM\
              auth_rbac_userassignment_roles\
             LEFT OUTER JOIN\
              auth_rbac_roleprofile\
             ON\
              (auth_rbac_roleprofile.parent_id=auth_rbac_userassignment_roles.rbacrole_id)\
             WHERE\
              auth_rbac_roleprofile.child_id IN ("+ssd_roles_id+")\
             UNION \
             SELECT\
              rbacuserassignment_id,\
              auth_rbac_userassignment_roles.rbacrole_id AS role_id\
             FROM\
              auth_rbac_userassignment_roles\
             WHERE\
              auth_rbac_userassignment_roles.rbacrole_id IN ("+ssd_roles_id+")\
            )\
           GROUP BY\
            rbacuserassignment_id\
           HAVING\
            ssd_cardinality>=%s"
            
    cursor = connection.cursor()                
    cursor.execute(sql, [ssd_cardinality])
    if cursor.fetchone():
        raise ValidationError("One or more RbacUserAssignments would be affected by this change!")    


def _rbac_check_role_ssd_ua(node_id, ssd_roles_set, ssd_cardinality):
    """
    This function is called when adding new descendants to the I{role node_id}.
    It checks if any of the current RbacUserAssignment instamces would violate
    the SSD set with ssd_roles_set and ssd_cardinality.
        
    In order to keep the network and database load at a minimum we are using
    custom SQL here.
    
    The functionality is close to L{_rbac_check_ssd_userassignment}. The only
    difference is that we'll only check RbacUserAssignments which have the 
    role specified by I{node_id} in their effective roles.
    
    @param node_id: The ID of a RbacRole
    @type node_id: int 
    @param ssd_roles: A set of RbacRole ids
    @type ssd_roles: set
    @type ssd_cardinality: int
    @raise ValidationError: When the SSD set specified by the provided
    parameters would break an existing RbacUserAssignment. 
    """
    ssd_roles_id = ', '.join(itertools.imap(lambda x: str(x), ssd_roles_set))

    sql = "SELECT\
            COUNT(role_id) AS ssd_cardinality\
           FROM\
            (\
             SELECT\
              rbacuserassignment_id,\
              auth_rbac_roleprofile.child_id AS role_id\
             FROM\
              auth_rbac_userassignment_roles\
             LEFT OUTER JOIN\
              auth_rbac_roleprofile\
             ON\
              (auth_rbac_roleprofile.parent_id=auth_rbac_userassignment_roles.rbacrole_id)\
             WHERE\
              auth_rbac_roleprofile.child_id IN ("+ssd_roles_id+")\
             UNION \
             SELECT\
              rbacuserassignment_id,\
              auth_rbac_userassignment_roles.rbacrole_id AS role_id\
             FROM\
              auth_rbac_userassignment_roles\
             WHERE\
              auth_rbac_userassignment_roles.rbacrole_id IN ("+ssd_roles_id+")\
            )\
           WHERE\
            rbacuserassignment_id\
            IN\
             (\
              SELECT DISTINCT\
               rbacuserassignment_id\
              FROM\
               auth_rbac_userassignment_roles\
              LEFT OUTER JOIN\
               auth_rbac_roleprofile\
              ON\
               (auth_rbac_roleprofile.parent_id=auth_rbac_userassignment_roles.rbacrole_id)\
              WHERE\
               auth_rbac_userassignment_roles.rbacrole_id=%s\
              OR\
               auth_rbac_roleprofile.child_id=%s\
              )\
           GROUP BY\
            rbacuserassignment_id\
           HAVING\
            ssd_cardinality>=%s"
            
    cursor = connection.cursor()                
    cursor.execute(sql, [node_id, node_id, ssd_cardinality])
    if cursor.fetchone():
        raise ValidationError("One or more RbacUserAssignments would be affected by this change!")   


@receiver(models.signals.m2m_changed, sender=RbacRole.permissions.through)
def _rbac_role_permissions_changed(sender, instance, action, reverse, model, pk_set, **kwargs):
    """
    After adding/removing permissions we need to make sure to re-create the
    RbacPermissionProfile.
    """
    if action == 'post_add' or action == 'post_remove' or action == 'post_clear':
        RbacPermissionProfile.create()
    

@receiver(models.signals.m2m_changed, sender=RbacRole.children.through)
def _rbac_role_children_changed(sender, instance, action, reverse, model, pk_set, **kwargs):
    """
    Re-creates the RbacRoleProfile and RbacPermissionProfile after adding or
    removing child roles.
    """
    if action == 'post_add' or action == 'post_remove' or action == 'post_clear':
        RbacRoleProfile.create()
        #If the role hierarchy changed the permissions of parent roles could
        # also change. This is why we also re-create the permission profile.
        RbacPermissionProfile.create()


@receiver(models.signals.m2m_changed, sender=RbacSession.active_roles.through)
def _rbac_session_validate_roles(sender, instance, action, reverse, model, pk_set, **kwargs):
    """
    Makes sure that only valid roles are assigned to an RbacSession.

    @raise ValidationError: When trying to assign a role to a session which is
                            not assigned to the user.
    """
    if action == 'pre_add':
        if instance.user.get_all_roles().filter(id__in=pk_set).count() != len(pk_set):
            raise ValidationError(
               "At least one role is not assigned to the session user!")


@receiver(models.signals.m2m_changed, sender=RbacRole.children.through)
def _rbac_role_children_validate(sender, instance, action, reverse, model, pk_set, **kwargs):
    """
    Validates the children of a role prior to adding them.
    
        - check for cycle in the role graph.
        - check if adding a child role violates a SSD policy
    """   
    if action == 'pre_add':
        if instance.pk in pk_set:
            raise ValidationError("Adding this child role would result in a cycle in the role graph!")
        
        child_ids = RbacRole.objects.filter(
                        parents_all__in=pk_set
                    ).distinct().values_list('id', flat=True)
        parent_ids = RbacRole.objects.filter(
                         children_all=instance
                     ).distinct().values_list('id', flat=True)
        # The set of effective roles we're adding
        add_roles_eff_set = pk_set.union(child_ids)
        
        if len(add_roles_eff_set.intersection(parent_ids)) > 0:
            raise ValidationError("Adding this child role would result in a cycle in the role graph!")

        instance_children = instance.children_all.all().values_list('id', flat=True)
        # The set of all roles involved in this process (parents/children)
        involved_roles_set = add_roles_eff_set
        involved_roles_set = involved_roles_set.union(parent_ids)
        involved_roles_set = involved_roles_set.union(instance_children)
        involved_roles_set.add(instance.id)
        
        
        """
        We also need to make sure that existing RbacUserAssignments
        remain valid.
        
        This is what we do here:
            1. Get all of the parent roles and child roles (including the ones
               we're adding right now) of *instance*. -> *involved_roles_set*
            2. Select all SSD sets which apply to *involved_roles_set*
            3. For each *ssd_set* count how many roles of the SSD set apply to
               *involved_roles_set*.
            4. Get all of the RbacUserAssignments *uas* which have *instance*
               in their effective roles. 
            5. Count all of the roles of each RbacUserAssignment in *uas*
               which are part of the current *ssd_set*, excluding the
               ones we've just counted in the third step.
            6. If the sum of the values from steps #3 and #5 is less
               than *ssd_set.cardinality*, we are good. Otherwise
               we'll need to raise a ValidationError.
               
        For performance reasons some of these steps need custom SQL.
        """
        #Check if the graph violates a SSD constraint
        for ssd_set in RbacSsdSet.objects.filter(
                           roles__in=add_roles_eff_set
                       ):
            ssd_roles_set = set(ssd_set.roles.all().values_list('id', flat=True))
            ssd_roles_involved_set = involved_roles_set.intersection(ssd_roles_set)
            cardinality = len(ssd_roles_involved_set)

            if cardinality >= ssd_set.cardinality:
                raise ValidationError("Cannot add child role due to SSD policy!")
                            
            #now check the RbacUserAssignment instances
            ua_ssd_roles = ssd_roles_set.difference(ssd_roles_involved_set)
            max_ua_cardinality = ssd_set.cardinality - cardinality            
            _rbac_check_role_ssd_ua(instance.id, ua_ssd_roles, max_ua_cardinality)
                            

@receiver(models.signals.m2m_changed, sender=RbacSsdSet.roles.through)
def _rbac_ssd_validation(sender, instance, action, pk_set, **kwargs):
    """
    Validates a SSD set.
    
    @TODO: Validate on pre_delete
    """
    if action == 'pre_add':       
        roles = RbacRole.objects.filter(Q(id__in=instance.roles.all()) |
                                        Q(id__in=pk_set)).distinct()

        if roles.count() < 2:
            raise ValidationError("Two or more roles are required for a SSD set.")
        
        if roles.count() < instance.cardinality:
            raise ValidationError(
               "The cardinality of a SSD set must be less than or equal to the"
               " number of it's roles.")
        
        if RbacRoleProfile.objects.filter(parent__in=roles, child__in=roles).count() > 0:
            raise ValidationError(
               "Failed to create SSD Set. Some of the specified roles are in a"
               " parent<->child relation."
            )
            
        _rbac_check_ssd_userassignment(roles.values_list('id', flat=True), instance.cardinality)


@receiver(models.signals.m2m_changed, sender=RbacUserAssignment.roles.through)
def _rbac_ssd_enforcement(instance, action, pk_set, **kwargs):
    """
    Enforces the Static Separation of Duty constraints when adding roles
    to a user.    
    """
    if action == 'pre_add':
        
        user_roles = RbacRole.objects.filter(\
                            models.Q(id__in=instance.user.get_all_roles()) | \
                            models.Q(id__in=pk_set)).distinct()
        user_roles_id=list(user_roles.values_list('id', flat=True))
        user_childroles_id = list(RbacRoleProfile.objects.filter(parent__id__in=user_roles_id).values_list('child', flat=True))
        user_roles_id.extend(user_childroles_id)
        sql_in = ', '.join(itertools.imap(lambda x: str(x), set(user_roles_id)))
        
        sql = "SELECT\
                SUM(CASE WHEN auth_rbac_ssdset_roles.rbacrole_id IN ("+sql_in+") THEN 1 ELSE 0 END)\
                AS ssd_cardinality,\
                auth_rbac_ssdset.cardinality\
                AS max_ssd_cardinality\
               FROM\
                auth_rbac_ssdset_roles\
               LEFT OUTER JOIN\
                auth_rbac_userassignment_roles\
               ON\
                (auth_rbac_userassignment_roles.rbacrole_id=auth_rbac_ssdset_roles.rbacrole_id)\
               LEFT OUTER JOIN\
                auth_rbac_ssdset\
               ON\
                (auth_rbac_ssdset_roles.rbacssdset_id=auth_rbac_ssdset.id)\
               GROUP BY\
                auth_rbac_ssdset_roles.rbacssdset_id\
               HAVING\
                ssd_cardinality>=max_ssd_cardinality"
        cursor = connection.cursor()
        cursor.execute(sql)
        if cursor.fetchone():
            raise ValidationError(
               "A static separation of duty policy prevents you from adding"
               " this role!")

@receiver(models.signals.m2m_changed, sender=RbacUserAssignment.roles.through)
def _rbac_userassignment_roles_changed(sender, instance, action, reverse, model, pk_set, **kwargs):
    """
    When roles were added or removed from the RbacUserAssignment we also have
    to add/remove them from the user's sessions.
    """
    if action == 'post_add':
        RbacSession.objects.filter(user=instance.user, backend_session=True).delete()
    
    if action == 'post_remove':
        RbacSession.objects.filter(user=instance.user, active_roles__in=pk_set).delete()
    
    if action == 'post_clean':
        RbacSession.objects.filter(user=instance.user).delete()


@receiver(models.signals.post_delete, sender=RbacUserAssignment)
def _rbac_userassignment_delete(sender, instance, **kwargs):
    """
    Makes sure that RbacSessions are invalidated when removing a
    RbacUserAssignment.
    """
    RbacSession.objects.filter(user=instance.user).delete()

