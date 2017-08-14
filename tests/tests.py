from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.test import TestCase
from django.test.utils import override_settings
from rbac import functions
from rbac.models import RbacPermissionProfile, RbacRoleProfile, RbacRole, RbacSsdSet, RbacPermission, RbacUser
from rbac.utils import testing

def skipWithoutRbacUser(func):
    """
    TestCase decorator which skips the test if an RBAC user is required
    but could not be loaded.
    """
    def _decorated(*args, **kwargs):
        self = args[0]
        model = get_user_model()
        if not issubclass(model, RbacUser):
            return self.skipTest('No RBAC user could be loaded')
        else:       
            return func(*args, **kwargs)
    return _decorated


@override_settings(RBAC_DEFAULT_ROLES = 'all', USE_TZ=False)
class RbacBackendTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super(RbacBackendTest, cls).setUpClass()
        # Create roles and assign permissions
        role_a = RbacRole.objects.create(name="Role A")
        role_a.permissions.add(RbacPermission.objects.get(name="opa"))
        role_b = RbacRole.objects.create(name="Role B")
        role_b.permissions.add(RbacPermission.objects.get(name="opb"))
        role_c = RbacRole.objects.create(name="Role C")
        role_c.permissions.add(RbacPermission.objects.get(name="opc"))
        role_d = RbacRole.objects.create(name="Role D")
        role_d.permissions.add(RbacPermission.objects.get(name="opd"))

        role_ssdone = RbacRole.objects.create(name="Role SSD 1")
        role_ssdone.permissions.add(RbacPermission.objects.get(name="opssd1"))

        role_ssdtwo = RbacRole.objects.create(name="Role SSD 2")
        role_ssdtwo.permissions.add(RbacPermission.objects.get(name="opssd2"))

        role_ssdthree = RbacRole.objects.create(name="Role SSD 3")
        role_ssdthree.permissions.add(RbacPermission.objects.get(name="opssd3"))

        role_ssdfour = RbacRole.objects.create(name="Role SSD 4")
        role_ssdfour.permissions.add(RbacPermission.objects.get(name="opssd4"))

        # Define role hierarchy
        # For a visualization of the test role graph see doc/test_role_graph.pdf
        role_a.children.add(role_b)
        role_a.children.add(role_ssdone)

        role_b.children.add(role_ssdtwo)

        role_c.children.add(role_d)

        role_d.children.add(role_ssdone)
        role_d.children.add(role_ssdthree)

        # Define SSD set
        ssdset = RbacSsdSet.objects.create(
            name="Test SSD", description="This SSD set is used for testing SSD enforcement", cardinality=4
        )
        ssdset.roles = RbacRole.objects.filter(name__startswith="Role SSD")

    def setUp(self):
        RbacRoleProfile.create()
        RbacPermissionProfile.create()

        #after loading fixtures we need to populate the role and permission
        # profiles first
        self.role_a = RbacRole.objects.get(name="Role A")
        self.role_b = RbacRole.objects.get(name="Role B")
        self.role_c = RbacRole.objects.get(name="Role C")
        self.role_d = RbacRole.objects.get(name="Role D")
        self.role_ssdone = RbacRole.objects.get(name="Role SSD 1")
        self.role_ssdtwo = RbacRole.objects.get(name="Role SSD 2")
        self.role_ssdthree = RbacRole.objects.get(name="Role SSD 3")
        self.role_ssdfour = RbacRole.objects.get(name="Role SSD 4")

        # We're using the RBAC user model and do not need any fixtures.
        self.user = get_user_model().objects.create(id=1, username="test")

        functions.AssignUser(self.user, self.role_a)
        functions.AssignUser(self.user, self.role_c)


    def tearDown(self):
        self.user = None

    
    @skipWithoutRbacUser
    def test_user_permission_basic(self):
        """
        Test basic permission assignment. If this test fails something is
        going extremely wrong...
        """
        #test all permissions
        self.assertTrue(self.user.has_perm('tests.opa_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opb_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opc_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opd_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opssd1_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opssd2_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opssd3_testmodel'))
        self.assertFalse(self.user.has_perm('tests.opssd4_testmodel'))
  

    @skipWithoutRbacUser
    def test_user_permission_role_deassign(self):
        """
        Deassign "Role A" and test permissions.
        """
        self.assertTrue(functions.DeassignUser(self.user, self.role_a))
        
        self.assertFalse(self.user.has_perm('tests.opa_testmodel'))
        self.assertFalse(self.user.has_perm('tests.opb_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opc_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opd_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opssd1_testmodel'))
        self.assertFalse(self.user.has_perm('tests.opssd2_testmodel'))
        self.assertTrue(self.user.has_perm('tests.opssd3_testmodel'))
        self.assertFalse(self.user.has_perm('tests.opssd4_testmodel'))

    
    @skipWithoutRbacUser
    def test_user_permission_after_hierarchy_change(self):
        """
        Test if permissions are inherited correctly after making changes in
        the role hierarchy.
        """
        #remove "Role B" from "Role A" and test permissions
        self.role_a.children.remove(self.role_b)
        self.assertEqual(self.user.has_perm('tests.opa_testmodel'), True)
        self.assertEqual(self.user.has_perm('tests.opb_testmodel'), False)
        self.assertEqual(self.user.has_perm('tests.opssd1_testmodel'), True)
        self.assertEqual(self.user.has_perm('tests.opssd2_testmodel'), False)
        
    
    @skipWithoutRbacUser
    def test_user_permission_after_hierarchy_change2(self):
        """
        Remove "Role B" from hierarchy and add it again.
        """
        self.role_a.children.remove(self.role_b)
        self.role_a.children.add(self.role_b)
        self.assertEqual(self.user.has_perm('tests.opa_testmodel'), True)
        self.assertEqual(self.user.has_perm('tests.opb_testmodel'), True)
        self.assertEqual(self.user.has_perm('tests.opssd1_testmodel'), True)
        self.assertEqual(self.user.has_perm('tests.opssd2_testmodel'), True)    


    def test_role_cycle_in_graph(self):
        """
        Test if trying to create a cycle in the role graph results in a
        ValidationError.
        """
        self.assertRaises(ValidationError, self.role_ssdthree.children.add, self.role_c)


    @skipWithoutRbacUser
    def test_ssd_enforcement(self):
        """
        Test if SSD is enforced when assigning roles to a user.
        """
        with transaction.atomic():
            self.assertRaises(ValidationError, functions.AssignUser, self.user, self.role_ssdfour)
        self.assertEqual(functions.DeassignUser(self.user, self.role_a), True)
        self.assertEqual(functions.AssignUser(self.user, self.role_ssdfour), True)
        with transaction.atomic():
            self.assertRaises(ValidationError, functions.AssignUser, self.user, self.role_a)

    def test_ssd_change_cardinality_simple(self):
        """
        Test if changes to the SSD cardinality are handled correctly.
        """
        #cardinality of 3 is invalid, as it affects a UserAssignment
        ssd_set = RbacSsdSet.objects.get(id=1)
        ssd_set.cardinality=3
        self.assertRaises(ValidationError, ssd_set.save)
        
        self.assertEqual(functions.DeassignUser(self.user, self.role_a), True)
        #the SSD set is valid now
        ssd_set.save()
        
        self.assertRaises(ValidationError, functions.AssignUser, self.user, self.role_a)
       
    
    def test_ssd_change_cardinality_direct(self):
        """
        This time we are removing the immediate inheritance relationship
        between "Role D" and "Role SSD3", change the SSD cardinality to 3
        and try to establish the inheritance again (which should raise a
        ValidationError).
        """
        ssd_set = RbacSsdSet.objects.get(id=1)
        ssd_set.cardinality=3
        self.assertRaises(ValidationError, ssd_set.save)
        
        self.assertEqual(functions.DeleteInheritance(self.role_d, self.role_ssdthree), True)
        ssd_set.save()
        
        self.assertRaises(ValidationError, functions.AddInheritance, self.role_d, self.role_ssdthree)


    def test_ssd_change_cardinality_intermediate(self):
        """
        This testcase is very similar to the one above. The only difference is
        that an entire subgraph containing a SSD role is removed (immediate
        inheritance relationship between "Role A" and "Role B").
        """
        ssd_set = RbacSsdSet.objects.get(id=1)
        ssd_set.cardinality=3
        self.assertRaises(ValidationError, ssd_set.save)
        
        self.assertEqual(functions.DeleteInheritance(self.role_a, self.role_b), True)
        ssd_set.save()
        
        self.assertRaises(ValidationError, functions.AddInheritance, self.role_a, self.role_b)


    def test_ssd_when_adding_child_roles(self):
        """
        Test if adding child roles to a RbacRole which would violate a SSD set
        are detected.
        """
        with transaction.atomic():
            self.assertRaises(ValidationError, functions.AddInheritance, self.role_b, self.role_ssdfour)
        
        self.assertEqual(functions.DeassignUser(self.user, self.role_a), True)
        self.assertEqual(functions.AddInheritance(self.role_b, self.role_ssdfour), True)
        with transaction.atomic():
            self.assertRaises(ValidationError, functions.AddInheritance, self.role_b, self.role_c)


class RbacUtilsTest(TestCase):
    """
    Tests for `rbac.utils`
    """
    def test_testing_context_manager(self):
        with testing.DisableRbacValidationContextManager():
            role_a = RbacRole.objects.create(name="Role A")
            role_a.permissions.add(RbacPermission.objects.get(name="opa"))
            role_b = RbacRole.objects.create(name="Role B")
            role_b.permissions.add(RbacPermission.objects.get(name="opb"))
            role_c = RbacRole.objects.create(name="Role C")

            role_a.children.add(role_b)

            # We have disconnected all relevant signal handlers, so the caches should be empty
            self.assertEqual(RbacRoleProfile.objects.count(), 0)
            self.assertEqual(RbacPermissionProfile.objects.count(), 0)

            # Since validation is disabled we should now be able to create invalid SSD constraints
            ssd_set = RbacSsdSet.objects.create(name="Test", cardinality=2)
            # This should usually trigger a ValidationError
            ssd_set.roles = RbacRole.objects.all()
            ssd_set.delete()

        # After leaving the context manager the caches should be populated
        self.assertGreater(RbacRoleProfile.objects.count(), 0)
        self.assertGreater(RbacPermissionProfile.objects.count(), 0)

        # ... and the SSD validation should be working again
        ssd_set = RbacSsdSet.objects.create(name="Test", cardinality=2)
        self.assertRaises(ValidationError, lambda: ssd_set.roles.add(*RbacRole.objects.all()))
