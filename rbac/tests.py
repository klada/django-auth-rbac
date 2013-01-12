from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from rbac import functions
from rbac import models

settings.RBAC_DEFAULT_ROLES = 'all'

class RbacBackendTest(TestCase):
    fixtures = [ 'test-users.json', 'test-permissions.json',
                 'test-roles.json', 'test-ssdsets.json',
                 'test-userassignments.json' ]
    
    
    def setUp(self):
        #after loading fixtures we need to populate the role and permission
        # profiles first
        models.RbacRoleProfile.create()
        models.RbacPermissionProfile.create()
        
        #get user with username=test
        self.user = get_user_model().objects.get(pk=2)
        
        self.role_a = models.RbacRole.objects.get(name="A")
        self.role_b = models.RbacRole.objects.get(name="B")
        self.role_c = models.RbacRole.objects.get(name="C")
        self.role_d = models.RbacRole.objects.get(name="D")
        self.role_ssdone = models.RbacRole.objects.get(name="SSD1")
        self.role_ssdtwo = models.RbacRole.objects.get(name="SSD2")
        self.role_ssdthree = models.RbacRole.objects.get(name="SSD3")
        self.role_ssdfour = models.RbacRole.objects.get(name="SSD4")
        
        self.perm_test_role_a = models.RbacPermission.objects.get(name="test_role_a")
        self.perm_test_role_b = models.RbacPermission.objects.get(name="test_role_b")
        self.perm_test_role_c = models.RbacPermission.objects.get(name="test_role_c")
        self.perm_test_role_d = models.RbacPermission.objects.get(name="test_role_d")
        self.perm_test_role_ssd_one = models.RbacPermission.objects.get(name="test_role_ssd_one")
        self.perm_test_role_ssd_two = models.RbacPermission.objects.get(name="test_role_ssd_two")
        self.perm_test_role_ssd_three = models.RbacPermission.objects.get(name="test_role_ssd_three")
        self.perm_test_role_ssd_four = models.RbacPermission.objects.get(name="test_role_ssd_four")

    
    def test_user_permission_basic(self):
        """
        Test basic permission assignment. If this test fails something is
        going extremely wrong...
        """
        #test all permissions
        self.assertEqual(self.user.has_perm(self.perm_test_role_a), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_b), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_c), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_d), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_one), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_two), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_three), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_four), False)

        #now deassign "Role A" and test again
        self.assertEqual(functions.DeassignUser(self.user, self.role_a), True)
        
        self.assertEqual(self.user.has_perm(self.perm_test_role_a), False)
        self.assertEqual(self.user.has_perm(self.perm_test_role_b), False)
        self.assertEqual(self.user.has_perm(self.perm_test_role_c), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_d), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_one), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_two), False)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_three), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_four), False)

        #assign "Role A" again
        self.assertEqual(functions.AssignUser(self.user, self.role_a), True)
        
        self.assertEqual(self.user.has_perm(self.perm_test_role_a), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_b), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_c), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_d), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_one), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_two), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_three), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_four), False)

    
    def test_user_permission_after_hierarchy_change(self):
        """
        Test if permissions are inherited correctly after making changes in
        the role hierarchy.
        """
        #remove "Role B" from "Role A" and test permissions
        self.role_a.children.remove(self.role_b)
        self.assertEqual(self.user.has_perm(self.perm_test_role_a), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_b), False)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_one), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_two), False)
        
        #add "Role B" again and test permissions
        self.role_a.children.add(self.role_b)
        self.assertEqual(self.user.has_perm(self.perm_test_role_a), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_b), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_one), True)
        self.assertEqual(self.user.has_perm(self.perm_test_role_ssd_two), True)


    def test_role_cycle_in_graph(self):
        """
        Test if trying to create a cycle in the role graph results in a
        ValidationError.
        """
        self.assertRaises(ValidationError, self.role_ssdthree.children.add, self.role_c)


    def test_ssd_enforcement(self):
        """
        Test if SSD is enforced when assigning roles to a user.
        """
        self.assertRaises(ValidationError, functions.AssignUser, self.user, self.role_ssdfour)
        self.assertEqual(functions.DeassignUser(self.user, self.role_a), True)
        self.assertEqual(functions.AssignUser(self.user, self.role_ssdfour), True)
        self.assertRaises(ValidationError, functions.AssignUser, self.user, self.role_a)


    def test_ssd_change_cardinality_simple(self):
        """
        Test if changes to the SSD cardinality are handled correctly.
        """
        #cardinality of 3 is invalid, as it affects a UserAssignment
        ssd_set = models.RbacSsdSet.objects.get(id=1)
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
        ssd_set = models.RbacSsdSet.objects.get(id=1)
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
        ssd_set = models.RbacSsdSet.objects.get(id=1)
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
        self.assertRaises(ValidationError, functions.AddInheritance, self.role_b, self.role_ssdfour)
        
        self.assertEqual(functions.DeassignUser(self.user, self.role_a), True)
        self.assertEqual(functions.AddInheritance(self.role_b, self.role_ssdfour), True)
        self.assertRaises(ValidationError, functions.AddInheritance, self.role_b, self.role_c)
