from django.db.models import Model

class TestModel(Model):
    """
    This is a dummy model only used for testing.
    """
    class Meta:
        permissions = (
            ('opa', 'Operation allowed by role A'),
            ('opb', 'Operation allowed by role B'),
            ('opc', 'Operation allowed by role C'),
            ('opd', 'Operation allowed by role D'),
            ('opssd1', 'Operation allowed by role SSD1'),
            ('opssd2', 'Operation allowed by role SSD2'),
            ('opssd3', 'Operation allowed by role SSD3'),
            ('opssd4', 'Operation allowed by role SSD4'),
        )

