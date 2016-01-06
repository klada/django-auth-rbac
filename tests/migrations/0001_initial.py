# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("rbac", "0001_initial")
    ]

    operations = [
        migrations.CreateModel(
            name='TestModel',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
            ],
            options={
                'permissions': (('opa', 'Operation allowed by role A'), ('opb', 'Operation allowed by role B'), ('opc', 'Operation allowed by role C'), ('opd', 'Operation allowed by role D'), ('opssd1', 'Operation allowed by role SSD1'), ('opssd2', 'Operation allowed by role SSD2'), ('opssd3', 'Operation allowed by role SSD3'), ('opssd4', 'Operation allowed by role SSD4')),
            },
        ),
    ]
