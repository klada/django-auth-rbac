#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='django-auth-rbac',
    version='0.3',
    description='An attempt of implementing role-based access control (ANSI/INCITS 359-2004) for Django',
    author='Daniel Klaffenbach',
    url='https://github.com/klada/django-auth-rbac',
    packages=find_packages(exclude=['tests', 'tests.*']),
    package_data = {
        'rbac': [
            'static/rbac/css/*',
            'locale/de/LC_MESSAGES/*',
            'templates/rbac/*'
        ]
    },
    python_requires='>3.5',
    install_requires=[
        'django>=2.2',
    ],
)
