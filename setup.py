# -*- coding: utf8 -*-
#
# Copyright (C) Cauly Kan, mail: cauliflower.kan@gmail.com
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.


'''
Created on 2018/1/13

@author: cauly
'''
from setuptools import find_packages, setup

setup(
    name='TracConfigurablePermissionPlugin', version='1.0',
    packages=find_packages(exclude=['*.tests*']),
    license = "BSD 3-Clause",
    author_email='cauliflower.kan@gmail.com',
    author='Cauly Kan',
    entry_points = {
        'trac.plugins': [
            'configurable_permission = configurable_permission',
        ],
    },
)
