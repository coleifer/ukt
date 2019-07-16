import os
import warnings

from setuptools import setup
from setuptools.extension import Extension
try:
    from Cython.Build import cythonize
except ImportError:
    import warnings
    cython_installed = False
    warnings.warn('Cython not installed, using pre-generated C source file.')
else:
    cython_installed = True

try:
    from ukt import __version__
except ImportError:
    warnings.warn('could not import ukt module to determine version')
    __version__ = '0.0.0'


if cython_installed:
    python_source = 'ukt/serializer.pyx'
else:
    python_source = 'ukt/serializer.c'
    cythonize = lambda obj: obj


serializer = Extension(
    'ukt.serializer',
    #extra_compile_args=['-g', '-O0'],
    #extra_link_args=['-g'],
    sources=[python_source])


setup(
    name='ukt',
    version=__version__,
    description='lightweight kyototycoon client',
    long_description='lightweight kyototycoon client',
    author='Charles Leifer',
    author_email='',
    url='http://github.com/coleifer/ukt/',
    packages=['ukt'],
    ext_modules=cythonize([serializer]),
    test_suite='tests')
