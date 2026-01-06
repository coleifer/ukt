from setuptools import setup
from setuptools.extension import Extension
try:
    from Cython.Build import cythonize
    cython_installed = True
except ImportError:
    cython_installed = False

if cython_installed:
    python_source = 'ukt/serializer.pyx'
else:
    python_source = 'ukt/serializer.c'
    cythonize = lambda obj: obj


serializer = Extension('ukt.serializer', sources=[python_source])

setup(
    name='ukt',
    packages=['ukt'],
    ext_modules=cythonize([serializer]))
