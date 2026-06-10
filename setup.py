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

# Package discovery is configured in pyproject.toml; specifying packages here
# as well would override it and drop the ukt.scripts subpackage from dists.
setup(
    name='ukt',
    ext_modules=cythonize([serializer]))
