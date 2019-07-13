import os
from setuptools import setup


with open(os.path.join(os.path.dirname(__file__), 'README.md')) as fh:
    readme = fh.read()


setup(
    name='ukt',
    version=__import__('ukt').__version__,
    description='lightweight kyototycoon client',
    long_description=readme,
    author='Charles Leifer',
    author_email='coleifer@gmail.com',
    url='http://github.com/coleifer/ukt/',
    packages=[],
    py_modules=['ukt'],
    test_suite='tests')
