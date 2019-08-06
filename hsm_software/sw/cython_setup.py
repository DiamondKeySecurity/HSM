import os
from setuptools import setup, find_packages
from distutils.extension import Extension
from Cython.Build import cythonize


def find_pyx(path='.'):
    extensions = []
    for root, dirs, filenames in os.walk(path):
        for fname in filenames:
            if fname.endswith('.pyx'):
                basename = os.path.splitext(fname)[0]
                extension_name = (os.path.join(root, basename)[2:]).replace('/','.')
                print extension_name
                extension = Extension(name=extension_name,
                                      sources=[os.path.join(root, fname)],
                                      extra_compile_args=['-lstdc++', "-std=c++17", '-lpthread'],
                                      language="c++")
                extensions.append(extension)
    return extensions


setup(
    name='dvedit',
    version='0.1',
    ext_modules=cythonize(find_pyx(), language_level=2),
    packages=find_packages(),
    )