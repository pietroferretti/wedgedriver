import setuptools
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    requirements = f.read().strip().split('\n')

setuptools.setup(
    name="wedgedriver",
    version="0.1.2",
    author="Pietro Ferretti",
    author_email="pietro.ferretti1@gmail.com",
    description="A collection of tools to break common cryptography weaknesses",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pietroferretti/wedgedriver",
    license="MIT",
    packages=setuptools.find_packages(exclude=["tests", "data"]),
    package_data={"wedgedriver": ["data/english_words.txt"]},
    install_requires=requirements,
    extras_require={
        "rsa": ["gmpy"],
        "tests": ["pytest", "pycryptodome"]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"
    ],
    keywords="ctf security cryptography",
    project_urls={
        "Source": "https://github.com/pietroferretti/wedgedriver"
    },
)
