import setuptools
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="ctftools",
    version="0.1.2",
    author="Pietro Ferretti",
    author_email="me@pietroferretti.com",
    description="A small collection of tools for solving CTF challenges",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pietroferretti/ctftools",
    license="MIT",
    packages=setuptools.find_packages(exclude=["tests", "data"]),
    package_data={"ctftools": ["data/english_words.txt"]},
    install_requires=["six"],
    extras_require={
        "tests": ["pytest", "pycrypto"]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
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
        "Source": "https://github.com/pietroferretti/ctftools"
    },
)
