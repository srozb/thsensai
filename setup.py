""" Setup script for the 'thsensai' Python package. """

from setuptools import setup, find_packages

def parse_requirements(filename):
    """Load requirements from a pip requirements file."""
    with open(filename, encoding="utf-8") as f:
        return f.read().splitlines()

setup(
    name="thsensai",
    version="0.1.0",
    description="A library and CLI tool for AI-aided threat hunting and intelligence analysis.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="srozb",
    author_email="github@rozbicki.eu",
    url="https://github.com/srozb/thsensai",  # Replace with your repo URL
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=parse_requirements("requirements.txt"),
    entry_points={
        "console_scripts": [
            "sensai=thsensai.cli:app",
            "thsensai=thsensai.cli:app",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)