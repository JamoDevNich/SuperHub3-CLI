import setuptools;
import superhubclientsapi as project;

with open("README.md", "r") as fh:
    long_description = fh.read();

setuptools.setup(
    name="superhub3-cli",
    version=project.version,
    author="JamoDevNich",
    author_email="github@nich.dev",
    description="A command line interface for interacting with the Virgin Media SuperHub 3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/JamoDevNich/SuperHub3-CLI",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
);
