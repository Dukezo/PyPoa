import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pypoa",
    version="1.0.1",
    author="Dukezo",
    author_email="Dukezo@web.de",
    description="A python implementation of the Oracle Padding Attack",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Dukezo/pypoa",
    py_modules=["pypoa"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.0',
)