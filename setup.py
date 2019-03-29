import setuptools

with open("README.md", "r") as readme:
    long_description = readme.read()

setuptools.setup(
    name         = "xply",
    version      = "0.1.1",
    author       = "Tobias Holl",
    author_email = "tobias.holl@tum.de",
    description  = "An exploit development framework for Python 3",
    url          = "https://github.com/tobiasholl/xply",
    packages     = setuptools.find_packages(),
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    long_description = long_description,
    long_description_content_type = "text/markdown",
)

