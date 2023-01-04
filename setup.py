from setuptools import setup


requires = ["requests"]

packages = ["ReversingLabs",
            "ReversingLabs.SDK"]

with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="reversinglabs-sdk-py3",
    version="1.4.0",
    description="Python SDK for using ReversingLabs services - Python 3 version.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ReversingLabs",
    author_email="support@reversinglabs.com",
    url="https://github.com/reversinglabs/reversinglabs-sdk-py3",
    packages=packages,
    python_requires=">=3.6",
    install_requires=requires,
    license="MIT",
    zip_safe=False,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    project_urls={
        "Documentation": "https://github.com/reversinglabs/reversinglabs-sdk-py3/blob/main/README.md",
        "Source": "https://github.com/reversinglabs/reversinglabs-sdk-py3"
    },
)
