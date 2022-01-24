from distutils.core import setup

setup(
    name="oci_enum",
    packages=["oci_enum"],
    version="0.1.1",
    license="MIT",
    description="CLI Tool by Orca Security to enumerate services in Oracle Cloud Infrastructure",
    author="Lidor Ben Shitrit, Tohar Braun",
    author_email="lidor@orca.security, tohar@orca.security",
    url="https://github.com/orcasecurity/orca-toolbox/tree/main/oci_enum",
    install_requires=["oci", "texttable"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    entry_points={
        "console_scripts": ["oci-enum=oci_enum.command_line:main"],
    },
)
