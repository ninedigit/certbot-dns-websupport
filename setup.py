# https://github.com/m42e/certbot-dns-ispconfig/blob/master/setup.py

from setuptools import setup
from setuptools import find_packages

version = "0.0.1"

install_requires=[
    "acme",
    "certbot",
    "requests",
    "setuptools",
    "requests",
    "mock",
    "requests-mock",
    "zope.interface"
]

# read the contents of your README file
from os import path

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.rst")) as f:
    long_description = f.read()

setup(
    name="certbot-dns-websupport",
    version=version,
    description="WebSupport.sk DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/ninedigit/certbot-dns-websupport",
    author="Nine Digit, s.r.o.",
    author_email="info@ninedigit.sk",
    license="MIT",
    python_requires=">=3.7",
    #package="certbot_dns_websupport.py",
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "certbot.plugins": [
            "dns-websupport = certbot_dns_websupport.dns_websupport:Authenticator"
        ],
    }
)
