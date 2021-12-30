from setuptools import setup

setup(
   name='Azure-Managed-Identity-Explorer',
   version='0.1.0',
   author='Roee Sagi',
   author_email='roee@orca.security',
   scripts=['src/Managed-Identity-Explorer/azure_identity_credential_adapter.py', 'src/Managed-Identity-Explorer/main.py'],
   url='https://github.com/orcasecurity/orca-toolbox/Azure-Managed-Identity-Explorer/',
   description='Package for managed-identity misconfigurations detections',
   long_description=open('README.md').read(),
   install_requires=[
    "msrest",
    "azure.graphrbac",
    "azure.mgmt.authorization",
    "azure.core",
    "azure-cli-core"
   ],
)
