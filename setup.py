#!/usr/bin/env python3
"""
IOC Threat Scanner - Setup Configuration
Author: Adi Cohen
License: MIT
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f
                    if line.strip() and not line.startswith('#')]
    return ['PyQt6>=6.4.0', 'requests>=2.28.0', 'bytez>=0.1.0']

setup(
    name='ioc-threat-scanner',
    version='1.0.7',
    author='Adi Cohen',
    author_email='adi.cohen@example.com',  # Update with your email
    description='Professional IOC Threat Intelligence Platform',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/AdiZzZ0052/IOC-Threat-Scanner',
    project_urls={
        'Bug Reports': 'https://github.com/AdiZzZ0052/IOC-Threat-Scanner/issues',
        'Source': 'https://github.com/AdiZzZ0052/IOC-Threat-Scanner',
        'LinkedIn': 'https://www.linkedin.com/in/adi-cohen-ac/',
    },
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: X11 Applications :: Qt',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: System :: Networking :: Monitoring',
    ],
    keywords=[
        'ioc', 'threat-intelligence', 'security', 'malware',
        'virustotal', 'abuseipdb', 'otx', 'soc', 'incident-response',
        'cybersecurity', 'threat-hunting', 'phishing-detection'
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-qt>=4.2.0',
            'pytest-cov>=4.0.0',
            'flake8>=6.0.0',
            'black>=23.0.0',
            'mypy>=1.0.0',
            'bandit>=1.7.0',
        ],
    },
    py_modules=['ioc_scanner'],
    entry_points={
        'console_scripts': [
            'ioc-scanner=ioc_scanner:main',
        ],
        'gui_scripts': [
            'ioc-scanner-gui=ioc_scanner:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
)


def main():
    """Entry point for the application."""
    from ioc_scanner import IOCScannerApp
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)
    window = IOCScannerApp()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
