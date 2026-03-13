from setuptools import setup, find_packages

setup(
    name="gdpr-flow-validator",
    version="1.0.0",
    description="GDPR Cross-Border Data Transfer Flow Validator — Yuno Engineering Challenge",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
    ],
    entry_points={
        "console_scripts": [
            "gdpr-validator=gdpr_validator.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
