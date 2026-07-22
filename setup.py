from setuptools import setup, find_packages

setup(
    name="vulnpy",
    version="1.0.0",
    description="Professional Vulnerability Scanner",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "vulnpy=vulnpy.cli:app",
        ],
    },
    install_requires=[
        "typer[all]>=0.9.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "jinja2>=3.1.2",
        "reportlab>=4.0.0",
        "pydantic>=2.0.0",
    ],
)
