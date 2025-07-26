"""Setup file for Linknode Security Tester."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="linknode-security-tester",
    version="2.0.0",
    author="Murray Kopit",
    author_email="murr2k@gmail.com",
    description="A comprehensive web application security testing framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/murr2k/linknode-security-tester",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "python-owasp-zap-v2.4>=0.0.21",
        "fastapi>=0.104.1",
        "uvicorn>=0.24.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "httpx>=0.25.2",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "lxml>=4.9.3",
        "selenium>=4.15.2",
        "webdriver-manager>=4.0.1",
        "jinja2>=3.1.2",
        "weasyprint>=60.1",
        "matplotlib>=3.7.5",
        "plotly>=5.18.0",
        "sqlalchemy>=2.0.23",
        "aiosqlite>=0.19.0",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "click>=8.1.7",
        "rich>=13.7.0",
        "tabulate>=0.9.0",
        "aiofiles>=23.2.1",
        "psutil>=5.9.6",
        "defusedxml>=0.7.1",
        "python-dateutil>=2.8.2",
        "validators>=0.22.0",
        "tenacity>=8.2.3",
        "cachetools>=5.3.2",
    ],
    entry_points={
        "console_scripts": [
            "lst=main:cli",
            "linknode-security-tester=main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/**/*", "config/**/*"],
    },
)