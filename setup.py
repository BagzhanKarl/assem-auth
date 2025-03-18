from setuptools import setup, find_packages

# Read the contents of README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="assem",
    version="0.1.0",
    author="Bagzhan Karl",
    author_email="bagzhankarl@gmail.com",
    description="A flexible and secure JWT authentication framework for FastAPI applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BagzhanKarl/assem-auth",
    project_urls={
        "Bug Tracker": "https://github.com/BagzhanKarl/assem-auth/issues",
        "Documentation": "https://github.com/BagzhanKarl/assem-auth",
        "Source Code": "https://github.com/BagzhanKarl/assem-auth",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: FastAPI",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
    ],
    package_data={
        "assem": ["py.typed"],
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.7",
    install_requires=[
        "fastapi>=0.68.0",
        "pydantic>=1.8.0",
        "jwt",
        "starlette>=0.14.2",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-asyncio>=0.15.0",
            "black>=21.5b2",
            "isort>=5.9.1",
            "mypy>=0.910",
            "flake8>=3.9.2",
            "uvicorn>=0.14.0",
        ],
    },
)