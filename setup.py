from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent
REQUIREMENTS = [
    line.strip()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="cloud-siem-grc-platform",
    version="1.0.0",
    description="Unified cloud security monitoring and compliance management platform",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Sansk",
    packages=find_packages(include=["src", "src.*"]),
    package_data={"src.api": ["static/*", "static/fonts/*"]},
    include_package_data=True,
    python_requires=">=3.12",
    install_requires=REQUIREMENTS,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
    ],
)
