#!/usr/bin/env python3

# Used to install library requirements for "webscanner.py"

requirements = [
    "asyncio",
    "aiohttp",
    "ipaddress",
    "resource"
]

def install_requirements():
    import subprocess

    for requirement in requirements:
        subprocess.call(["pip", "install", requirement])

if __name__ == "__main__":
    install_requirements()
