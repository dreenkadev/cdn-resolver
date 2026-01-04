#!/usr/bin/env python3
"""Cdn Resolver - Entry Point"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run main from core
from core import main

if __name__ == "__main__":
    main()
