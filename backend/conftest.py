"""
Root conftest.py — adds the backend directory to sys.path so that
tests can import `from app.models import ...` without needing PYTHONPATH set.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
