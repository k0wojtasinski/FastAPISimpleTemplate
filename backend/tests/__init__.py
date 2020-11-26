""" main module for unit tests
    it loads environment variables and provides some helper functions """
from pathlib import Path
import sys

from dotenv import load_dotenv

# loading .env configuration for unit tests
load_dotenv(Path("tests/test.env"))

# loading server directory for unit tests
sys.path.append(Path("../server"))
