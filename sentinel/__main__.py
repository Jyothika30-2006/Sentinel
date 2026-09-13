"""Allow `python -m sentinel ...` to run the agent."""
import sys
from sentinel.main import main

if __name__ == "__main__":
    sys.exit(main())
