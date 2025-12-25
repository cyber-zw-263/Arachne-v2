#!/bin/bash

# Arachne v2.0 Runner
# Usage: ./run_arachne.sh [target1 target2 ...]

set -e

echo "Starting Arachne v2.0..."

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo "$python_version < 3.9" | bc) -eq 1 ]]; then
    echo "Error: Python 3.9 or higher required (found $python_version)"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Installing dependencies..."
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Run setup if first time
if [ ! -f "config/targets.json" ]; then
    echo "First run detected. Running setup..."
    python3 setup.py
fi

# Run Arachne
if [ $# -eq 0 ]; then
    echo "Running with configured targets..."
    python3 arachne_core.py
else
    echo "Running with specified targets: $*"
    # Create temporary config for these targets
    python3 -c "
import json
import sys
targets = sys.argv[1:]
config = {
    'targets': [{'domain': t, 'scope': [f'*.{t}'], 'exclude': [], 'priority': 'high'} for t in targets],
    'global_settings': {
        'rate_limit': 10,
        'max_concurrent': 5,
        'respect_robots_txt': False,
        'auto_report': True
    }
}
with open('config/temp_targets.json', 'w') as f:
    json.dump(config, f, indent=2)
print('Temporary config created')
" "$@"
    ARACHNE_CONFIG=config/temp_targets.json python3 arachne_core.py
fi

deactivate
echo "Arachne completed."