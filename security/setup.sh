#!/bin/bash
# Setup script for Kimi Ecosystem Security

set -e

echo "========================================"
echo "Kimi Ecosystem Security Setup"
echo "========================================"
echo

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo
echo "========================================"
echo "Generating TLS Certificates"
echo "========================================"

# Create certs directory
mkdir -p certs

# Generate certificates
python3 shared/generate_certs.py --output-dir certs

echo
echo "========================================"
echo "Generating API Keys"
echo "========================================"

# Generate API keys for each service
python3 shared/generate_api_key.py --no-save admin admin
echo
python3 shared/generate_api_key.py --no-save operator operator
echo
python3 shared/generate_api_key.py --no-save viewer viewer
echo

echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo
echo "Next steps:"
echo "1. Set environment variables for each service:"
echo
echo "   # Security Auditor"
echo "   export SECURITY_AUDITOR_TLS_CERT=$SCRIPT_DIR/certs/security-auditor/tls.crt"
echo "   export SECURITY_AUDITOR_TLS_KEY=$SCRIPT_DIR/certs/security-auditor/tls.key"
echo "   export SECURITY_AUDITOR_TLS_CA=$SCRIPT_DIR/certs/ca.crt"
echo "   export SECURITY_AUDITOR_JWT_SECRET=\$(openssl rand -base64 32)"
echo
echo "   # SysAdmin AI"
echo "   export SYSADMIN_AI_TLS_CERT=$SCRIPT_DIR/certs/sysadmin-ai/tls.crt"
echo "   export SYSADMIN_AI_TLS_KEY=$SCRIPT_DIR/certs/sysadmin-ai/tls.key"
echo "   export SYSADMIN_AI_TLS_CA=$SCRIPT_DIR/certs/ca.crt"
echo "   export SYSADMIN_AI_JWT_SECRET=\$(openssl rand -base64 32)"
echo
echo "   # Convergence Loop"
echo "   export CONVERGENCE_LOOP_TLS_CERT=$SCRIPT_DIR/certs/convergence-loop/tls.crt"
echo "   export CONVERGENCE_LOOP_TLS_KEY=$SCRIPT_DIR/certs/convergence-loop/tls.key"
echo "   export CONVERGENCE_LOOP_TLS_CA=$SCRIPT_DIR/certs/ca.crt"
echo "   export CONVERGENCE_LOOP_JWT_SECRET=\$(openssl rand -base64 32)"
echo
echo "   # Dashboard"
echo "   export DASHBOARD_TLS_CERT=$SCRIPT_DIR/certs/dashboard/tls.crt"
echo "   export DASHBOARD_TLS_KEY=$SCRIPT_DIR/certs/dashboard/tls.key"
echo "   export DASHBOARD_TLS_CA=$SCRIPT_DIR/certs/ca.crt"
echo "   export DASHBOARD_JWT_SECRET=\$(openssl rand -base64 32)"
echo
echo "2. Start the services:"
echo
echo "   # Terminal 1 - Security Auditor"
echo "   cd $SCRIPT_DIR/kimi-security-auditor/src && python main.py"
echo
echo "   # Terminal 2 - SysAdmin AI"
echo "   cd $SCRIPT_DIR/kimi-sysadmin-ai/src && python main.py"
echo
echo "   # Terminal 3 - Convergence Loop"
echo "   cd $SCRIPT_DIR/kimi-convergence-loop/src && python main.py"
echo
echo "   # Terminal 4 - Dashboard"
echo "   cd $SCRIPT_DIR/kimi-dashboard/src && python main.py"
echo
echo "3. Access the dashboard at:"
echo "   https://localhost:8766"
echo
echo "   Default credentials:"
echo "   - admin / admin (full access)"
echo "   - operator / operator (can execute commands)"
echo "   - viewer / viewer (read-only)"
echo
echo "4. Test API access:"
echo "   curl -k -H 'X-API-Key: <your-api-key>' https://localhost:8000/health"
echo