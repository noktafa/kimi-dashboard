#!/bin/bash
# Deploy kimi ecosystem to DigitalOcean droplet

DROPLET_IP="152.42.182.107"
SSH_KEY="~/.ssh/kimi_ecosystem"

echo "=== Deploying Kimi Ecosystem to $DROPLET_IP ==="

# Wait for SSH to be ready
echo "Waiting for SSH..."
for i in {1..30}; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i $SSH_KEY root@$DROPLET_IP "echo 'ready'" 2>/dev/null; then
        break
    fi
    echo -n "."
    sleep 5
done
echo

# Copy ecosystem files
echo "Copying files..."
scp -r -i $SSH_KEY /root/.openclaw/workspace/kimi-ecosystem root@$DROPLET_IP:/opt/

# Deploy with Docker Compose
echo "Deploying..."
ssh -i $SSH_KEY root@$DROPLET_IP "
cd /opt/kimi-ecosystem/docker
./start.sh
"

echo "=== Deployment Complete ==="
echo "Dashboard: http://$DROPLET_IP"
echo "API: http://$DROPLET_IP/api/"
