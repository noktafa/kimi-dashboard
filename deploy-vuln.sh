#!/bin/bash
# Deploy vulnerable target to DigitalOcean infrastructure

SSH_KEY="~/.ssh/kimi_ecosystem"

# Deploy to API servers
echo "Deploying to API servers..."
for IP in 178.128.117.238 152.42.220.203; do
    echo "  Deploying to $IP..."
    scp -o StrictHostKeyChecking=no -i $SSH_KEY -r /root/.openclaw/workspace/kimi-ecosystem/test-target root@$IP:/opt/vuln-app
    ssh -o StrictHostKeyChecking=no -i $SSH_KEY root@$IP "
        cd /opt/vuln-app
        docker build -t vuln-app .
        docker run -d -p 80:5000 --name vuln-app vuln-app
    "
done

# Deploy to DB server
echo "Deploying database..."
ssh -o StrictHostKeyChecking=no -i $SSH_KEY root@152.42.222.84 "
    docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=vulndb -e POSTGRES_DB=vulnapp --name postgres postgres:15
"

# Deploy to cache server  
echo "Deploying cache..."
ssh -o StrictHostKeyChecking=no -i $SSH_KEY root@167.71.196.196 "
    docker run -d -p 6379:6379 --name redis redis:7
"

LB_IP="167.172.71.245"

# Deploy load balancer
echo "Deploying load balancer..."
ssh -o StrictHostKeyChecking=no -i $SSH_KEY root@$LB_IP "
cat > /etc/nginx/nginx.conf << 'EOF'
events { worker_connections 1024; }
http {
    upstream backend {
        server 178.128.117.238;
        server 152.42.220.203;
    }
    server {
        listen 80;
        location / {
            proxy_pass http://backend;
        }
    }
}
EOF
    docker run -d -p 80:80 -v /etc/nginx/nginx.conf:/etc/nginx/nginx.conf:ro --name nginx nginx:alpine
"

echo "=== Deployment Complete ==="
echo "Load Balancer: http://$LB_IP"
