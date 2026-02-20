# CI/CD Integration Examples

## GitHub Actions

### Basic Security Scan

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Kimi Security Auditor
        run: pip install kimi-security-auditor

      - name: Run security scan
        run: |
          kimi-audit https://staging.example.com \
            -f sarif \
            -o security-report.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-report.sarif
```

### Full Convergence Pipeline

```yaml
# .github/workflows/convergence.yml
name: Convergence Loop

on:
  workflow_dispatch:  # Manual trigger
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  converge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Kimi Ecosystem
        run: |
          pip install kimi-security-auditor
          pip install kimi-sysadmin-ai
          pip install kimi-convergence-loop

      - name: Run convergence loop
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          kimi-converge run --config .kimi/convergence.yaml

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: convergence-results
          path: reports/
```

### Pre-deployment Check

```yaml
# .github/workflows/pre-deploy.yml
name: Pre-deployment Security Check

on:
  deployment: {}

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Install auditor
        run: pip install kimi-security-auditor

      - name: Run security check
        run: |
          kimi-audit https://staging.example.com \
            --fail-on critical \
            --fail-on high
```

## GitLab CI

### Basic Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - security
  - converge

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip
    - venv/

security_scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install kimi-security-auditor
  script:
    - kimi-audit https://$CI_ENVIRONMENT_URL -f sarif -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - security-report.md
  only:
    - schedules
    - web

convergence:
  stage: converge
  image: python:3.11-slim
  before_script:
    - pip install kimi-security-auditor kimi-sysadmin-ai kimi-convergence-loop
  script:
    - kimi-converge run --config .kimi/convergence.yaml
  artifacts:
    paths:
      - reports/
  only:
    - schedules
```

## Jenkins

### Pipeline Script

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        OPENAI_API_KEY = credentials('openai-api-key')
    }
    
    stages {
        stage('Install') {
            steps {
                sh 'pip install kimi-security-auditor kimi-convergence-loop'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    kimi-audit https://staging.example.com \
                        -f sarif \
                        -o security-report.sarif
                '''
            }
        }
        
        stage('Convergence') {
            steps {
                sh 'kimi-converge run --config convergence.yaml'
            }
        }
        
        stage('Publish Reports') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'index.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
    }
}
```

## Azure DevOps

### Pipeline Configuration

```yaml
# azure-pipelines.yml
trigger:
  - main

schedules:
  - cron: "0 2 * * *"
    displayName: Daily security scan
    branches:
      include:
        - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
    displayName: 'Use Python 3.11'

  - script: |
      pip install kimi-security-auditor kimi-convergence-loop
    displayName: 'Install Kimi Ecosystem'

  - script: |
      kimi-audit https://$(targetUrl) \
        -f sarif \
        -o $(Build.ArtifactStagingDirectory)/security-report.sarif
    displayName: 'Run Security Scan'
    env:
      targetUrl: $(stagingUrl)

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'security-reports'

  - script: |
      kimi-converge run --config convergence.yaml
    displayName: 'Run Convergence Loop'
    env:
      OPENAI_API_KEY: $(openaiApiKey)
```

## CircleCI

### Configuration

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install Kimi
          command: pip install kimi-security-auditor
      - run:
          name: Run Security Scan
          command: |
            kimi-audit https://example.com \
              -f sarif \
              -o /tmp/security-report.sarif
      - store_artifacts:
          path: /tmp/security-report.sarif

  convergence:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install Kimi Ecosystem
          command: |
            pip install kimi-security-auditor
            pip install kimi-sysadmin-ai
            pip install kimi-convergence-loop
      - run:
          name: Run Convergence
          command: kimi-converge run --config .kimi/convergence.yaml

workflows:
  version: 2
  security:
    triggers:
      - schedule:
          cron: "0 0 * * 0"
          filters:
            branches:
              only:
                - main
    jobs:
      - security-scan
      - convergence
```

## Custom Integration

### Python Script for CI/CD

```python
#!/usr/bin/env python3
"""CI/CD integration script for Kimi Ecosystem."""

import asyncio
import sys
import os
from kimi_security_auditor import SecurityAuditor
from kimi_security_auditor.models import Severity

async def ci_security_check():
    """Run security check for CI/CD pipeline."""
    
    target = os.environ.get('TARGET_URL', 'https://staging.example.com')
    fail_on_critical = os.environ.get('FAIL_ON_CRITICAL', 'true').lower() == 'true'
    fail_on_high = os.environ.get('FAIL_ON_HIGH', 'false').lower() == 'true'
    
    print(f"🔍 Running security check on {target}...")
    
    auditor = SecurityAuditor(target)
    result = await auditor.run()
    
    # Generate report
    summary = result.get_summary()
    print("\n📊 Security Scan Results:")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
    
    # Check failure conditions
    failed = False
    
    if fail_on_critical and summary['critical'] > 0:
        print(f"\n❌ FAILED: {summary['critical']} critical vulnerabilities found")
        failed = True
    
    if fail_on_high and summary['high'] > 0:
        print(f"\n❌ FAILED: {summary['high']} high vulnerabilities found")
        failed = True
    
    # Save report
    report_path = os.environ.get('REPORT_PATH', 'security-report.json')
    with open(report_path, 'w') as f:
        f.write(result.to_json(indent=2))
    print(f"\n📄 Report saved to {report_path}")
    
    if failed:
        sys.exit(1)
    
    print("\n✅ Security check passed")

if __name__ == '__main__':
    asyncio.run(ci_security_check())
```

## Best Practices

1. **Schedule Regular Scans**: Run security scans daily or weekly
2. **Gate Deployments**: Block deployments if critical vulnerabilities found
3. **Track Trends**: Monitor vulnerability trends over time
4. **Alert on Changes**: Notify team when new vulnerabilities discovered
5. **Document Exceptions**: Document accepted risks with justification
