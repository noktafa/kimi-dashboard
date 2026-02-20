# System Architecture Overview

## High-Level Architecture

```mermaid
flowchart TB
    subgraph User["👤 User Interface Layer"]
        CLI["Command Line Interface"]
        API["REST API"]
        DASH["Web Dashboard"]
    end

    subgraph Core["🔄 Convergence Loop Core"]
        SM["State Machine"]
        EB["Event Bus"]
        PL["Pipeline Orchestrator"]
        
        subgraph Steps["Pipeline Steps"]
            DIAG["1. Diagnose"]
            FIX["2. Fix"]
            ATT["3. Attack"]
            VAL["4. Validate"]
        end
    end

    subgraph Tools["🛠️ Security Tools"]
        AUDIT["Security Auditor"]
        ADMIN["Sysadmin AI"]
    end

    subgraph Data["💾 Data Layer"]
        DB[(SQLite/Event Store)]
        CFG[Configuration Files]
    end

    CLI --> PL
    API --> PL
    DASH --> EB
    
    PL --> SM
    PL --> EB
    SM --> Steps
    
    DIAG --> AUDIT
    FIX --> ADMIN
    ATT --> AUDIT
    VAL --> ADMIN
    
    AUDIT --> DB
    ADMIN --> DB
    EB --> DB
    
    style Core fill:#e1f5fe
    style Tools fill:#e8f5e9
    style Data fill:#fff3e0
```

## Component Architecture

### 1. Kimi Security Auditor

```mermaid
flowchart LR
    subgraph Input["Input"]
        URL["Target URL"]
        OPT["Scan Options"]
    end

    subgraph Scanner["Scanner Engine"]
        RECON["Reconnaissance"]
        SQL["SQL Injection"]
        CMD["Command Injection"]
        JWT["JWT Security"]
    end

    subgraph Output["Output"]
        FIND["Findings"]
        REP["Reports"]
    end

    URL --> RECON
    OPT --> Scanner
    
    RECON --> SQL
    RECON --> CMD
    RECON --> JWT
    
    SQL --> FIND
    CMD --> FIND
    JWT --> FIND
    
    FIND --> REP

    style Scanner fill:#ffebee
```

### 2. Kimi Sysadmin AI

```mermaid
flowchart TD
    subgraph Input["Command Input"]
        CMD["User Command"]
        CHAT["Chat Message"]
    end

    subgraph Safety["Safety Layer"]
        FILTER["Safety Filter"]
        POLICY["Policy Engine"]
        LLM["LLM Client"]
    end

    subgraph Execution["Execution Layer"]
        HOST["Host Executor"]
        DOCKER["Docker Executor"]
        K8S["Kubernetes Executor"]
    end

    CMD --> FILTER
    CHAT --> LLM
    
    FILTER --> POLICY
    POLICY -->|Allow| Execution
    POLICY -->|Deny| BLOCK["🚫 Blocked"]
    POLICY -->|Gray| CONFIRM["⚠️ Confirm"]
    
    CONFIRM -->|Approved| Execution
    
    LLM -->|Tool Call| Execution
    
    HOST --> OUT["Output"]
    DOCKER --> OUT
    K8S --> OUT

    style Safety fill:#e8f5e9
    style BLOCK fill:#ffebee
    style CONFIRM fill:#fff3e0
```

### 3. Kimi Convergence Loop

```mermaid
stateDiagram-v2
    [*] --> IDLE
    IDLE --> DIAGNOSING: START
    
    DIAGNOSING --> FIXING: DIAGNOSIS_COMPLETE
    DIAGNOSING --> FAILED: FAIL
    
    FIXING --> ATTACKING: FIX_COMPLETE
    FIXING --> FAILED: FAIL
    
    ATTACKING --> VALIDATING: ATTACK_COMPLETE
    ATTACKING --> FAILED: FAIL
    
    VALIDATING --> CONVERGED: CONVERGE
    VALIDATING --> IDLE: RETRY
    VALIDATING --> FAILED: FAIL
    
    CONVERGED --> [*]
    FAILED --> [*]
    
    note right of DIAGNOSING
        Run security audit
        Identify issues
    end note
    
    note right of FIXING
        Apply fixes using
        sysadmin-ai
    end note
    
    note right of ATTACKING
        Attempt to exploit
        vulnerabilities
    end note
    
    note right of VALIDATING
        Verify fixes work
        Check stability
    end note
```

### 4. Kimi Dashboard

```mermaid
flowchart LR
    subgraph Sources["Event Sources"]
        WS["WebSocket\nConvergence Loop"]
        API["REST API"]
        DB[(SQLite DB)]
    end

    subgraph Server["Dashboard Server"]
        HANDLER["Event Handler"]
        STATE["State Manager"]
        API_SRV["API Server"]
    end

    subgraph Frontend["Web Frontend"]
        UI["React UI"]
        CHARTS["Charts & Graphs"]
        LOGS["Live Logs"]
    end

    WS --> HANDLER
    HANDLER --> STATE
    STATE --> API_SRV
    DB --> API_SRV
    
    API_SRV --> UI
    UI --> CHARTS
    UI --> LOGS

    style Frontend fill:#e3f2fd
```

## Communication Patterns

### Event-Driven Architecture

```mermaid
sequenceDiagram
    participant CL as Convergence Loop
    participant EB as Event Bus
    participant DB as Database
    participant DASH as Dashboard
    
    CL->>EB: emit(STEP_STARTED)
    EB->>DB: persist(event)
    EB->>DASH: websocket broadcast
    DASH-->>User: UI update
    
    CL->>EB: emit(STEP_COMPLETE)
    EB->>DB: persist(event)
    EB->>DASH: websocket broadcast
    DASH-->>User: progress update
    
    CL->>EB: emit(CONVERGENCE_REACHED)
    EB->>DB: persist(event)
    EB->>DASH: websocket broadcast
    DASH-->>User: success notification
```

### Pipeline Execution Flow

```mermaid
sequenceDiagram
    participant User
    participant Pipeline
    participant Diagnose
    participant Fix
    participant Attack
    participant Validate
    
    User->>Pipeline: run()
    Pipeline->>Diagnose: execute()
    Diagnose-->>Pipeline: findings[]
    
    Pipeline->>Fix: execute(findings)
    Fix-->>Pipeline: fixes_applied[]
    
    Pipeline->>Attack: execute()
    Attack-->>Pipeline: vulnerabilities[]
    
    Pipeline->>Validate: execute()
    Validate-->>Pipeline: test_results
    
    alt Converged
        Pipeline-->>User: PipelineResult(converged=true)
    else More iterations needed
        Pipeline->>Pipeline: Next iteration
    end
```

## Deployment Architecture

### Standalone Deployment

```mermaid
flowchart TB
    subgraph Host["Single Host"]
        subgraph Docker["Docker Network"]
            AUDIT["kimi-security-auditor"]
            ADMIN["kimi-sysadmin-ai"]
            CONV["kimi-convergence-loop"]
            DASH["kimi-dashboard"]
            DB[(SQLite)]
        end
    end

    User["👤 User"] -->|CLI| AUDIT
    User -->|CLI| ADMIN
    User -->|CLI| CONV
    User -->|Browser| DASH
    
    CONV -->|WebSocket| DASH
    AUDIT --> DB
    ADMIN --> DB
    CONV --> DB

    style Host fill:#f5f5f5
```

### Distributed Deployment

```mermaid
flowchart TB
    subgraph Control["Control Plane"]
        CONV["kimi-convergence-loop"]
        DASH["kimi-dashboard"]
        DB[(PostgreSQL)]
        REDIS[(Redis)]
    end

    subgraph Workers["Worker Nodes"]
        W1["Auditor Worker 1"]
        W2["Auditor Worker 2"]
        W3["Sysadmin Worker"]
    end

    subgraph Targets["Target Systems"]
        T1["Web App 1"]
        T2["Web App 2"]
        T3["Infrastructure"]
    end

    CONV -->|Queue| REDIS
    REDIS --> W1
    REDIS --> W2
    REDIS --> W3
    
    W1 --> T1
    W2 --> T2
    W3 --> T3
    
    W1 --> DB
    W2 --> DB
    W3 --> DB
    CONV --> DB
    DASH --> DB

    style Control fill:#e3f2fd
    style Workers fill:#e8f5e9
    style Targets fill:#fff3e0
```

## Security Boundaries

```mermaid
flowchart TB
    subgraph Untrusted["Untrusted Zone"]
        WEB["Web Targets"]
        USER["External Users"]
    end

    subgraph DMZ["DMZ"]
        AUDIT["Security Auditor"]
        DASH["Dashboard"]
    end

    subgraph Trusted["Trusted Zone"]
        CONV["Convergence Loop"]
        ADMIN["Sysadmin AI"]
    end

    subgraph Restricted["Restricted Zone"]
        HOST["Host Systems"]
        K8S["Kubernetes"]
        DOCKER["Docker"]
    end

    USER -->|Scan| WEB
    AUDIT -->|Scan| WEB
    
    DASH -->|Monitor| CONV
    CONV -->|Orchestrate| ADMIN
    
    ADMIN -->|Execute| HOST
    ADMIN -->|Execute| K8S
    ADMIN -->|Execute| DOCKER

    style Untrusted fill:#ffebee
    style DMZ fill:#fff3e0
    style Trusted fill:#e8f5e9
    style Restricted fill:#e3f2fd
```

## Data Model

### Core Entities

```mermaid
erDiagram
    SESSION ||--o{ ITERATION : contains
    ITERATION ||--o{ STEP : contains
    STEP ||--o{ FINDING : produces
    STEP ||--o{ EVENT : generates
    
    SESSION {
        string session_id PK
        datetime start_time
        datetime end_time
        string target
        string status
        json config
    }
    
    ITERATION {
        string iteration_id PK
        string session_id FK
        int number
        datetime start_time
        datetime end_time
        string status
    }
    
    STEP {
        string step_id PK
        string iteration_id FK
        string type
        datetime start_time
        datetime end_time
        string status
        json result
    }
    
    FINDING {
        string finding_id PK
        string step_id FK
        string title
        string severity
        string description
        string target
        json metadata
    }
    
    EVENT {
        string event_id PK
        string session_id FK
        string type
        datetime timestamp
        json data
    }
```
