#!/bin/bash
# Kimi Ecosystem Convergence Demo Runner
# ========================================
#
# One-command demo runner for the convergence loop demonstration.
# Scans the vulnerable infrastructure and generates reports.
#
# Usage:
#   ./run_demo.sh [options]
#
# Options:
#   --format {markdown,json,both}   Output format (default: both)
#   --report-dir DIR                Report output directory (default: reports)
#   --no-display                    Skip console display
#   --help                          Show this help message
#
# Examples:
#   ./run_demo.sh                          # Run full demo with both formats
#   ./run_demo.sh --format markdown        # Generate only markdown report
#   ./run_demo.sh --report-dir ./output    # Save reports to ./output

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
FORMAT="both"
REPORT_DIR="reports"
NO_DISPLAY=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --report-dir)
            REPORT_DIR="$2"
            shift 2
            ;;
        --no-display)
            NO_DISPLAY="--no-display"
            shift
            ;;
        --help|-h)
            echo "Kimi Ecosystem Convergence Demo Runner"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --format {markdown,json,both}   Output format (default: both)"
            echo "  --report-dir DIR                Report output directory (default: reports)"
            echo "  --no-display                    Skip console display"
            echo "  --help, -h                      Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                          # Run full demo with both formats"
            echo "  $0 --format markdown        # Generate only markdown report"
            echo "  $0 --report-dir ./output    # Save reports to ./output"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_PY="$SCRIPT_DIR/demo.py"

# Check if demo.py exists
if [ ! -f "$DEMO_PY" ]; then
    echo -e "${RED}Error: demo.py not found at $DEMO_PY${NC}"
    exit 1
fi

# Check Python availability
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is required but not installed${NC}"
    exit 1
fi

# Print banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║           KIMI ECOSYSTEM CONVERGENCE DEMO                      ║"
echo "║                                                                ║"
echo "║   Security Assessment Against Vulnerable Infrastructure        ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Show configuration
echo -e "${BLUE}Configuration:${NC}"
echo "  Script Directory: $SCRIPT_DIR"
echo "  Output Format: $FORMAT"
echo "  Report Directory: $REPORT_DIR"
echo "  Display Results: $([ -z "$NO_DISPLAY" ] && echo 'Yes' || echo 'No')"
echo ""

# Check if kimi-security-auditor is installed/available
KIMI_AUDITOR_PATH="/root/.openclaw/workspace/kimi-ecosystem/kimi-security-auditor"
if [ ! -d "$KIMI_AUDITOR_PATH" ]; then
    echo -e "${YELLOW}Warning: kimi-security-auditor not found at expected path${NC}"
    echo "  Expected: $KIMI_AUDITOR_PATH"
fi

# Check Python dependencies
echo -e "${BLUE}Checking dependencies...${NC}"
python3 -c "import httpx, click, rich" 2>/dev/null || {
    echo -e "${YELLOW}Installing required Python packages...${NC}"
    pip install httpx click rich -q
}
echo -e "${GREEN}✓ Dependencies ready${NC}"
echo ""

# Target infrastructure info
echo -e "${BLUE}Target Infrastructure:${NC}"
echo "  • Load Balancer:  167.172.71.245 (Nginx)"
echo "  • API Server 1:   178.128.117.238 (Flask)"
echo "  • API Server 2:   152.42.220.203 (Flask)"
echo "  • Database:       152.42.222.84 (PostgreSQL)"
echo "  • Cache:          167.71.196.196 (Redis)"
echo ""

# Run the demo
echo -e "${CYAN}Starting convergence loop demonstration...${NC}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Change to script directory for proper relative paths
cd "$SCRIPT_DIR"

# Run demo.py with all arguments
python3 "$DEMO_PY" \
    --format "$FORMAT" \
    --report-dir "$REPORT_DIR" \
    $NO_DISPLAY

EXIT_CODE=$?

echo ""
echo "═══════════════════════════════════════════════════════════════════"

# Check exit code and provide summary
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Demo completed successfully${NC}"
    echo -e "${GREEN}  No critical vulnerabilities detected${NC}"
elif [ $EXIT_CODE -eq 1 ]; then
    echo -e "${YELLOW}⚠ Demo completed with findings${NC}"
    echo -e "${YELLOW}  Critical or high vulnerabilities were detected${NC}"
else
    echo -e "${RED}✗ Demo encountered an error${NC}"
fi

# Show report locations
if [ -d "$REPORT_DIR" ]; then
    echo ""
    echo -e "${BLUE}Generated Reports:${NC}"
    
    # Find the most recent reports
    LATEST_MD=$(find "$REPORT_DIR" -name "convergence_demo_report_*.md" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    LATEST_JSON=$(find "$REPORT_DIR" -name "convergence_demo_report_*.json" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [ -n "$LATEST_MD" ]; then
        echo "  📄 Markdown: $LATEST_MD"
    fi
    if [ -n "$LATEST_JSON" ]; then
        echo "  📄 JSON:     $LATEST_JSON"
    fi
    
    echo ""
    echo -e "${BLUE}View reports:${NC}"
    [ -n "$LATEST_MD" ] && echo "  cat $LATEST_MD"
    [ -n "$LATEST_JSON" ] && echo "  cat $LATEST_JSON"
fi

echo ""
echo -e "${CYAN}Convergence Demo Complete!${NC}"

exit $EXIT_CODE
