#!/bin/bash
# CodeAudit - Code Quality and Security Analysis Tool
# For Operating Systems Module Mini Project
# Compatible with Windows PowerShell and Unix/Linux systems

VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/codeaudit.log"
HISTORY_LOG="/var/log/codeaudit/history.log"

# Default configuration
DEFAULT_TARGET="$SCRIPT_DIR/mini_project"
DEFAULT_OUTPUT_FORMAT="text"
DEFAULT_PROCESS_MODE="sequential"
DEFAULT_OUTPUT_FILE=""
DEFAULT_LOG_DIR="/var/log/codeaudit"

# Initialize variables
TARGET_DIR="$DEFAULT_TARGET"
OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
PROCESS_MODE="$DEFAULT_PROCESS_MODE"
OUTPUT_FILE="$DEFAULT_OUTPUT_FILE"
LOG_DIR="$DEFAULT_LOG_DIR"
VERBOSE=false
HELP=false
RESTORE_DEFAULTS=false

# Define error codes with associative array
declare -A ERROR_CODES
ERROR_CODES[100]="Invalid option entered"
ERROR_CODES[101]="Target directory not found"
ERROR_CODES[102]="Invalid output format"
ERROR_CODES[103]="Invalid process mode"
ERROR_CODES[104]="Error creating output file"
ERROR_CODES[105]="Administrator privileges required"
ERROR_CODES[106]="Log initialization failed"
ERROR_CODES[107]="Code analysis error"

# Define temporary files globally using PID for uniqueness
TMP_ISSUES_FILE="$SCRIPT_DIR/codeaudit_issues.$$.tmp"
TMP_COUNTS_FILE="$SCRIPT_DIR/codeaudit_counts.$$.tmp"

# Cleanup function to remove temporary files
_cleanup() {
    echo "DEBUG: Cleaning up temporary files..." >&2
    rm -f "$TMP_ISSUES_FILE" "$TMP_COUNTS_FILE"
    echo "DEBUG: Cleanup completed." >&2
}

# Trap to ensure cleanup runs on exit or interruption
trap _cleanup EXIT SIGINT SIGTERM

# Colors for output
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    NC=""
else
    RED='\\033[0;31m'
    GREEN='\\033[0;32m'
    YELLOW='\\033[1;33m'
    BLUE='\\033[0;34m'
    NC='\\033[0m'
fi

# Error handling function with error codes
handle_error() {
    local error_code="$1"
    local context="$2"
    local message="${ERROR_CODES[$error_code]}"
    
    if [[ -z "$message" ]]; then
        message="Unknown error (code: $error_code)"
    fi
    
    if [[ -n "$context" ]]; then
        message="$message - $context"
    fi
    
    echo -e "${RED}Error $error_code:${NC} $message" >&2
    log_message "ERROR" "Code $error_code: $message"
    
    # Write to history log if available and writable
    if [[ -n "$HISTORY_LOG" && -f "$HISTORY_LOG" && -w "$HISTORY_LOG" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR $error_code: $message" >> "$HISTORY_LOG"
    fi
    
    exit "$error_code"
}

# Admin privileges check function
check_admin_privileges() {
    if [[ $EUID -ne 0 ]]; then
        handle_error 105 "This operation requires administrator privileges (sudo)"
    fi
}

# History log setup function
setup_history_log() {
    # Try to create log directory if it doesn't exist
    if [[ ! -d "$LOG_DIR" ]]; then
        if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
            # If we can't create the system log directory, use local directory
            echo -e "${YELLOW}Warning:${NC} Cannot create $LOG_DIR. Using local directory." >&2
            LOG_DIR="$SCRIPT_DIR"
            HISTORY_LOG="$SCRIPT_DIR/history.log"
        fi
    fi
    
    # If still using system path, update HISTORY_LOG
    if [[ "$LOG_DIR" != "$SCRIPT_DIR" ]]; then
        HISTORY_LOG="$LOG_DIR/history.log"
    fi
    
    # Create history log file if it doesn't exist
    if [[ ! -f "$HISTORY_LOG" ]]; then
        if ! touch "$HISTORY_LOG" 2>/dev/null; then
            # Final fallback to local directory
            HISTORY_LOG="$SCRIPT_DIR/history.log"
            touch "$HISTORY_LOG" || handle_error 106 "Cannot create local log file"
        fi
    fi
    
    # Ensure proper permissions if we have root access
    if [[ $EUID -eq 0 && -f "$HISTORY_LOG" ]]; then
        chmod 644 "$HISTORY_LOG" 2>/dev/null
        chown root:root "$HISTORY_LOG" 2>/dev/null
    fi
    
    # Write startup entry to history log
    if [[ -w "$HISTORY_LOG" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting CodeAudit v$VERSION" >> "$HISTORY_LOG"
    fi
}

# Global variables for statistics
TOTAL_FILES_PROCESSED=0
AGGREGATED_ISSUES_FOUND=0
AGGREGATED_SECURITY_ISSUES=0
AGGREGATED_QUALITY_ISSUES=0
PARALLEL_MAX_PROCS=4 # Default, will be updated in main

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}[$level]${NC} $message" >&2
    fi
}

# History logging function
log_to_history() {
    local message="$1"
    if [[ -n "$HISTORY_LOG" && -f "$HISTORY_LOG" && -w "$HISTORY_LOG" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$HISTORY_LOG"
    fi
}

# Help function
show_help() {
    cat << EOF
CodeAudit - Code Quality and Security Analysis Tool v$VERSION

USAGE:
    $0 [OPTIONS] [TARGET_DIRECTORY]

OPTIONS:
    -h, --help              Display this help message
    -v, --verbose           Enable verbose output
    -f, --format FORMAT     Output format (text, html, json) [default: text]
    -o, --output FILE       Output file (default: stdout)
    -m, --mode MODE         Process mode (sequential, fork, subshell, thread) [default: sequential]
    -d, --directory DIR     Target directory to analyze [default: $DEFAULT_TARGET]
    --fork                  Use fork mode for parallel processing
    --thread                Use thread mode for parallel processing
    --subshell              Use subshell mode for parallel processing
    -l, --log DIR           Log files directory [default: $DEFAULT_LOG_DIR]
    -r, --restore           Restore default settings (requires sudo)

EXAMPLES:
    $0                                    # Analyze default directory
    $0 -v -f json -o report.json         # Detailed JSON output
    $0 -d /path/to/code --fork            # Analyze specific directory in fork mode
    $0 -m thread -v                       # Thread mode with verbose output
    sudo $0 -r                            # Restore default settings

OUTPUT FORMATS:
    text    Simple text format (default)
    html    HTML report with formatting
    json    Structured JSON format

PROCESS MODES:
    sequential  Sequential processing (default)
    fork        Parallel processing with fork
    thread      Parallel processing with threads
    subshell    Parallel processing with subshells

For more information, consult the project documentation.
EOF
}

# Default settings restoration function
restore_defaults() {
    check_admin_privileges
    
    echo -e "${BLUE}Restoring default settings...${NC}"
    
    # Restore default values
    TARGET_DIR="$DEFAULT_TARGET"
    OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
    PROCESS_MODE="$DEFAULT_PROCESS_MODE"
    OUTPUT_FILE="$DEFAULT_OUTPUT_FILE"
    LOG_DIR="$DEFAULT_LOG_DIR"
    VERBOSE=false
    
    # Recreate log directories
    setup_history_log
    
    echo -e "${GREEN}Default settings restored successfully.${NC}"
    log_to_history "Default settings restored successfully"
    
    exit 0
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                HELP=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--format)
                if [[ -z "$2" ]]; then
                    handle_error 100 "Option -f requires an argument"
                fi
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                if [[ -z "$2" ]]; then
                    handle_error 100 "Option -o requires an argument"
                fi
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -m|--mode)
                if [[ -z "$2" ]]; then
                    handle_error 100 "Option -m requires an argument"
                fi
                PROCESS_MODE="$2"
                shift 2
                ;;
            -d|--directory)
                if [[ -z "$2" ]]; then
                    handle_error 100 "Option -d requires an argument"
                fi
                TARGET_DIR="$2"
                shift 2
                ;;
            -l|--log)
                if [[ -z "$2" ]]; then
                    handle_error 100 "Option -l requires an argument"
                fi
                LOG_DIR="$2"
                HISTORY_LOG="$LOG_DIR/history.log"
                shift 2
                ;;
            -r|--restore)
                RESTORE_DEFAULTS=true
                shift
                ;;
            --fork)
                PROCESS_MODE="fork"
                shift
                ;;
            --thread)
                PROCESS_MODE="thread"
                shift
                ;;
            --subshell)
                PROCESS_MODE="subshell"
                shift
                ;;
            -*)
                handle_error 100 "Unknown option: $1"
                ;;
            *)
                TARGET_DIR="$1"
                shift
                ;;
        esac
    done
}

# Validate arguments
validate_arguments() {
    # Check output format
    case "$OUTPUT_FORMAT" in
        text|html|json) ;;
        *) handle_error 102 "Invalid output format '$OUTPUT_FORMAT'. Use: text, html, json" ;;
    esac
    
    # Check process mode
    case "$PROCESS_MODE" in
        sequential|fork|subshell|thread) ;;
        *) handle_error 103 "Invalid process mode '$PROCESS_MODE'. Use: sequential, fork, subshell, thread" ;;
    esac
    
    # Check target directory
    if [[ ! -d "$TARGET_DIR" ]]; then
        handle_error 101 "Target directory '$TARGET_DIR' does not exist"
    fi
    
    # Check fork availability on Windows
    if [[ "$PROCESS_MODE" == "fork" && ("$OSTYPE" == "msys" || "$OSTYPE" == "win32") ]]; then
        echo -e "${YELLOW}Warning:${NC} Fork mode not available on Windows. Using subshell mode instead." >&2
        PROCESS_MODE="subshell"
    fi
    
    # Create output file if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        if ! touch "$OUTPUT_FILE" 2>/dev/null; then
            handle_error 104 "Cannot create output file '$OUTPUT_FILE'"
        fi
    fi
}

# Language detection
detect_language() {
    local file="$1"
    local extension="${file##*.}"
    
    case "$extension" in
        js) echo "javascript" ;;
        py) echo "python" ;;
        c|h) echo "c" ;;
        cpp|cc|cxx) echo "cpp" ;;
        java) echo "java" ;;
        php) echo "php" ;;
        sh|bash) echo "shell" ;;
        html|htm) echo "html" ;;
        css) echo "css" ;;
        *) echo "unknown" ;;
    esac
}

# Security vulnerability analysis
scan_security_vulnerabilities() {
    local file="$1"
    local language="$2"
    local issues=()
    
    case "$language" in
        "javascript")
            # Check for eval usage
            if grep -q "eval(" "$file" 2>/dev/null; then
                issues+=("SECURITY: Dangerous eval() function usage")
            fi
            
            # Check for hardcoded passwords
            if grep -iq "password\s*=\s*['\"][^'\"]*['\"]" "$file" 2>/dev/null; then
                issues+=("SECURITY: Hardcoded password detected")
            fi
            
            # Check for loose equality
            if grep -q "==" "$file" 2>/dev/null; then
                issues+=("SECURITY: Loose equality operator (use === instead)")
            fi
            ;;
            
        "python")
            # Check for eval/exec usage
            if grep -q "eval\|exec\|os\.system" "$file" 2>/dev/null; then
                issues+=("SECURITY: Dangerous function usage (eval/exec/os.system)")
            fi
            
            # Check for hardcoded secrets
            if grep -iq "password\|secret\|api_key" "$file" 2>/dev/null; then
                issues+=("SECURITY: Potential hardcoded credentials")
            fi
            ;;
            
        "c"|"cpp")
            # Check for buffer overflow risks
            if grep -q "gets\|strcpy\|strcat" "$file" 2>/dev/null; then
                issues+=("SECURITY: Unsafe string functions (buffer overflow risk)")
            fi
            
            # Check for memory leaks
            if grep -q "malloc\|calloc" "$file" 2>/dev/null && ! grep -q "free" "$file" 2>/dev/null; then
                issues+=("SECURITY: Potential memory leak (malloc without free)")
            fi
            ;;
            
        "php")
            # Check for SQL injection
            if grep -q "SELECT.*FROM.*WHERE" "$file" 2>/dev/null; then
                issues+=("SECURITY: Potential SQL injection vulnerability")
            fi
            
            # Check for file inclusion vulnerabilities
            if grep -q "include\|require" "$file" 2>/dev/null; then
                issues+=("SECURITY: File inclusion detected (check for LFI/RFI)")
            fi
            ;;
    esac
    
    printf '%s\n' "${issues[@]}"
}

# Code quality issue analysis
scan_quality_issues() {
    local file="$1"
    local language="$2"
    local issues=()
    
    # Check file size
    local file_size=$(wc -l < "$file" 2>/dev/null || echo "0")
    if [[ $file_size -gt 500 ]]; then
        issues+=("QUALITY: Large file ($file_size lines) - consider splitting")
    fi
    
    # Check line length
    if awk 'length > 120 { exit 1 }' "$file" 2>/dev/null; then
        :
    else
        issues+=("QUALITY: Lines exceeding 120 characters detected")
    fi
    
    case "$language" in
        "javascript")
            # Check for console.log
            if grep -q "console\.log" "$file" 2>/dev/null; then
                issues+=("QUALITY: Debug console.log statements found")
            fi
            ;;
            
        "python")
            # Check for TODO comments
            if grep -iq "todo\|fixme" "$file" 2>/dev/null; then
                issues+=("QUALITY: TODO/FIXME comments found")
            fi
            ;;
            
        "c"|"cpp")
            # Check for proper headers
            if ! grep -q "#include" "$file" 2>/dev/null; then
                issues+=("QUALITY: No include statements found")
            fi
            ;;
    esac
    
    printf '%s\n' "${issues[@]}"
}

# Analyze a single file
analyze_file() {
    local file="$1"
    local language
    language=$(detect_language "$file")

    log_message "INFO" "Analyzing file: $file (Language: $language)" >&2

    if [[ "$language" == "unknown" ]]; then
        log_message "INFO" "Skipping file with unknown language: $file" >&2
        echo "0:0:0" 
        return 0
    fi

    local file_issues_details=()
    local current_file_security_issues=0
    local current_file_quality_issues=0

    # Analyze security vulnerabilities
    local security_scan_output
    security_scan_output=$(scan_security_vulnerabilities "$file" "$language")
    while IFS= read -r issue; do
        if [[ -n "$issue" ]]; then
            file_issues_details+=("$issue")
            ((current_file_security_issues++))
        fi
    done <<< "$security_scan_output"

    # Analyze quality issues
    local quality_scan_output
    quality_scan_output=$(scan_quality_issues "$file" "$language")
    while IFS= read -r issue; do
        if [[ -n "$issue" ]]; then
            file_issues_details+=("$issue")
            ((current_file_quality_issues++))
        fi
    done <<< "$quality_scan_output"

    # If issues found for this file, add them to TMP_ISSUES_FILE for detailed report
    if [[ ${#file_issues_details[@]} -gt 0 ]]; then
        echo "$file@@@$(IFS=###; echo "${file_issues_details[*]}")" >> "$TMP_ISSUES_FILE"
    fi

    # Echo counters: 1 (indicates this file was processed), security issues, quality issues
    echo "1:$current_file_security_issues:$current_file_quality_issues"
}

# Process files using different modes
process_files() {
    local files=()
    # Find all files in target directory
    while IFS= read -r -d '' file; do
        files+=("$file")
    done < <(find "$TARGET_DIR" -type f -print0 2>/dev/null)

    log_message "INFO" "Found ${#files[@]} files to analyze in $PROCESS_MODE mode with $PARALLEL_MAX_PROCS maximum processes."

    # Ensure TMP_COUNTS_FILE is clean for parallel modes
    if [[ "$PROCESS_MODE" != "sequential" ]]; then
        >"$TMP_COUNTS_FILE" # Ensure it's clean
        echo "DEBUG: TMP_COUNTS_FILE cleared ($TMP_COUNTS_FILE) for parallel mode." >&2
    fi

    case "$PROCESS_MODE" in
        "sequential")
            for file in "${files[@]}"; do
                local counts_str
                counts_str=$(analyze_file "$file")
                local processed_flag file_sec_issues file_qual_issues
                IFS=':' read -r processed_flag file_sec_issues file_qual_issues <<< "$counts_str"

                if [[ "$processed_flag" == "1" ]]; then
                    ((TOTAL_FILES_PROCESSED++))
                    ((AGGREGATED_SECURITY_ISSUES += file_sec_issues))
                    ((AGGREGATED_QUALITY_ISSUES += file_qual_issues))
                fi
            done
            ;;
        "fork"|"subshell"|"thread")
            local job_pids=()
            local current_jobs=0
            for file in "${files[@]}"; do
                (analyze_file "$file" >> "$TMP_COUNTS_FILE") &
                job_pids+=($!) # Store background job PID
                ((current_jobs++))
                
                echo "DEBUG: Job started for $file. Current jobs: $current_jobs" >&2

                if (( current_jobs >= PARALLEL_MAX_PROCS )); then
                    echo "DEBUG: Maximum processes ($PARALLEL_MAX_PROCS) reached. Waiting for a job to finish..." >&2
                    wait -n # Wait for a background job to finish
                    ((current_jobs--))
                    echo "DEBUG: One job finished. Current jobs: $current_jobs" >&2
                fi
            done
            
            echo "DEBUG: All files submitted. Waiting for ${#job_pids[@]} remaining jobs..." >&2
            wait # Wait for all remaining background jobs associated with this shell
            echo "DEBUG: All background jobs finished." >&2

            # Aggregate results from TMP_COUNTS_FILE
            if [[ -f "$TMP_COUNTS_FILE" ]]; then
                echo "DEBUG: Aggregating results from TMP_COUNTS_FILE ($TMP_COUNTS_FILE):" >&2
                cat "$TMP_COUNTS_FILE" >&2
                echo "DEBUG: --- End of TMP_COUNTS_FILE content ---" >&2
                
                local line_num=0
                while IFS=':' read -r processed_flag file_sec_issues file_qual_issues || { [[ -n "$processed_flag" ]] && break; }; do
                    ((line_num++))
                    echo "DEBUG: Line $line_num from TMP_COUNTS_FILE: P='$processed_flag', S='$file_sec_issues', Q='$file_qual_issues'" >&2
                    if [[ "$processed_flag" == "1" && -n "$file_sec_issues" && -n "$file_qual_issues" ]]; then
                        TOTAL_FILES_PROCESSED=$((TOTAL_FILES_PROCESSED + 1))
                        AGGREGATED_SECURITY_ISSUES=$((AGGREGATED_SECURITY_ISSUES + file_sec_issues))
                        AGGREGATED_QUALITY_ISSUES=$((AGGREGATED_QUALITY_ISSUES + file_qual_issues))
                        echo "DEBUG: Counters updated: TFP=$TOTAL_FILES_PROCESSED, ASI=$AGGREGATED_SECURITY_ISSUES, AQI=$AGGREGATED_QUALITY_ISSUES" >&2
                    else
                        echo "DEBUG: Line $line_num ignored due to invalid data: P='$processed_flag', S='$file_sec_issues', Q='$file_qual_issues'" >&2
                    fi
                done < "$TMP_COUNTS_FILE"
                echo "DEBUG: TMP_COUNTS_FILE reading completed. Final counters in process_files: TFP=$TOTAL_FILES_PROCESSED, ASI=$AGGREGATED_SECURITY_ISSUES, AQI=$AGGREGATED_QUALITY_ISSUES" >&2
            else
                echo "DEBUG: TMP_COUNTS_FILE ($TMP_COUNTS_FILE) not found or empty after jobs." >&2
            fi
            ;;
    esac

    AGGREGATED_ISSUES_FOUND=$((AGGREGATED_SECURITY_ISSUES + AGGREGATED_QUALITY_ISSUES))
    echo "DEBUG: process_files completed. AGGREGATED_ISSUES_FOUND=$AGGREGATED_ISSUES_FOUND" >&2
}

# Generate output based on format
generate_output() {
    echo "DEBUG: generate_output called. Counters: TFP=$TOTAL_FILES_PROCESSED, ASI=$AGGREGATED_SECURITY_ISSUES, AQI=$AGGREGATED_QUALITY_ISSUES, AIF=$AGGREGATED_ISSUES_FOUND" >&2
    case "$OUTPUT_FORMAT" in
        "text")
            echo "CodeAudit Analysis Report"
            echo "========================="
            echo "Target Directory: $TARGET_DIR"
            echo "Process Mode: $PROCESS_MODE"
            echo "Files Analyzed: $TOTAL_FILES_PROCESSED"
            echo "Issues Found: $AGGREGATED_ISSUES_FOUND"
            echo "Security Issues: $AGGREGATED_SECURITY_ISSUES"
            echo "Quality Issues: $AGGREGATED_QUALITY_ISSUES"
            echo

            if [[ "$AGGREGATED_ISSUES_FOUND" -gt 0 && -f "$TMP_ISSUES_FILE" && -s "$TMP_ISSUES_FILE" ]]; then
                echo "Detailed Issues:"
                echo "----------------"
                while IFS= read -r line || [[ -n "$line" ]]; do
                    if [[ -z "$line" ]]; then continue; fi
                    local file_path="${line%%@@@*}"
                    local issues_str="${line#*@@@}"
                    echo "File: $file_path"
                    IFS='###' read -r -a issues_array <<< "$issues_str"
                    for issue in "${issues_array[@]}"; do
                        echo "  - $issue"
                    done
                    echo
                done < "$TMP_ISSUES_FILE"
            elif [[ "$AGGREGATED_ISSUES_FOUND" -gt 0 ]]; then
                echo "Detailed issues could not be read from $TMP_ISSUES_FILE (or file is empty)."
            else
                echo "No issues found."
            fi
            ;;
        "json")
            printf "{\n"
            printf "    \"codeaudit_report\": {\n"
            printf "        \"version\": \"%s\",\n" "$VERSION"
            printf "        \"timestamp\": \"%s\",\n" "$(date -Iseconds)"
            printf "        \"target_directory\": \"%s\",\n" "$TARGET_DIR"
            printf "        \"process_mode\": \"%s\",\n" "$PROCESS_MODE"
            printf "        \"summary\": {\n"
            printf "            \"files_analyzed\": %d,\n" "$TOTAL_FILES_PROCESSED"
            printf "            \"issues_found\": %d,\n" "$AGGREGATED_ISSUES_FOUND"
            printf "            \"security_issues\": %d,\n" "$AGGREGATED_SECURITY_ISSUES"
            printf "            \"quality_issues\": %d\n" "$AGGREGATED_QUALITY_ISSUES"
            printf "        },\n"
            printf "        \"file_details\": [\n"

            local first_file_entry=true
            if [[ -f "$TMP_ISSUES_FILE" ]] && [[ -s "$TMP_ISSUES_FILE" ]]; then
                while IFS= read -r line || [[ -n "$line" ]]; do
                    if [[ -z "$line" ]]; then continue; fi 
                    local file_path="${line%%@@@*}"
                    local issues_str="${line#*@@@}"

                    if ! $first_file_entry; then
                        printf ",\n"
                    fi
                    first_file_entry=false

                    local escaped_file_path=$(echo "$file_path" | sed 's/\\/\\\\/g; s/"/\\"/g') 
                    printf "            {\n"
                    printf "                \"file\": \"%s\",\n" "$escaped_file_path"
                    printf "                \"issues\": [\n"

                    local first_issue=true
                    IFS='###' read -r -a issues_array <<< "$issues_str"
                    for issue in "${issues_array[@]}"; do
                        if ! $first_issue; then
                            printf ",\n"
                        fi
                        first_issue=false
                        local escaped_issue=$(echo "$issue" | sed 's/\\/\\\\/g; s/"/\\"/g') 
                        printf "                    \"%s\"" "$escaped_issue"
                    done
                    printf "\n                ]\n"
                    printf "            }"
                done < "$TMP_ISSUES_FILE"
            fi
            printf "\n        ]\n" 
            printf "    }\n"       
            printf "}\n"          
            ;;
        "html")
            cat << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <title>CodeAudit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; color: #333; }
        .container { max-width: 900px; margin: auto; background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { background-color: #f4f4f4; padding: 15px; border-radius: 5px; margin-bottom: 20px; text-align: center; }
        .header h1 { margin: 0; color: #333; }
        .header p { margin: 5px 0 0; color: #555; }
        .summary, .file-issues { margin-bottom: 20px; }
        .summary h2, .file-issues h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 15px; color: #444; }
        .summary ul { list-style-type: none; padding-left: 0; }
        .summary ul li { background-color: #e9ecef; margin-bottom: 8px; padding: 10px; border-radius: 4px; }
        .file-issues ul { list-style-type: none; padding-left: 0; }
        .file-issues > ul > li { background-color: #fff; margin-bottom: 15px; padding: 15px; border: 1px solid #ddd; border-radius: 4px; }
        .file-issues > ul > li > strong { display: block; margin-bottom: 10px; color: #007bff; }
        .file-issues ul ul { list-style-type: disc; padding-left: 20px; margin-top: 5px; }
        .file-issues ul ul li { margin-bottom: 5px; }
        .security { color: #d9534f; font-weight: bold; }
        .quality { color: #f0ad4e; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CodeAudit Analysis Report</h1>
            <p><strong>Target:</strong> $TARGET_DIR</p>
            <p><strong>Generated on:</strong> $(date)</p>
            <p><strong>Process Mode:</strong> $PROCESS_MODE</p>
        </div>
    
        <div class="summary">
            <h2>Summary</h2>
            <ul>
                <li>Files Analyzed: $TOTAL_FILES_PROCESSED</li>
                <li>Issues Found: $AGGREGATED_ISSUES_FOUND</li>
                <li>Security Issues: <span class="security">$AGGREGATED_SECURITY_ISSUES</span></li>
                <li>Quality Issues: <span class="quality">$AGGREGATED_QUALITY_ISSUES</span></li>
            </ul>
        </div>

        <div class="file-issues">
            <h2>File Details</h2>
EOF
            if [[ "$AGGREGATED_ISSUES_FOUND" -gt 0 && -f "$TMP_ISSUES_FILE" ]] && [[ -s "$TMP_ISSUES_FILE" ]]; then
                echo "<ul>"
                while IFS= read -r line || [[ -n "$line" ]]; do
                    if [[ -z "$line" ]]; then continue; fi 
                    local file_path="${line%%@@@*}"
                    local issues_str="${line#*@@@}"
                    local file_path_html=$(echo "$file_path" | sed 's/&/&amp;/g; s/</&lt;/g; s/>/&gt;/g; s/"/&quot;/g; s/'"'"'/\&#39;/g')
                    echo "<li><strong>File: ${file_path_html}</strong>"
                    echo "  <ul>"
                    IFS='###' read -r -a issues_array <<< "$issues_str"
                    for issue in "${issues_array[@]}"; do
                        local issue_html=$(echo "$issue" | sed 's/&/&amp;/g; s/</&lt;/g; s/>/&gt;/g; s/'"'"'/\&#39;/g')
                        local issue_type_class=""
                        if [[ "$issue" == SECURITY:* ]]; then
                            issue_type_class="security"
                        elif [[ "$issue" == QUALITY:* ]]; then
                            issue_type_class="quality"
                        fi
                        echo "    <li class=\"${issue_type_class}\">${issue_html}</li>"
                    done
                    echo "  </ul>"
                    echo "</li>"
                done < "$TMP_ISSUES_FILE"
                echo "</ul>"
            elif [[ "$AGGREGATED_ISSUES_FOUND" -gt 0 ]]; then
                echo "<p>Detailed issues could not be read from $TMP_ISSUES_FILE (or file is empty).</p>"
            else
                echo "<p>No issues found.</p>"
            fi
            cat << EOF
        </div>
    </div>
</body>
</html>
EOF
            ;;
    esac
}

# Main execution function
main() {
    echo "CodeAudit v$VERSION started at $(date)" > "$LOG_FILE"
    
    # Setup history logging
    setup_history_log
    
    # Handle default settings restoration if requested
    if [[ "$RESTORE_DEFAULTS" == true ]]; then
        restore_defaults
        exit 0
    fi
    
    # Truncate temp files at the start of the main script
    >"$TMP_ISSUES_FILE"
    >"$TMP_COUNTS_FILE"
    echo "DEBUG: Temporary files initialized/cleared TMP_ISSUES_FILE ($TMP_ISSUES_FILE) and TMP_COUNTS_FILE ($TMP_COUNTS_FILE)." >&2

    TOTAL_FILES_PROCESSED=0
    AGGREGATED_ISSUES_FOUND=0
    AGGREGATED_SECURITY_ISSUES=0
    AGGREGATED_QUALITY_ISSUES=0
    
    # Determine PARALLEL_MAX_PROCS
    if command -v nproc &> /dev/null; then
        PARALLEL_MAX_PROCS=$(nproc)
    else
        PARALLEL_MAX_PROCS=4 # Default if nproc is not available
    fi
    echo "DEBUG: PARALLEL_MAX_PROCS set to $PARALLEL_MAX_PROCS." >&2

    export -f analyze_file detect_language scan_security_vulnerabilities scan_quality_issues log_message handle_error
    export VERBOSE TMP_ISSUES_FILE LOG_FILE RED GREEN YELLOW BLUE NC SCRIPT_DIR TMP_COUNTS_FILE PARALLEL_MAX_PROCS ERROR_CODES

    parse_arguments "$@"

    if [[ "$HELP" == true ]]; then
        show_help
        exit 0 # Trap will handle cleanup
    fi
    
    validate_arguments

    log_message "INFO" "Starting CodeAudit analysis"
    log_message "INFO" "Target: $TARGET_DIR, Format: $OUTPUT_FORMAT, Mode: $PROCESS_MODE"
    log_to_history "Analysis started - Target: $TARGET_DIR, Format: $OUTPUT_FORMAT, Mode: $PROCESS_MODE"

    if [[ -n "$OUTPUT_FILE" ]]; then
        exec > "$OUTPUT_FILE"
    fi

    process_files 

    generate_output 

    log_message "INFO" "Analysis completed. Files: $TOTAL_FILES_PROCESSED, Issues: $AGGREGATED_ISSUES_FOUND"
    log_to_history "Analysis completed - Files: $TOTAL_FILES_PROCESSED, Security Issues: $AGGREGATED_SECURITY_ISSUES, Quality Issues: $AGGREGATED_QUALITY_ISSUES"

    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "${GREEN}Analysis complete!${NC} Results written to: $OUTPUT_FILE" >&2
        echo -e "Files analyzed: $TOTAL_FILES_PROCESSED, Issues found: $AGGREGATED_ISSUES_FOUND" >&2
    fi
    # No explicit rm here, trap will handle it.
}

main "$@"
