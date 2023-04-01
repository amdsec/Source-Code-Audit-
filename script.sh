#!/bin/bash

# set the directory to search in
DIRECTORY=$1

# check if the directory argument is provided
if [ -z "$DIRECTORY" ]
then
  echo "Please provide a directory to search in."
  exit 1
fi

# create a directory to store the vulnerability reports
REPORTS_DIR="$DIRECTORY/reports"
mkdir -p "$REPORTS_DIR"

# search for possible SQL injection vulnerabilities
SQL_INJECTION_FILE="$REPORTS_DIR/sql_injection.txt"
find "$DIRECTORY" -name "*.php" -type f -exec grep -rnE "(mysql_query|mysqli_query|PDO::query|PDO::prepare).*[$]_(GET|POST|REQUEST)\[[^]]+\]" {} \; > "$SQL_INJECTION_FILE"

# search for possible cross-site scripting (XSS) vulnerabilities
XSS_FILE="$REPORTS_DIR/xss.txt"
find "$DIRECTORY" -name "*.php" -type f -exec grep -rnE "[$]_(GET|POST|REQUEST)\[[^]]+\]" {} \; | grep -iE "(echo|print|print_r).*htmlspecialchars\(" > "$XSS_FILE"

# search for possible file inclusion vulnerabilities
FILE_INCLUSION_FILE="$REPORTS_DIR/file_inclusion.txt"
find "$DIRECTORY" -name "*.php" -type f -exec grep -rnE "(include|require|include_once|require_once)\([$]_(GET|POST|REQUEST)\[[^]]+\]\)" {} \; > "$FILE_INCLUSION_FILE"

# search for possible command injection vulnerabilities
COMMAND_INJECTION_FILE="$REPORTS_DIR/command_injection.txt"
find "$DIRECTORY" -name "*.php" -type f -exec grep -rnE "(system|exec|passthru|shell_exec|popen)\([$]_(GET|POST|REQUEST)\[[^]]+\]" {} \; > "$COMMAND_INJECTION_FILE"

# search for possible directory traversal vulnerabilities
DIRECTORY_TRAVERSAL_FILE="$REPORTS_DIR/directory_traversal.txt"
find "$DIRECTORY" -name "*.php" -type f -exec grep -rnE "[$]_(GET|POST|REQUEST)\['(path|file|dir)'\]" {} \; > "$DIRECTORY_TRAVERSAL_FILE"

# search for possible authentication bypass vulnerabilities
AUTH_BYPASS_FILE="$REPORTS_DIR/authentication_bypass.txt"
find "$DIRECTORY" -name "*.php" -type f -exec grep -rnE "[$]_SESSION" {} \; | grep -iE "(password|login|auth|admin)" > "$AUTH_BYPASS_FILE"
