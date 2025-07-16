#!/bin/bash
cd /home/kavia/workspace/code-generation/jira-issue-export-import-tool-26429a48/jira_syncer_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

