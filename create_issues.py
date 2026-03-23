import re
import subprocess
import sys

def parse_issues(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Could not find {file_path}")
        sys.exit(1)

    # Split the document by "Issue #<number>:"
    # The first element will be the header text which we ignore
    parts = re.split(r'Issue #\d+:', content)
    
    issues = []
    # Skip the header (index 0)
    for part in parts[1:]:
        # Clean up whitespace and split into lines
        lines = part.strip().split('\n')
        
        # The first line is the issue title
        title = lines[0].strip()
        
        # The rest is the issue body
        body = '\n'.join(lines[1:]).strip()
        
        issues.append({
            'title': title,
            'body': body
        })
        
    return issues

def create_issues(issues):
    # Check if gh CLI is available
    try:
        subprocess.run(['gh', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: GitHub CLI ('gh') is not installed or not found in PATH.")
        print("Please install it from https://cli.github.com/ and run 'gh auth login' first.")
        sys.exit(1)

    print(f"Parsed {len(issues)} issues. Starting creation...")
    
    for i, issue in enumerate(issues, 1):
        print(f"[{i}/{len(issues)}] Creating issue: {issue['title']}")
        try:
            # Call the gh CLI to create the issue
            result = subprocess.run([
                'gh', 'issue', 'create',
                '--title', issue['title'],
                '--body', issue['body']
            ], capture_output=True, text=True, check=True)
            
            # gh issue create usually prints the URL of the created issue to stdout
            issue_url = result.stdout.strip()
            print(f"  -> Success: {issue_url}")
            
        except subprocess.CalledProcessError as e:
            print(f"  -> Failed to create issue!")
            print(f"  -> Error output: {e.stderr.strip()}")

if __name__ == '__main__':
    file_to_parse = 'issues.md'
    parsed_issues = parse_issues(file_to_parse)
    
    if not parsed_issues:
        print("No issues found to create.")
        sys.exit(0)
        
    create_issues(parsed_issues)
