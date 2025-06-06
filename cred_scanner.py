import os
import re
import sys
import click

EXCLUDED_DIRS = {'.git', '__pycache__', 'venv'}
ALLOWED_EXTENSIONS = {'.py', '.txt', '.env', '.cfg', '.json', '.yaml', '.yml'}

AWS_KEY_PATTERN = r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])'
SECRET_KEY_PATTERN = r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'

@click.command()
@click.option('--path', default='.', help='Directory path to scan')
@click.option('--secret', is_flag=True, help='Scan for generic secret key patterns too')
@click.option('--log', type=click.Path(), help='Log results to a file')
def scan(path, secret, log):
    fail = False
    findings = []

    for root, dirs, files in os.walk(path):
        # Ignore excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            file_path = os.path.join(root, file)
            _, ext = os.path.splitext(file)
            if ext.lower() not in ALLOWED_EXTENSIONS:
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.readlines()
            except (UnicodeDecodeError, PermissionError) as e:
                click.secho(f"Skipped binary or unreadable file: {file_path}", fg='yellow')
                continue

            pattern = f"{AWS_KEY_PATTERN}|{SECRET_KEY_PATTERN}" if secret else AWS_KEY_PATTERN
            regex = re.compile(pattern)

            for i, line in enumerate(content):
                for match in regex.finditer(line):
                    finding = f"Found possible secret in {file_path} at line {i+1}: {match.group()}"
                    click.secho(finding, fg='red')
                    findings.append(finding)
                    fail = True

    if log and findings:
        with open(log, 'w', encoding='utf-8') as logfile:
            logfile.write("\n".join(findings))
        click.secho(f"\nFindings written to {log}", fg='blue')

    if fail:
        sys.exit(1)

if __name__ == '__main__':
    scan()
