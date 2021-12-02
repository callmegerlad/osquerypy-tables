# osquerypy-tables

An osquery extension built with osquery-python with a few tables that were converted from Go.

## 📝 Prerequisites

- Have _Python_ and [_osquery-python_](https://github.com/osquery/osquery-python) installed on your dev environment,
- A tool to help convert Python programs into executables, like [_PyInstaller_](https://www.pyinstaller.org/),
- And of course, [_osquery_](https://osquery.io/downloads/official/5.0.1).

## 🛠️ Usage

| Table         | Description                             | Example Usage |
| ------------- | --------------------------------------- | ------------- |
| file_lines    | Returns each line in a specified file.  | `SELECT * FROM file_lines WHERE path='/home/readme.md'`<br>`SELECT * FROM file_lines WHERE path LIKE '/home/%.md'` |
| exec          | Allows command execution with queries.  | `SELECT * FROM exec WHERE cmd='whoami'` |

WIP...
