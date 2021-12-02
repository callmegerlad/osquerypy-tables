#!/usr/bin/env python
import json
import glob
import osquery
import platform
import subprocess

@osquery.register_plugin
class FileLinesTable(osquery.TablePlugin):
    def name(self):
        return "file_lines"

    def columns(self):
        return [
            osquery.TableColumn(name="line", type=osquery.STRING),
            osquery.TableColumn(name="path", type=osquery.STRING),
        ]

    def generate(self, context):
        query_data = []
        context = json.loads(json.loads(context))
        path = context["constraints"][1]["list"][0]["expr"]
        operator = context["constraints"][1]["list"][0]["op"]
        wildcard = False
        if operator == 65:
            wildcard = True
        output = process_file(path, wildcard)

        for key, values in output.items():
            for line in values:
                row = {}
                row["line"] = line
                row["path"] = key
                query_data.append(row)

        return query_data


def process_file(path, wildcard):
    output = {}

    if wildcard:
        path = path.replace("%", "*")
        files = glob.glob(path, recursive = True)
        for filepath in files:
            with open(filepath, 'r', encoding='UTF-8') as file:
                lines = [line.rstrip() for line in file]
                output[filepath] = lines
    else:
        with open(path, 'r', encoding='UTF-8') as file:
            lines = [line.rstrip() for line in file]
            output[path] = lines

    return output


@osquery.register_plugin
class ExecTable(osquery.TablePlugin):
    def name(self):
        return "exec"

    def columns(self):
        return [
            osquery.TableColumn(name="cmd", type=osquery.STRING),
            osquery.TableColumn(name="stdout", type=osquery.STRING),
            osquery.TableColumn(name="stderr", type=osquery.STRING),
            osquery.TableColumn(name="code", type=osquery.STRING),
        ]

    def generate(self, context):
        query_data = []
        context = json.loads(json.loads(context))
        cmd = context["constraints"][0]["list"][0]["expr"]

        if platform.system() == "Windows":
            cmdArr = str.split(cmd, " ")
            args = cmdArr[1:]
            out, err, code = executeWin(cmdArr[0], *args)
        else:
            out, err, code = execute(cmd)

        row = {}
        row["cmd"] = cmd
        row["stdout"] = out
        row["stderr"] = err
        row["code"] = code
        query_data.append(row)

        return query_data


def execute(cmd):
    cmd = subprocess.run([cmd], shell=True, capture_output=True)
    stdout = cmd.stdout.decode('UTF-8').rstrip()
    stderr = cmd.stderr.decode('UTF-8').rstrip()
    return stdout, stderr, 0 if len(stderr) > 0 else 1


def executeWin(cmd, *args):
    cmd = subprocess.run([cmd, *args], shell=True, capture_output=True)
    stdout = cmd.stdout.decode('UTF-8').rstrip()
    stderr = cmd.stderr.decode('UTF-8').rstrip()
    return stdout, stderr, 0 if len(stderr) > 0 else 1


if __name__ == "__main__":
    osquery.start_extension(name="my_extension", version="1.0.0")