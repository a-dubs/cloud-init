import ast
import os
import yaml
import argparse
import sys

def has_type_hint(node):
    """Check if a node has type hints."""
    # if there are no arguments, return True since no type hints are needed
    if not node.args.args:
        return True
    return any(
        isinstance(arg.annotation, ast.AST)
        for arg in node.args.args
        if arg.annotation
    )


def has_return_type_hint(node):
    """Check if a node has a return type hint."""
    return node.returns is not None


def has_docstring(node):
    """Check if a node has a docstring."""
    return (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and len(node.body) > 0
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, (ast.Str, ast.Constant))
    )


def find_functions_info(directories, analyze_docstrings, analyze_type_hints):
    total_number_of_functions = 0
    """Find functions without type hints and functions without docstrings in multiple directories."""
    files_info = {}
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    functions_without_type_hints = []
                    functions_without_docstrings = []
                    with open(file_path, "r") as f:
                        try:
                            tree = ast.parse(f.read(), filename=file_path)
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef):
                                    total_number_of_functions += 1
                                    if analyze_type_hints:
                                        if not has_type_hint(
                                            node
                                        ) or not has_return_type_hint(node):
                                            functions_without_type_hints.append(
                                                node.name
                                            )
                                    if analyze_docstrings:
                                        if not has_docstring(node):
                                            functions_without_docstrings.append(
                                                node.name
                                            )
                        except SyntaxError:
                            print(f"Error parsing {file_path}. Skipping...")

                    file_relative_path = os.path.relpath(file_path, directory)
                    file_info = {}
                    if analyze_type_hints:
                        file_info["functions_without_type_hints"] = (
                            functions_without_type_hints
                        )
                    if analyze_docstrings:
                        file_info["functions_without_docstrings"] = (
                            functions_without_docstrings
                        )
                    if file_info:  # Only add if there is data
                        files_info[file_relative_path] = file_info
    return files_info, total_number_of_functions


def save_to_yaml(data, output_file):
    """Save data to a YAML file."""
    with open(output_file, "w") as f:
        yaml.dump(data, f)


def count_functions(info, key):
    """Count the number of functions based on the specified key."""
    return sum(len(file_info.get(key, [])) for file_info in info.values())


def analyze(directories, output_file, analyze_docstrings, analyze_type_hints):
    functions_info, total_number_of_functions = find_functions_info(
        directories, analyze_docstrings, analyze_type_hints
    )
    print(f"Total number of functions: {total_number_of_functions}")
    save_to_yaml(functions_info, output_file)
    if analyze_type_hints:
        print(
            f"Total functions without type hints: {count_functions(functions_info, 'functions_without_type_hints')}"
        )
    if analyze_docstrings:
        print(
            f"Total functions without docstrings: {count_functions(functions_info, 'functions_without_docstrings')}"
        )


def compare(existing_analysis_file, new_analysis_file):
    print(
        f"Comparing existing analysis ({existing_analysis_file}) with new analysis ({new_analysis_file})"
    )
    existing_info = yaml.safe_load(open(existing_analysis_file))
    new_info = yaml.safe_load(open(new_analysis_file))

    # Determine which keys are present in the data
    keys_to_compare = set()
    for file_info in new_info.values():
        keys_to_compare.update(file_info.keys())
    if not keys_to_compare:
        print("No data to compare in new analysis file.")
        sys.exit(1)

    errors = []
    new_issues = {}

    for key in keys_to_compare:
        existing_count = count_functions(existing_info, key)
        new_count = count_functions(new_info, key)
        print(f"Existing analysis - {key.replace('_', ' ')}: {existing_count}")
        print(f"New analysis - {key.replace('_', ' ')}: {new_count}")

        new_functions = []
        for file, data in new_info.items():
            new_functions_set = set(data.get(key, []))
            existing_functions_set = set(
                existing_info.get(file, {}).get(key, [])
            )
            added_funcs = new_functions_set - existing_functions_set
            if added_funcs:
                new_functions.extend(
                    [f"{file}: {func}" for func in added_funcs]
                )
        if new_functions:
            errors.append(
                f'Error: Number of {key.replace("_", " ")} increased'
            )
            new_issues[key] = new_functions

    for key, functions in new_issues.items():
        print(f"New functions {key.replace('_', ' ')}:")
        for func in functions:
            print(f"  {func}")

    if errors:
        for error in errors:
            print(error)
        sys.exit(1)
    else:
        print("No new issues found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze Python functions in directories or compare results."
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze the functions in directories."
    )
    analyze_parser.add_argument(
        "--output-file", type=str, required=True, help="Output YAML file"
    )
    analyze_parser.add_argument(
        "--dir",
        type=str,
        action="append",
        required=True,
        help="Directory to analyze (can be specified multiple times)",
    )
    analyze_parser.add_argument(
        "--docstrings", action="store_true", help="Analyze docstrings"
    )
    analyze_parser.add_argument(
        "--type-hints", action="store_true", help="Analyze type hints"
    )

    compare_parser = subparsers.add_parser(
        "compare", help="Compare the results of two analyses."
    )
    compare_parser.add_argument(
        "--existing-analysis",
        type=str,
        required=True,
        help="Existing/current analysis YAML file",
    )
    compare_parser.add_argument(
        "--new-analysis",
        type=str,
        required=True,
        help="New/modified analysis YAML file",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        if not args.docstrings and not args.type_hints:
            parser.error(
                "At least one of --docstrings or --type-hints must be specified."
            )
        analyze(args.dir, args.output_file, args.docstrings, args.type_hints)
    elif args.command == "compare":
        compare(args.existing_analysis, args.new_analysis)
    else:
        parser.print_help()
