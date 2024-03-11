import ast
import os
import subprocess
import sys
import tempfile
import shutil

def count_params_without_type_hints(node):
    """Count the number of parameters without type hints."""
    return sum(1 for arg in node.args.args if not arg.annotation)

def has_type_hint(node):
    """Check if a function has type hints."""
    total_params = len(node.args.args)
    params_without_type_hints = count_params_without_type_hints(node)
    return params_without_type_hints == 0

def has_docstring(node):
    """Check if a node has a docstring."""
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Str)

def find_functions_info(directory):
    """Find functions without type hints and functions without docstrings."""
    files_info = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                functions_without_type_hints = []
                functions_without_docstrings = []
                with open(file_path, 'r') as f:
                    try:
                        tree = ast.parse(f.read(), filename=file_path)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.FunctionDef):
                                if not has_type_hint(node):
                                    functions_without_type_hints.append(node.name)
                                if not has_docstring(node):
                                    functions_without_docstrings.append(node.name)
                    except SyntaxError:
                        print(f"Error parsing {file_path}. Skipping...")
                
                files_info[os.path.relpath(file_path, directory)] = {
                    "functions_without_type_hints": functions_without_type_hints,
                    "functions_without_docstrings": functions_without_docstrings
                }

    return files_info

def compare_with_main(directory):
    """Compare functions in the current directory with the main branch."""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()

    try:
        # Clone the repository into the temporary directory
        subprocess.run(["git", "clone", ".", temp_dir], check=True)

        # Switch to the main branch
        subprocess.run(["git", "checkout", "main"], cwd=temp_dir, check=True)

        # Analyze main branch
        main_info = find_functions_info(temp_dir + "/" + directory)

        # Analyze current directory
        current_info = find_functions_info(directory)

        diff_type_hints = set(current_info.keys()) - set(main_info.keys())
        diff_docstrings = set(current_info.keys()) - set(main_info.keys())

        for file in current_info.keys():
            if file in main_info:
                diff_type_hints.update(set(current_info[file]['functions_without_type_hints']) - set(main_info[file]['functions_without_type_hints']))
                diff_docstrings.update(set(current_info[file]['functions_without_docstrings']) - set(main_info[file]['functions_without_docstrings']))

        return diff_type_hints, diff_docstrings

    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)

def main():
    current_directory = os.getcwd()

    diff_type_hints, diff_docstrings = compare_with_main(current_directory)

    if diff_type_hints or diff_docstrings:
        print("Functions with missing type hints or docstrings found:")
        if diff_type_hints:
            print("Functions with missing type hints:")
            print(diff_type_hints)
        if diff_docstrings:
            print("Functions with missing docstrings:")
            print(diff_docstrings)
        sys.exit(1)  # Exit with a non-zero status
    else:
        print("No functions with missing type hints or docstrings found.")

if __name__ == "__main__":
    main()
