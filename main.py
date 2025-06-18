from pydantic import BaseModel, ValidationError
from typing import Optional, Annotated
import os
import glob
import yaml
import re
import subprocess
import typer
from rich.console import Console
from rich.table import Table

# Initialize Typer app and Rich console
app = typer.Typer(
    name="loas",
    help="LOAS (Living Off AppleScript) - Convert YAML test definitions to OSAScript applications",
    add_completion=False,
)
console = Console()


class Script(BaseModel):
    name: str
    command: str
    elevation_required: Optional[bool] = False
    tcc_required: Optional[bool] = False
    args: Optional[dict] = None

    def to_osascript(self) -> str:
        """Convert the script to OSAScript format with help function and parameter handling"""
        script_lines = []

        # Check if command uses frameworks and add them at the top level
        if "use framework" in self.command:
            framework_lines = []
            command_lines = []
            for line in self.command.strip().split("\n"):
                if line.strip().startswith("use framework"):
                    framework_lines.append(line.strip())
                else:
                    command_lines.append(line)

            # Add frameworks at the top
            for framework_line in framework_lines:
                script_lines.append(framework_line)
            script_lines.append("")

            # Update command to exclude framework declarations
            self.command = "\n".join(command_lines)

        # Add help function
        script_lines.append("on show_help()")
        script_lines.append(f'    log "{self.name}"')
        script_lines.append('    log ""')
        script_lines.append('    log "Usage: Run this script to execute the command."')

        if self.args:
            script_lines.append('    log ""')
            script_lines.append('    log "Available arguments (in order):"')
            for i, (arg_name, default_value) in enumerate(self.args.items(), 1):
                # Escape special characters and avoid bullet points that might cause issues
                script_lines.append(
                    f'    log "  {i}. {arg_name}: {type(default_value).__name__} (default: {default_value})"'
                )

            script_lines.append('    log ""')
            script_lines.append('    log "Usage examples:"')
            script_lines.append(
                '    log "  osascript script.scpt                    # Use all defaults"'
            )

            # Show examples with different numbers of arguments (avoid nested quotes)
            if len(self.args) == 1:
                arg_name = list(self.args.keys())[0]
                script_lines.append(
                    f'    log "  osascript script.scpt [value]            # Set {arg_name}"'
                )
            else:
                script_lines.append(
                    '    log "  osascript script.scpt [arg1]             # Set first argument"'
                )
                script_lines.append(
                    '    log "  osascript script.scpt [arg1] [arg2] ...  # Set all arguments"'
                )

        script_lines.append("end show_help")
        script_lines.append("")

        if self.args:
            # Create main function with regular parameters
            param_list = list(self.args.keys())
            script_lines.append(f"on main({', '.join(param_list)})")

            # Replace template variables in command
            command = self.command
            for arg_name, default_value in self.args.items():
                # Replace "#{arg_name}" (with quotes) with just the parameter name
                command = command.replace(f'"#{{{arg_name}}}"', arg_name)
                # Replace #{arg_name} (without quotes) with the parameter name
                command = command.replace(f"#{{{arg_name}}}", arg_name)

            # Add the command to the function
            for line in command.strip().split("\n"):
                if line.strip():  # Only add non-empty lines
                    script_lines.append(f"    {line.strip()}")

            script_lines.append("end main")
            script_lines.append("")

            # Add example usage with default values
            script_lines.append("-- Example usage with default values:")
            example_params = []
            for arg_name, default_value in self.args.items():
                if isinstance(default_value, str):
                    example_params.append(f'"{default_value}"')
                elif isinstance(default_value, bool):
                    example_params.append("true" if default_value else "false")
                else:
                    example_params.append(str(default_value))

            script_lines.append(f"-- main({', '.join(example_params)})")
            script_lines.append("")

            # Add command line argument handling
            script_lines.append("-- Handle command line arguments")
            script_lines.append("on run argv")
            script_lines.append(
                '    if (count of argv) > 0 and item 1 of argv is "-h" then'
            )
            script_lines.append("        show_help()")
            script_lines.append("        return")
            script_lines.append("    end if")
            script_lines.append("    ")

            # Generate argument parsing logic
            arg_names = list(self.args.keys())
            for i, (arg_name, default_value) in enumerate(self.args.items()):
                script_lines.append(f"    -- Parse {arg_name} (argument {i + 1})")
                script_lines.append(f"    if (count of argv) > {i} then")
                script_lines.append(f"        set {arg_name} to item {i + 1} of argv")
                script_lines.append("    else")
                if isinstance(default_value, str):
                    script_lines.append(f'        set {arg_name} to "{default_value}"')
                elif isinstance(default_value, bool):
                    script_lines.append(
                        f"        set {arg_name} to {'true' if default_value else 'false'}"
                    )
                else:
                    script_lines.append(f"        set {arg_name} to {default_value}")
                script_lines.append("    end if")
                script_lines.append("    ")

            # Call main with parsed arguments
            param_list = arg_names
            script_lines.append(f"    main({', '.join(param_list)})")
            script_lines.append("end run")

        else:
            # Simple script without parameters
            script_lines.append("on main()")
            for line in self.command.strip().split("\n"):
                if line.strip():  # Only add non-empty lines
                    script_lines.append(f"    {line.strip()}")
            script_lines.append("end main")
            script_lines.append("")

            # Add command line argument handling
            script_lines.append("on run argv")
            script_lines.append(
                '    if (count of argv) > 0 and item 1 of argv is "-h" then'
            )
            script_lines.append("        show_help()")
            script_lines.append("        return")
            script_lines.append("    end if")
            script_lines.append("    ")
            script_lines.append("    main()")
            script_lines.append("end run")

        return "\n".join(script_lines)

    def get_filename(self) -> str:
        """Generate a safe filename for the script"""
        # Remove special characters and replace spaces with underscores
        safe_name = re.sub(r"[^\w\s-]", "", self.name)
        safe_name = re.sub(r"[-\s]+", "_", safe_name)
        return f"{safe_name.lower()}.scpt"


class File(BaseModel):
    name: str
    tests: list[Script]


def validate_yaml_files(yaml_dir: str = "yaml") -> bool:
    """Validate all YAML files in the specified directory"""
    errors = []
    files_validated = 0

    for file in glob.glob(f"{yaml_dir}/**/*.yaml", recursive=True):
        with open(file, "r") as f:
            try:
                script = yaml.safe_load(f)
                script = File(**script)
                files_validated += 1
                console.print(f"✅ [green]Validated[/green] {file}")
            except ValidationError as e:
                errors.append(f"Error validating {file}: {e}")
                console.print(f"❌ [red]Error[/red] validating {file}: {e}")
            except Exception as e:
                errors.append(f"Unexpected error in {file}: {e}")
                console.print(f"❌ [red]Unexpected error[/red] in {file}: {e}")

    if errors:
        console.print(f"\n[red]Validation failed with {len(errors)} errors[/red]")
        return False

    console.print(
        f"\n[green]✅ All {files_validated} YAML files validated successfully[/green]"
    )
    return True


def compile_osascript_files(
    osascript_dir: str = "osascripts", output_dir: str = "releases"
) -> bool:
    """Compile OSAScript files to .app bundles"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create subdirectories for each technique
    if os.path.exists(osascript_dir):
        for folder in os.listdir(osascript_dir):
            folder_path = os.path.join(osascript_dir, folder)
            if os.path.isdir(folder_path):
                os.makedirs(os.path.join(output_dir, folder), exist_ok=True)

    compiled_count = 0
    errors = []

    for file in glob.glob(f"{osascript_dir}/**/*.scpt", recursive=True):
        try:
            output_file = file.replace(".scpt", ".app").replace(
                osascript_dir, output_dir
            )
            result = subprocess.run(
                ["osacompile", "-o", output_file, file], capture_output=True, text=True
            )

            if result.returncode == 0:
                compiled_count += 1
                console.print(f"✅ [green]Compiled[/green] {file} → {output_file}")
            else:
                error_msg = f"Failed to compile {file}: {result.stderr}"
                errors.append(error_msg)
                console.print(
                    f"❌ [red]Failed[/red] to compile {file}: {result.stderr}"
                )

        except Exception as e:
            error_msg = f"Unexpected error compiling {file}: {e}"
            errors.append(error_msg)
            console.print(f"❌ [red]Unexpected error[/red] compiling {file}: {e}")

    if errors:
        console.print(f"\n[red]Compilation completed with {len(errors)} errors[/red]")
        console.print(f"[green]Successfully compiled: {compiled_count} files[/green]")
        return False

    console.print(
        f"\n[green]✅ Successfully compiled {compiled_count} OSAScript files[/green]"
    )
    return True


def convert_yaml_to_osascript(
    yaml_dir: str = "yaml", output_dir: str = "osascripts"
) -> bool:
    """Convert all YAML test commands to separate OSAScript files"""

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    converted_count = 0
    errors = []

    for file_path in glob.glob(f"{yaml_dir}/**/*.yaml", recursive=True):
        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                file_obj = File(**data)

                # Create subdirectory based on the YAML file structure
                yaml_dir_path = os.path.dirname(file_path)
                technique_name = os.path.basename(yaml_dir_path)
                script_output_dir = os.path.join(output_dir, technique_name)

                if not os.path.exists(script_output_dir):
                    os.makedirs(script_output_dir)

                # Convert each test to an OSAScript file
                for script in file_obj.tests:
                    osascript_content = script.to_osascript()
                    filename = script.get_filename()
                    output_path = os.path.join(script_output_dir, filename)

                    with open(output_path, "w") as script_file:
                        script_file.write(osascript_content)

                    converted_count += 1
                    console.print(f"✅ [green]Created[/green] {output_path}")

        except ValidationError as e:
            error_msg = f"Validation error in {file_path}: {e}"
            errors.append(error_msg)
            console.print(f"❌ [red]Validation error[/red] in {file_path}: {e}")
        except Exception as e:
            error_msg = f"Unexpected error processing {file_path}: {e}"
            errors.append(error_msg)
            console.print(f"❌ [red]Unexpected error[/red] processing {file_path}: {e}")

    if errors:
        console.print(f"\n[red]Conversion completed with {len(errors)} errors[/red]")
        console.print(
            f"[green]Successfully converted: {converted_count} scripts[/green]"
        )
        return False

    console.print(
        f"\n[green]✅ Successfully converted {converted_count} scripts[/green]"
    )
    return True


@app.command()
def validate(
    yaml_dir: Annotated[
        str, typer.Option("--yaml-dir", "-y", help="Directory containing YAML files")
    ] = "yaml",
):
    """Validate YAML test definition files"""
    console.print("[bold blue]🔍 Validating YAML files...[/bold blue]")

    if not os.path.exists(yaml_dir):
        console.print(f"[red]❌ YAML directory '{yaml_dir}' does not exist[/red]")
        raise typer.Exit(1)

    success = validate_yaml_files(yaml_dir)
    if not success:
        raise typer.Exit(1)


@app.command()
def convert(
    yaml_dir: Annotated[
        str, typer.Option("--yaml-dir", "-y", help="Directory containing YAML files")
    ] = "yaml",
    output_dir: Annotated[
        str,
        typer.Option("--output-dir", "-o", help="Output directory for OSAScript files"),
    ] = "osascripts",
):
    """Convert YAML test definitions to OSAScript files"""
    console.print("[bold blue]🔄 Converting YAML to OSAScript files...[/bold blue]")

    if not os.path.exists(yaml_dir):
        console.print(f"[red]❌ YAML directory '{yaml_dir}' does not exist[/red]")
        raise typer.Exit(1)

    success = convert_yaml_to_osascript(yaml_dir, output_dir)
    if not success:
        raise typer.Exit(1)


@app.command()
def compile(
    osascript_dir: Annotated[
        str,
        typer.Option(
            "--osascript-dir", "-s", help="Directory containing OSAScript files"
        ),
    ] = "osascripts",
    output_dir: Annotated[
        str,
        typer.Option("--output-dir", "-o", help="Output directory for compiled apps"),
    ] = "releases",
):
    """Compile OSAScript files to .app bundles"""
    console.print(
        "[bold blue]🔨 Compiling OSAScript files to .app bundles...[/bold blue]"
    )

    if not os.path.exists(osascript_dir):
        console.print(
            f"[red]❌ OSAScript directory '{osascript_dir}' does not exist[/red]"
        )
        raise typer.Exit(1)

    success = compile_osascript_files(osascript_dir, output_dir)
    if not success:
        raise typer.Exit(1)


@app.command()
def build(
    yaml_dir: Annotated[
        str, typer.Option("--yaml-dir", "-y", help="Directory containing YAML files")
    ] = "yaml",
    osascript_dir: Annotated[
        str, typer.Option("--osascript-dir", "-s", help="Directory for OSAScript files")
    ] = "osascripts",
    output_dir: Annotated[
        str,
        typer.Option("--output-dir", "-o", help="Output directory for compiled apps"),
    ] = "releases",
):
    """Complete build process: validate, convert, and compile"""
    console.print("[bold blue]🚀 Starting complete build process...[/bold blue]")

    # Validate
    console.print("\n[bold]Step 1: Validation[/bold]")
    if not validate_yaml_files(yaml_dir):
        raise typer.Exit(1)

    # Convert
    console.print("\n[bold]Step 2: Conversion[/bold]")
    if not convert_yaml_to_osascript(yaml_dir, osascript_dir):
        raise typer.Exit(1)

    # Compile
    console.print("\n[bold]Step 3: Compilation[/bold]")
    if not compile_osascript_files(osascript_dir, output_dir):
        raise typer.Exit(1)

    console.print("\n[bold green]🎉 Build completed successfully![/bold green]")


@app.command()
def stats(
    yaml_dir: Annotated[
        str, typer.Option("--yaml-dir", "-y", help="Directory containing YAML files")
    ] = "yaml",
    osascript_dir: Annotated[
        str,
        typer.Option(
            "--osascript-dir", "-s", help="Directory containing OSAScript files"
        ),
    ] = "osascripts",
    output_dir: Annotated[
        str,
        typer.Option("--output-dir", "-o", help="Directory containing compiled apps"),
    ] = "releases",
):
    """Show statistics about YAML files, OSAScript files, and compiled apps"""

    table = Table(title="LOAS Project Statistics")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Count", style="magenta")
    table.add_column("Details", style="green")

    # Count YAML files
    yaml_files = glob.glob(f"{yaml_dir}/**/*.yaml", recursive=True)
    yaml_count = len(yaml_files)

    # Count techniques (directories in yaml)
    techniques = set()
    for file in yaml_files:
        technique = os.path.basename(os.path.dirname(file))
        techniques.add(technique)

    # Count OSAScript files
    osascript_files = (
        glob.glob(f"{osascript_dir}/**/*.scpt", recursive=True)
        if os.path.exists(osascript_dir)
        else []
    )
    osascript_count = len(osascript_files)

    # Count compiled apps
    app_files = (
        glob.glob(f"{output_dir}/**/*.app", recursive=True)
        if os.path.exists(output_dir)
        else []
    )
    app_count = len(app_files)

    table.add_row("YAML Files", str(yaml_count), f"Across {len(techniques)} techniques")
    table.add_row("OSAScript Files", str(osascript_count), "Generated from YAML")
    table.add_row("Compiled Apps", str(app_count), "Ready to execute")

    console.print(table)

    if yaml_count > 0:
        console.print("\n[bold]Techniques found:[/bold]")
        for technique in sorted(techniques):
            console.print(f"  • {technique}")


@app.command()
def clean(
    osascript_dir: Annotated[
        str,
        typer.Option(
            "--osascript-dir", "-s", help="Directory containing OSAScript files"
        ),
    ] = "osascripts",
    output_dir: Annotated[
        str,
        typer.Option("--output-dir", "-o", help="Directory containing compiled apps"),
    ] = "releases",
    confirm: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")
    ] = False,
):
    """Clean generated files (OSAScript files and compiled apps)"""

    dirs_to_clean = []
    if os.path.exists(osascript_dir):
        dirs_to_clean.append(osascript_dir)
    if os.path.exists(output_dir):
        dirs_to_clean.append(output_dir)

    if not dirs_to_clean:
        console.print("[yellow]No directories to clean[/yellow]")
        return

    if not confirm:
        console.print("[yellow]This will delete the following directories:[/yellow]")
        for dir_path in dirs_to_clean:
            console.print(f"  • {dir_path}")

        if not typer.confirm("Are you sure you want to continue?"):
            console.print("[yellow]Operation cancelled[/yellow]")
            return

    import shutil

    for dir_path in dirs_to_clean:
        try:
            shutil.rmtree(dir_path)
            console.print(f"✅ [green]Cleaned[/green] {dir_path}")
        except Exception as e:
            console.print(f"❌ [red]Failed to clean[/red] {dir_path}: {e}")


if __name__ == "__main__":
    app()
