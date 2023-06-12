# -*- coding: utf-8 -*-

import os

import click
from cookiecutter.main import cookiecutter  # type: ignore
from rich import print
from rich.console import Console

from port_ocean.cli.download_git_folder import download_folder
from port_ocean.cli.list_integrations import list_git_folders


def print_logo() -> None:
    ascii_art = """
=====================================================================================
          ::::::::       ::::::::       ::::::::::           :::        ::::    ::: 
        :+:    :+:     :+:    :+:      :+:                :+: :+:      :+:+:   :+:  
       +:+    +:+     +:+             +:+               +:+   +:+     :+:+:+  +:+   
      +#+    +:+     +#+             +#++:++#         +#++:++#++:    +#+ +:+ +#+    
     +#+    +#+     +#+             +#+              +#+     +#+    +#+  +#+#+#     
    #+#    #+#     #+#    #+#      #+#              #+#     #+#    #+#   #+#+#      
    ########       ########       ##########       ###     ###    ###    ####      
=====================================================================================
By: Port.io
        """

    # Display ASCII art
    Console().print(ascii_art)


@click.group()
def cli_start() -> None:
    # Ocean root command
    pass


@cli_start.command()
@click.argument("path", default=".")
def sail(path: str) -> None:
    from port_ocean.port_ocean import run

    print_logo()

    print("Setting sail... ⛵️⚓️⛵️⚓️ All hands on deck! ⚓️")
    run(path)


@cli_start.command()
def new() -> None:
    print_logo()

    console = Console()
    console.print(
        "🚢 Unloading cargo... Setting up your integration at the port.", style="bold"
    )

    cookiecutter(f"{os.path.dirname(__file__)}/cookiecutter")

    console.print(
        "\n🌊 Ahoy, Captain! Your project has set sail into the vast ocean of possibilities!",
        style="bold",
    )
    console.print("Here are your next steps: \n", style="bold")
    console.print(
        "⚓️ Install necessary packages: Run [bold][blue]make install[/blue][/bold] to install all required packages for your project."
    )
    console.print(
        "⚓️ Set sail with [blue]Ocean[/blue]: Run [bold][blue]ocean sail[/blue] <path_to_integration>[/bold] to run the project using Ocean."
    )
    console.print(
        "⚓️ Smooth sailing with [blue]Make[/blue]: Alternatively, you can run [bold][blue]make run[/blue][/bold] to launch your project using Make. \n"
    )


@cli_start.command(name="list")
def list_integrations() -> None:
    console = Console()
    console.print("🌊 Here are the integrations available to you:", style="bold")
    options = list_git_folders("https://github.com/port-labs/pulumi", "examples")

    for option in options:
        console.print(f"⚓️ [bold][blue]{option}[/blue][/bold]")


@cli_start.command()
@click.argument("name")
def pull(name: str) -> None:
    download_folder(
        "https://github.com/port-labs/pulumi", f"examples/{name}", f"./{name}"
    )
