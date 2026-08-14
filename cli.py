from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def banner():
    console.clear()

    console.print(
        Text(
            """
 ███████╗ ██████╗ █████╗ ██████╗  █████╗
 ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗
 ███████╗██║     ███████║██║  ██║███████║
 ╚════██║██║     ██╔══██║██║  ██║██╔══██║
 ███████║╚██████╗██║  ██║██████╔╝██║  ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝
            """,
            style="bold green"
        )
    )

    console.print(
        "[bold cyan]        SCADA SECURITY FRAMEWORK[/bold cyan]"
    )

    console.print(
        "[bold magenta]             BASELINE IDS[/bold magenta]\n"
    )


def menu():

    console.print(
        Panel(
            """
[bold white]  [1][/bold white] Live Network Capture

[bold white]  [2][/bold white] Analyze PCAP File

[bold white]  [3][/bold white] Exit
            """,
            title="[bold green]CAPTURE MODE[/bold green]",
            border_style="green"
        )
    )


def CLIchoice():

    banner()

    console.print("[green][+][/green] Initializing IDS............... [bold green]OK[/bold green]")
    console.print("[green][+][/green] Loading protocol engine........ [bold green]OK[/bold green]")
    console.print("[green][+][/green] Loading detector............... [bold green]OK[/bold green]")
    console.print("[green][+][/green] Loading risk engine............ [bold green]OK[/bold green]")

    while True:

        menu()

        choice = console.input(
            "\n[bold green]scada@ids[/bold green] > "
        )

        if choice == "1":
            console.print("\n[green][+][/green] Live capture selected")
            # call your existing live capture function here
            break

        elif choice == "2":
            console.print("\n[green][+][/green] PCAP analysis selected")

            pcap = console.input(
                "[bold green]scada@ids[/bold green] > "
            )

            # call your existing PCAP analysis function here
            break

        elif choice == "3":
            console.print("[yellow][*] Exiting...[/yellow]")
            break

        else:
            console.print("[red][-] Invalid option[/red]")

        return choice

if __name__=="__main__":
    CLIchoice()