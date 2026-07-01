import json
from dataclasses import asdict

import click

from repocheck.precheck import run_precheck


@click.command()
@click.argument("url")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output raw JSON instead of a human-readable summary.",
)
def main(url: str, as_json: bool) -> None:
    result = run_precheck(url)

    if as_json:
        click.echo(json.dumps(asdict(result), indent=2, default=str))
        return

    click.echo(f"Platform: {result.location.platform}")
    click.echo(f"Owner/repo: {result.location.owner}/{result.location.repo}")

    if not result.reachable:
        click.echo(f"Reachable: no ({result.error})")
    else:
        click.echo("Reachable: yes")
        click.echo(f"Age (days): {result.age_days}")
        click.echo(f"Stars: {result.stars}")
        click.echo(f"Forks: {result.forks}")
        click.echo(f"Owner type: {result.owner_type}")

    if result.possible_typosquat:
        click.echo(
            f"WARNING: name is suspiciously close to popular repo '{result.typosquat_match}'"
        )


if __name__ == "__main__":
    main()
