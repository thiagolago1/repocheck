import json
from dataclasses import asdict

import click

from repocheck.analysis import run_analysis
from repocheck.precheck import run_precheck
from repocheck.report import render_report
from repocheck.verdict import compute_verdict
from repocheck.vm import MultipassNotAvailable


@click.command()
@click.argument("url")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output raw JSON instead of a human-readable report.",
)
def main(url: str, as_json: bool) -> None:
    click.echo("Checking repository reputation...", err=True)
    precheck = run_precheck(url)

    analysis = None
    multipass_warning = None
    try:
        analysis = run_analysis(
            url, on_progress=lambda message: click.echo(message, err=True)
        )
    except MultipassNotAvailable as exc:
        multipass_warning = str(exc)

    verdict_result = compute_verdict(precheck, analysis)

    if as_json:
        payload = {
            "verdict": verdict_result.verdict.value,
            "reasons": verdict_result.reasons,
            "precheck": asdict(precheck),
            "analysis": asdict(analysis) if analysis is not None else None,
            "multipass_warning": multipass_warning,
        }
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    if multipass_warning is not None:
        click.echo(f"WARNING: {multipass_warning}")
        click.echo("")

    click.echo(render_report(precheck, analysis, verdict_result))


if __name__ == "__main__":
    main()
