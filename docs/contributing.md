# Contributing

Thank you for being interested in contributing to Starlette.
There are many ways you can contribute to the project:

- Try Starlette and [report bugs/issues you find](https://github.com/encode/starlette/issues/new)
- [Implement new features](https://github.com/encode/starlette/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
- [Review Pull Requests of others](https://github.com/encode/starlette/pulls)
- Write documentation
- Participate in discussions

## Reporting Bugs or Other Issues

Found something that Starlette should support?
Stumbled upon some unexpected behaviour?

Contributions should generally start out with [a discussion](https://github.com/encode/starlette/discussions).
Possible bugs may be raised as a "Potential Issue" discussion, feature requests may
be raised as an "Ideas" discussion. We can then determine if the discussion needs
to be escalated into an "Issue" or not, or if we'd consider a pull request.

Try to be more descriptive as you can and in case of a bug report,
provide as much information as possible like:

- OS platform
- Python version
- Installed dependencies and versions (`python -m pip freeze`)
- Code snippet
- Error traceback

You should always try to reduce any examples to the *simplest possible case*
that demonstrates the issue.

## Development

To start developing Starlette, create a **fork** of the
[Starlette repository](https://github.com/encode/starlette) on GitHub.

Then clone your fork with the following command replacing `YOUR-USERNAME` with
your GitHub username:

```shell
$ git clone https://github.com/YOUR-USERNAME/starlette
```

You can now install the project and its dependencies using:

```shell
$ cd starlette
$ scripts/install
```

## Testing and Linting

We use custom shell scripts to automate testing, linting,
and documentation building workflow.

To run the tests, use:

```shell
$ scripts/test
```

Any additional arguments will be passed to `pytest`. See the [pytest documentation](https://docs.pytest.org/en/latest/how-to/usage.html) for more information.

For example, to run a single test script:

```shell
$ scripts/test tests/test_application.py
```

To run the code auto-formatting:

```shell
$ scripts/lint
```

Lastly, to run code checks separately (they are also run as part of `scripts/test`), run:

```shell
$ scripts/check
```

## Documenting

Documentation pages are located under the `docs/` folder.

To run the documentation site locally (useful for previewing changes), use:

```shell
$ scripts/docs
```

## Resolving Build / CI Failures

Once you've submitted your pull request, the test suite will automatically run, and the results will show up in GitHub.
If the test suite fails, you'll want to click through to the "Details" link, and try to identify why the test suite failed.

<p align="center" style="margin: 0 0 10px">
  <img src="https://raw.githubusercontent.com/encode/starlette/master/docs/img/gh-actions-fail.png" alt='Failing PR commit status'>
</p>

Here are some common ways the test suite can fail:

### Check Job Failed

<p align="center" style="margin: 0 0 10px">
  <img src="https://raw.githubusercontent.com/encode/starlette/master/docs/img/gh-actions-fail-check.png" alt='Failing GitHub action lint job'>
</p>

This job failing means there is either a code formatting issue or type-annotation issue.
You can look at the job output to figure out why it's failed or within a shell run:

```shell
$ scripts/check
```

It may be worth it to run `$ scripts/lint` to attempt auto-formatting the code
and if that job succeeds commit the changes.

### Docs Job Failed

This job failing means the documentation failed to build. This can happen for
a variety of reasons like invalid markdown or missing configuration within `mkdocs.yml`.

### Python 3.X Job Failed

<p align="center" style="margin: 0 0 10px">
  <img src="https://raw.githubusercontent.com/encode/starlette/master/docs/img/gh-actions-fail-test.png" alt='Failing GitHub action test job'>
</p>

This job failing means the unit tests failed or not all code paths are covered by unit tests.

If tests are failing you will see this message under the coverage report:

`=== 1 failed, 435 passed, 1 skipped, 1 xfailed in 11.09s ===`

If tests succeed but coverage doesn't reach our current threshold, you will see this
message under the coverage report:

`FAIL Required test coverage of 100% not reached. Total coverage: 99.00%`

## Releasing

*This section is targeted at Starlette maintainers.*

Before releasing a new version, create a pull request that includes:

- **An update to the changelog**:
    - We follow the format from [keepachangelog](https://keepachangelog.com/en/1.0.0/).
    - [Compare](https://github.com/encode/starlette/compare/) `master` with the tag of the latest release, and list all entries that are of interest to our users:
        - Things that **must** go in the changelog: added, changed, deprecated or removed features, and bug fixes.
        - Things that **should not** go in the changelog: changes to documentation, tests or tooling.
        - Try sorting entries in descending order of impact / importance.
        - Keep it concise and to-the-point. 🎯
- **A version bump**: see `__version__.py`.

For an example, see [#1600](https://github.com/encode/starlette/pull/1600).

Once the release PR is merged, create a
[new release](https://github.com/encode/starlette/releases/new) including:

- Tag version like `0.13.3`.
- Release title `Version 0.13.3`
- Description copied from the changelog.

Once created this release will be automatically uploaded to PyPI.

If something goes wrong with the PyPI job the release can be published using the
`scripts/publish` script.
