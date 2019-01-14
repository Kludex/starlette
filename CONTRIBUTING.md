# Contributing to Starlette

The Starlette team happily welcomes contributions. This document will help you get ready to contribute to Starlette!

This guide references utility shell scripts that were written to automate common tasks. You can find them in the [scripts](./scripts) directory.

These scripts are currently suited to **Linux** and **macOS**, but we would happily take PRs to help us make them more cross-compatible or update the instructions.

> **NOTE**: before writing any code, please first consider [opening an issue][issues] to discuss your ideas with the maintainers.

## Setting up the repository

1. Fork the repo.
2. Clone your fork on your local computer: `git clone https://github.com/<username>/starlette.git`.
3. Install Starlette locally and run the tests (see next sections).
4. Create a branch for your work, e.g. `git checkout -b fix-some-bug`.
5. Remember to include tests and documentation updates if applicable.
6. Once ready, push to your remote: `git push origin fix-some-bug`.
 7. [Open a PR][pr] on the main repo.

## Install

Use the `install` script to install project dependencies in a virtual environment.

```bash
./scripts/install
```

Your Python version will be verified and the virtual environment created using the `python3` executable. To use another executable, use the `-p` option, e.g.:

```bash
./scripts/install -p py
```

## Running the tests

The tests are written using [pytest] and located in the `tests/` directory.

**Note**: tests should be run before making any changes to the code in order to make sure that everything is running as expected.

We provide a stand-alone **test script** to run tests in a reliable manner. Run it with:

```bash
./scripts/test
```

By default, tests involving a database are excluded. To include them, set the `STARLETTE_TEST_DATABASE` environment variable to the URL of a PostgreSQL database, e.g.:

```bash
export STARLETTE_TEST_DATABASE="postgresql://localhost/starlette"
```

## Linting

We use [Black] as a code formatter. To run it along with a few other linting tools, we provide a stand-alone linting script:

```bash
./scripts/lint
```

If linting has anything to say about the code, it will format it in-place.

To keep the code style consistent, you should apply linting before committing.

## Documentation

The documentation is built with [MkDocs], a Markdown-based documentation site generator.

To run the docs site in hot-reload mode (useful when editing the docs), run `$ mkdocs serve` in the project root directory.

For your information, the docs site configuration is located in the `mkdocs.yml` file.

Please refer to the [MkDocs docs][MkDocs] for more usage information, including how to add new pages.

[issues]: https://github.com/encode/starlette/issues/new
[pr]: https://github.com/encode/starlette/compare
[pytest]: https://docs.pytest.org
[pytest-cov]: https://github.com/pytest-dev/pytest-cov
[Black]: https://www.google.com/search?client=safari&rls=en&q=github+black&ie=UTF-8&oe=UTF-8
[MkDocs]: https://www.mkdocs.org
