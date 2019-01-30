# Contributing to Starlette

The Starlette team happily welcomes contributions. This document will help you get ready to contribute to Starlette!

To submit new code to the project you'll need to:

* Fork the repo.
* Clone your fork on your local computer: `git clone https://github.com/<username>/starlette.git`.
* Install Starlette locally and run the tests: `./scripts/install`, `./scripts/test`.
* Create a branch for your work, e.g. `git checkout -b fix-some-bug`.
* Remember to include tests and documentation updates if applicable.
* Once ready, push to your remote: `git push origin fix-some-bug`.
* [Open a Pull Request][pull-request].

## Install

**Note**: These scripts are currently suited to **Linux** and **macOS**, but we would happily take pull requests to help us make them more cross-compatible.

Use the `install` script to install project dependencies in a virtual environment.

```bash
./scripts/install
```

To use a specific Python executable, use the `-p` option, e.g.:

```bash
./scripts/install -p python3.7
```

## Running the tests

The tests are written using [pytest] and located in the `tests/` directory.

**Note**: tests should be run before making any changes to the code in order to make sure that everything is running as expected.

We provide a stand-alone **test script** to run tests in a reliable manner. Run it with:

```bash
./scripts/test
```

By default, tests involving a database are excluded. To include them, set the `STARLETTE_TEST_DATABASES` environment variable. This should be a comma separated string of database URLs.

```bash
# Any of the following are valid for running the database tests...
export STARLETTE_TEST_DATABASES="postgresql://localhost/starlette"
export STARLETTE_TEST_DATABASES="mysql://localhost/starlette_test"
export STARLETTE_TEST_DATABASES="postgresql://localhost/starlette, mysql://localhost/starlette_test"
```

## Linting

We use [Black][black] as a code formatter. To run it along with a few other linting tools, we provide a stand-alone linting script:

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
[pull-request]: https://github.com/encode/starlette/compare
[pytest]: https://docs.pytest.org
[pytest-cov]: https://github.com/pytest-dev/pytest-cov
[black]: https://www.google.com/search?client=safari&rls=en&q=github+black&ie=UTF-8&oe=UTF-8
[MkDocs]: https://www.mkdocs.org
