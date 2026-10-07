# The `admina` package name

From **0.14.0**, Admina is published on PyPI as **`admina`**. The package
`admina-framework`, which held the code up to 0.13.x, is no longer released
after that. This is a breaking change for anything that installs
`admina-framework`.

What does not change: the Python module (`import admina`), the `admina`
command, the extras, the Rust accelerator `admina-core` and the container
images (`ghcr.io/admina-org/admina-proxy`, `ghcr.io/admina-org/admina-dashboard`).

## Releases and package names

| Releases | `admina-framework` | `admina` |
|---|---|---|
| up to 0.13.1 | the code | — |
| 0.13.2 – 0.13.x | the code | an alias: no code, it installs `admina-framework` at the same version |
| from 0.14.0 | 0.14.0 only: a final release that cannot be installed (see below) | the code |

`admina-framework` 0.14.0 is a source distribution that stops the
installation with this message, and leaves the installed packages as they
are:

```text
admina-framework is now published as admina.
Run:  pip uninstall -y admina admina-framework && pip install admina
```

So `pip install -U admina-framework`, or a requirement `admina-framework`
without an upper bound, fails from 0.14.0 on. A pin such as
`admina-framework==0.13.2` or `admina-framework<0.14` keeps installing the
0.13 releases.

## How to upgrade

Both packages contain the `admina` module. Remove the installed ones first,
then install `admina`:

```bash
pip uninstall -y admina admina-framework
pip install "admina[proxy]"          # the extras you used: same names
```

With uv:

```bash
uv pip uninstall admina admina-framework
uv pip install "admina[proxy]"
# in a uv project: uv remove admina-framework && uv add "admina[proxy]"
```

In `requirements.txt`, `pyproject.toml` or any other dependency list,
replace `admina-framework` with `admina` and keep the extras and the
version constraint:

```diff
- admina-framework[proxy,rust]>=0.13,<0.14
+ admina[proxy,rust]>=0.14,<0.15
```

A plugin created with `admina plugin create` depends on `admina-framework`
in its `pyproject.toml`: change that line in the same way.

Check the result:

```bash
python -c "import admina; print(admina.__version__)"   # 0.14.0 or later
pip list | grep -i admina                             # admina (and admina-core with [rust])
```

## If `import admina` fails after the upgrade

Installing `admina` 0.14 while `admina-framework` 0.13 is installed, and
then uninstalling `admina-framework`, removes the files of the `admina`
module: pip and uv delete every file that the uninstalled package had
installed, and both packages installed the same files. `pip list` still
shows `admina`, but `import admina` raises `ModuleNotFoundError`. Reinstall
it:

```bash
pip install --force-reinstall "admina[proxy]"
# or: uv pip install --reinstall "admina[proxy]"
```
