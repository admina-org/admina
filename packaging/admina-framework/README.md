# admina-framework

Admina is published as [`admina`](https://pypi.org/project/admina/) since
0.14.0. This last release of `admina-framework` cannot be installed: it
stops with the commands to switch.

```bash
pip uninstall -y admina admina-framework
pip install admina            # extras keep their names: "admina[proxy]"
```

The module (`import admina`), the `admina` command and the extras did not
change. Releases up to 0.13.x of `admina-framework` remain installable with a
pin such as `admina-framework<0.14`.

Upgrade guide: https://github.com/admina-org/admina/blob/main/docs/guides/package-name.md
