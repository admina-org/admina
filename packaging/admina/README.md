# admina

`pip install admina` installs [`admina-framework`](https://pypi.org/project/admina-framework/),
the Admina governed AI development framework, at the same version. This
package has no code of its own; `import admina` comes from `admina-framework`.

Every extra of `admina-framework` is available under the same name:

```bash
pip install admina                  # SDK
pip install "admina[proxy]"         # SDK + proxy + dashboard
pip install "admina[full]"          # proxy + NLP + telemetry
```

Documentation, changelog and source: https://github.com/admina-org/admina
