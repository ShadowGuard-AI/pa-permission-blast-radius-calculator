# pa-permission-blast-radius-calculator

Calculates the potential impact of a compromised identity by mapping its permissions to accessible resources and their criticality. Provides a ranked list of high-impact targets. Focused on tools for analyzing and assessing file system permissions.

The config file is JSON with keys: resources (a list), permissions (a mapping of user or group names to resource permission values), criticality (a mapping of resource names to high, medium, or low), and group_membership (a mapping of user names to lists of group names). Group membership is read only from the group_membership key. A user with no entry in that key is groupless.

Any non empty permission value other than an explicit deny or none counts as access, for example read, write, execute, or admin, and the value counted is logged. A criticality value outside high, medium, and low is rejected at load with exit 1, naming the resource and the value. An empty resources list exits 1 with a nothing to assess line. A user with no entry in permissions or group_membership exits 1 with a user not present line. If the output file resolves to the same path as the config file, the run exits 1. If the output file cannot be written, the run exits 1 with a results not saved line.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-blast-radius-calculator.git
cd pa-permission-blast-radius-calculator
pip install -r requirements.txt
```

## Usage

```
python3 main.py --user USER [options]
```

## Parameters

- `--user`: Required. The username or identity to assess permissions for.
- `--config`: Path to the configuration file, default `config.json`.
- `--output`: Optional. Path to the output file to store results.

## Verified in this wave

`python3 main.py --help` could not run in this sandbox: it exits 1 at import with `ModuleNotFoundError: No module named 'rich'`, because `rich` is not installed and installs are not made in this wave. Parameters above are taken from the argument parser in `main.py`, and `main.py` passes `py_compile`. No live assessment run is claimed.

## License

See LICENSE.
