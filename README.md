# pa-permission-blast-radius-calculator
Calculates the potential impact of a compromised identity by mapping its permissions to accessible resources and their criticality. Provides a ranked list of high-impact targets. - Focused on Tools for analyzing and assessing file system permissions

The config file is JSON with keys: resources (a list), permissions (a mapping of user or group names to resource permission values), criticality (a mapping of resource names to high, medium, or low), and group_membership (a mapping of user names to lists of group names). Group membership is read only from the group_membership key. A user with no entry in that key is groupless.

Any non empty permission value other than an explicit deny or none counts as access, for example read, write, execute, or admin, and the value counted is logged. A criticality value outside high, medium, and low is rejected at load with exit 1, naming the resource and the value. An empty resources list exits 1 with a nothing to assess line. A user with no entry in permissions or group_membership exits 1 with a user not present line. If the output file resolves to the same path as the config file, the run exits 1. If the output file cannot be written, the run exits 1 with a results not saved line.

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-blast-radius-calculator`

## Usage
`./pa-permission-blast-radius-calculator [params]`

## Parameters
- `-h`: Show help message and exit
- `--user`: The username or identity to assess permissions for.
- `--config`: No description provided
- `--output`: No description provided

## License
Copyright (c) ShadowGuardAI
