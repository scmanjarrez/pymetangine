# Description
A Python metamorphic engine for PE/PE+ files.

# Requirements
- python3
- radare2
- keystone-engine

# Run
### Prelaunch
Install python dependencies

`pip install -r requirements.txt`

### Launch
pymetangine can generate metamorphic binaries one by one

`./pymetangine.py -i path_to_bin`

Or in batches

`./pymetangine.py -i path_to_dir -b`

# Output

One sample metamorph

```bash
./pymetangine.py -i samples/be5b9e6b8dc76ca6b4f2616b47ccaba4.bin
[+] Opening samples/be5b9e6b8dc76ca6b4f2616b47ccaba4.bin in radare2.
[+] Analyzing executable.
[+] Starting patching routine.
[+] Writing mutations to mutations/mutated.bin
[+] Mutations: 10/26
[+] Exiting...
```

Batch metamorph
```bash
./pymetangine.py -i samples -b
[+] File 1/10.
[+] Opening samples/d3e94909a6b134b83307168ab0ae8a1e.bin in radare2.
[+] Analyzing executable.
[+] Starting patching routine.
[+] Writing mutations to mutations/d3e94909a6b134b83307168ab0ae8a1e_ry.bin
[+] Mutations: 6/9

[+] File 2/10.
[+] Opening samples/eb64be920df8837443a152fa143a9e5b.bin in radare2.
[+] Analyzing executable.
[+] Starting patching routine.
[+] Writing mutations to mutations/eb64be920df8837443a152fa143a9e5b_ry.bin
[+] Mutations: 18/25
...
```

# Optional
A script to download samples from MalShare is provided.

- **helper_malshare.py**

> You need to save your MalShare API key in a file named **.key_malshare**.

A script to scan and query results from VirusTotal is provided.

- **helper_virustotal.py**

> You need to save your VirusTotal API key in a file named **.key_virustotal**.

A script to plot results is provided. Example data can be found in example_data folder.

- **helper_plotter.py**

# License
    pymetangine  Copyright (C) 2021-2022 Sergio Chica Manjarrez.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](https://github.com/scmanjarrez/pymetangine/blob/master/LICENSE)
