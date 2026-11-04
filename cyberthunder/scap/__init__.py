"""Running DISA SCAP benchmarks ourselves.

datastream.py loads a SCAP 1.2/1.3 source datastream (or a bare XCCDF + OVAL pair). oval/ parses and evaluates
the OVAL definitions the benchmark's rules point at. windows_plan.py turns the rules a profile selects into one
collection request for windows_collect.ps1, and benchmark.py turns OVAL results into findings.

On Linux hosts OpenSCAP evaluates the datastream on the host itself; this package is what evaluates Windows
benchmarks, from data collected over WinRM or from the simulated host. See docs/SCAP.md.
"""
