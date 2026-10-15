# Deliberately local fixture data

This directory contains harmless data used only to demonstrate the difference
between a writable and read-only Compose bind mount. It contains no secrets and
must not be replaced with a real host directory. SynapseAudit analyzes the YAML
without starting this service or modifying this directory.
