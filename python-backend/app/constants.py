# Ports that represent critical attack surfaces
CRITICAL_PORTS = frozenset({21, 22, 23, 445, 3389})

# Ports that are commonly risky but not always critical
RISKY_PORTS = frozenset({25, 80, 110, 143, 443, 3306, 5432, 5900, 8080, 8443})
