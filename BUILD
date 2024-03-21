langs("Python")

py_binary (
  name = "super_general",
  srcs = [
    "pidutil.py",
    "super_general.py",
  ],
  deps = [ "//impulse/args:args" ],
)

py_binary (
  name = "enable_console",
  srcs = [
    "enable_console.py",
    "pidutil.py",
  ],
  deps = [
    "//impulse/args:args",
    "//impulse/util:bintools",
  ],
  data = [ "skip_ironman_checks.gdb" ],
)