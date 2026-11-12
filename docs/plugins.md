# Plugins

A decoder is `(bytes) -> bytes | None`. Register it and the engine will try it
when no built-in chain opens a blob.

```python
from pydecomp.plugins import register_decoder

@register_decoder("rot47", priority=10)
def rot47(blob: bytes):
    return bytes(33 + ((byte - 33 + 47) % 94) for byte in blob)
```

Ship it as a package instead of a patch:

```toml
[project.entry-points."pydecomp.decoders"]
rot47 = "my_pkg.decoder:rot47"
```

`pydecomp.plugins.load_plugins()` imports the group once per process and lists
the plugins that failed to load in `load_plugins.errors`.

## Rules that make this safe inside a recovery

* a plugin that raises is skipped, and the run continues;
* a plugin that returns its input unchanged is ignored (an infinite loop is worse
  than a miss);
* the registry is capped at 64 decoders;
* plugins receive **bytes**, never a live interpreter. Nothing here can execute
  a sample, so the no-execution guarantee survives third-party code.

```console
>>> from pydecomp.plugins import summary
>>> summary()
'1 decoder(s): rot47'
```
