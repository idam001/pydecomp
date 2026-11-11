# pydecomp — minimal, non-root, network-free analysis container.
#
#   docker build -t pydecomp .
#   docker run --rm -v "$PWD:/w" -w /w --network=none pydecomp sample.py
#
# Two stages: the first builds a wheel from the source tree, the second installs
# only the wheel. No compiler, no build tooling and no pip cache end up in the
# runtime image.
FROM python:3.13-slim AS build

WORKDIR /src
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tools ./tools

RUN pip install --upgrade build \
 && python -m build --wheel --outdir /dist \
 && python tools/build_single.py --out /dist/pydecomp.py


FROM python:3.13-slim AS runtime

LABEL org.opencontainers.image.title="pydecomp" \
      org.opencontainers.image.description="Static Python deobfuscator: recover source without executing the sample." \
      org.opencontainers.image.source="https://github.com/idam001/pydecomp" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NO_COLOR=1 \
    PYDECOMP_MAX_BYTES=33554432 \
    PYDECOMP_MAX_LAYERS=25

# an unprivileged user with a home, so the CLI can write its output folder
RUN groupadd --system --gid 10001 analyst \
 && useradd --system --uid 10001 --gid analyst --create-home analyst

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-deps /tmp/*.whl && rm -rf /tmp/*.whl
COPY --from=build /dist/pydecomp.py /opt/pydecomp/pydecomp.py

USER analyst
WORKDIR /work

# the sample is analysed, never executed: no entrypoint wrapper, no shell
ENTRYPOINT ["pydecomp"]
CMD ["--help"]

# sanity check at build time; fails the build if the image cannot analyse
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["python3", "/opt/pydecomp/pydecomp.py", "--selftest", "--no-color"]
