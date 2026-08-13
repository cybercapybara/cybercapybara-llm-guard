# Third-Party Notices

This project, and the container images it ships, redistribute third-party
open-source software. Their licenses are reproduced or referenced below. This
file is a curated starting point — the authoritative license text for each
component lives in that component's own repository, and several licenses
(notably Apache-2.0) require their `NOTICE` file to be carried verbatim in
binary distributions; copy those in before you publish images commercially.

To regenerate mechanically against the exact versions you build, read the
copyright files vcpkg drops under `build/vcpkg_installed/*/share/*/copyright`,
and the OS package docs under `/usr/share/doc/*/copyright` in the runtime image.

## Backend — C++ libraries (vcpkg, linked into the service binary)

| Component | License |
|---|---|
| Drogon | MIT |
| libpqxx | BSD-3-Clause |
| redis-plus-plus | Apache-2.0 † |
| spdlog | MIT |
| prometheus-cpp | MIT |
| opentelemetry-cpp | Apache-2.0 † |
| nlohmann/json | MIT |
| GoogleTest | BSD-3-Clause (tests only — not shipped in runtime images) |

## Runtime — system libraries (apt, present in the runtime image)

| Component | License |
|---|---|
| OpenSSL (libssl3) | Apache-2.0 † |
| libpq (PostgreSQL client) | PostgreSQL License (BSD-style) |
| hiredis | BSD-3-Clause |
| jsoncpp | MIT / Public Domain |
| libcurl | curl license (MIT-style) |
| libstdc++ (GCC) | GPL-3.0 **with the GCC Runtime Library Exception** |

† **Apache-2.0 components** require that the upstream `NOTICE` file (if present)
be reproduced in distributions. Before shipping images publicly/commercially,
copy each project's `NOTICE` into the image (e.g. under `/app/NOTICES/`) and
append its contents here.
