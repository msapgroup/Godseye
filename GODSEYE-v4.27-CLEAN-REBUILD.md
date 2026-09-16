# GODSEYE v4.27 Clean Rebuild

The v4.27 branch intentionally removes the embedded legacy Windows Agent implementation and its packaging workflow. The GODSEYE application must build, test, install, upgrade, and operate without a Windows Agent binary in this repository.

Remote Access server endpoints and screenshot/session transport remain application features. The replacement Windows Agent will be versioned, built, tested, and released separately after the v4.27 application is green.
