+++
title = "passbox"
sort_by = "weight"
+++


A password store for machines that run agents. An agent asks for a secret, macOS
raises a Touch ID prompt naming the agent and the secret, and the value goes into
one child process rather than into the agent.

<p align="center">
  <img src="/prompt.png" alt="Touch ID prompt naming the secret and the agent" width="340">
</p>

Secrets are ordinary [age](https://age-encryption.org) files. The broker decides
who may open them. See [docs/content/design.md](/design) for why it is built this
way and what it costs.

Runs with no Apple Developer Program membership.

