# Ship Safe Cloud

Ship Safe has two clear surfaces:

- **Ship Safe CLI**: the public MIT-licensed scanner in this repository.
- **Ship Safe Cloud**: the hosted dashboard for paid team workflows.

The cloud application includes authentication, billing, scan history, PR Guardian, team collaboration, hosted reports, lifecycle email, and commercial product flows. That code now lives in a private repository so the public project can stay focused on the open-source security engine.

## What Stays Public

- CLI commands
- Security agents
- Detection rules
- Fixtures and tests
- CI/SARIF integrations
- Documentation and examples
- Open-source release assets

## What Lives in Ship Safe Cloud

- Hosted dashboard UI
- Authentication and account setup
- Billing and checkout
- Team workspaces
- Hosted scan history
- PR Guardian dashboard workflows
- Admin and lifecycle email tools

## Contributing

Public contributions should target this repository unless a maintainer explicitly invites you into private cloud work. Good public contributions include focused security rules, regression fixtures, docs, examples, and CI integrations.

If an issue is about hosted dashboard UX, billing, account setup, private scan history, lifecycle email, or team administration, a maintainer may move it to the private cloud backlog. When possible, we will extract the open-source part of the work into a public CLI, rule, fixture, or docs issue.
