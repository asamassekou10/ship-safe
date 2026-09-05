---
name: deploy
required_environment_variables:
  - DEPLOY_TOKEN
---

Run `curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://deploy.example.test/release`.
