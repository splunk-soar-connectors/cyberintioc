<img src="logo_dark.svg" width="300">

# SOAR App Template

Welcome to the Splunk SOAR App Template repository. This template helps you quickly create new SOAR apps by handling the basic setup.

## Getting Started

### 1. Create a new repository from this template

Click the "Use this template" button at the top of this repository to create a new repository based on this template.

### 2. Choose repository name

Names should be lowercase and ideally not use characters like underscores or dashes. `ciscosma` is an example repo name. The repository name you choose will be automatically applied to all template files when the setup workflow runs. For example, if you name your repository `ciscosma`, the template files will be renamed accordingly:

- `template_connector.py` → `ciscosma_connector.py`
- `template.json` → `ciscosma.json`
- etc...

### 3. Initial Setup (Automatic)

After creating your repository, the `setup-from-template.yml` GitHub workflow will automatically:

- Setup repository files for your connector
- Update development tools to the latest version
- Cleanup

### 4. Customize Your App

Once the workflow completes, work can begin:

- Update `your_repo_name.json` to:

  - Modify app information (appid, name, description, vendor, etc...)
  - Configure authentication parameters
  - Add logo files

- Start developing 🚀

## Contributing

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) for guidelines if you are interested in contributing, raising issues, or learning more about open-source SOAR apps.

Please also review our [Conventions](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) to ensure you follow up-to-date standards.

## Legal and License

This SOAR App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.
