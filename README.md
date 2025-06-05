# CivTAK - Azure VM for Open TAK Server (OTS)

## Terraform: VM Deploy - Azure

Based on root cloud-vm project for GitHub Actions and Terraform Setup.

## Setup a new Azure Subscription

Recommended Pre-requisite: **Azure Billing Profile: Invoice Section**

* Azure Invoice Section for new Subscription.
  * Search for "Billing Profiles" and `create` an Invoice Section.

This config item can be very hard to location. Start here with "billing profiles".

* Create Azure Subscription, **assign to distinct Invoice Section**

## Infra Overview

This repository an `infra` folder full of Terraform; to plan, deploy, and destory a Linux VM.

### Infra Components

Through the use of GitHub Actions, create terraform storage, network and VM in three terraform `components`.

### Environment Variables

To achive creation of distinct VMs, use GitHub environments; setup `variables` and `secrets` to enable the Terraform infrastructure deployment automation.

### More Infra Info

Learn more in the `infra/README` folder.

* [infra/README/Azure/docs/01_overview.md](infra/README/Azure/docs/01_overview.md)

## Software Maintenance

After creation of the VM, be sure to login and check for software package updates perodically:

```bash
ssh devadmin@newhost.nameor.ip
sudo apt update
sudo apt upgrade
sudo reboot
```
