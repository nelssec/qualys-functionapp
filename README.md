# QScanner Serverless Function Scanning

This repository contains documentation for extending QScanner to support multi-cloud serverless function scanning.

## Documentation

- [QSCANNER_SERVERLESS_SCANNING.md](docs/QSCANNER_SERVERLESS_SCANNING.md) - Comprehensive implementation guide for AWS Lambda, Azure Functions, and GCP Cloud Functions support

## Overview

The document proposes extending qscanner with native support for:

| Cloud | Command | Status |
|-------|---------|--------|
| AWS Lambda | `lambda` | Existing |
| Azure Functions | `azure-function` | Proposed |
| GCP Cloud Functions | `gcp-function` | Proposed |

## Security Model

All implementations follow the same security model:

1. **Scanner runs in customer's cloud environment** (not Qualys infrastructure)
2. **Source code never leaves the customer's environment**
3. **Only scan results (metadata) are sent to Qualys API**
4. **Short-lived credentials** that auto-rotate (IAM roles, Managed Identity, ADC)

## Bug Report

The document also includes a bug report for the `repo` command panic when scanning serverless function code that lacks repository markers (`.git/`, `package.json`, etc.).
