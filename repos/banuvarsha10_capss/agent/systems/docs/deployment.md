# CAPSS Deployment Guide

## Overview

The CAPSS Systems module is responsible for deploying and managing the 5G Core Network using Open5GS and UERANSIM.

## Components

- Open5GS Core
- MongoDB
- UERANSIM gNB
- UERANSIM UE

## Deployment Steps

1. Start MongoDB
2. Start Open5GS Core
3. Verify Network Functions
4. Start gNB
5. Start UE
6. Verify Registration
7. Collect Logs
8. Generate Experiment Results

## Scripts

| Script | Purpose |
|---------|----------|
| start_core.sh | Start Open5GS services |
| stop_core.sh | Stop Open5GS services |
| restart_core.sh | Restart Open5GS |
| cleanup.sh | Clean previous experiments |
| check_core.sh | Verify running services |
| start_gnb.sh | Launch UERANSIM gNB |
| start_ue.sh | Launch UE |
| start_all.sh | Run deployment workflow |

## Output

The deployment produces:

- Registration Logs
- Experiment Metadata
- Metrics Reports
- Registration Dataset