# Detecting SSH Brute Force & Password Spraying with Splunk

## Project Overview

This project demonstrates a practical Security Operations Center (SOC) lab focused on detecting SSH Brute Force and Password Spraying attacks using Splunk Enterprise.

The lab simulates authentication attacks from Kali Linux against an Ubuntu SSH server, collects authentication logs using Splunk Universal Forwarder, and analyzes the events to identify suspicious activities and generate security alerts.

## Lab Objectives

- Simulate SSH Brute Force attacks.
- Simulate SSH Password Spraying attacks.
- Collect and forward Linux authentication logs to Splunk.
- Analyze SSH authentication events using Splunk Search Processing Language (SPL).
- Build detection queries for suspicious authentication behavior.
- Configure scheduled alerts for attack detection.

## Lab Environment

| Component | Role |
|---|---|
| Kali Linux | Attacker |
| Ubuntu Linux | SSH Target |
| Windows | Splunk Enterprise SIEM |
| Splunk Universal Forwarder | Log Collection & Forwarding |
| Hydra | Attack Simulation |
| Splunk SPL | Detection & Analysis |

## Network Architecture

*Network topology diagram will be added here.*

## Attack Simulation

### 1. SSH Brute Force

A controlled SSH Brute Force simulation was performed from Kali Linux against the Ubuntu SSH server using Hydra.

### 2. SSH Password Spraying

A controlled Password Spraying simulation was performed using a single password against multiple dedicated test accounts.

## Log Collection

Ubuntu authentication logs were collected from:

`/var/log/auth.log`

Splunk Universal Forwarder forwarded the logs to Splunk Enterprise using TCP port `9997`.

## Detection & Analysis

The lab includes detection logic for:

- SSH Brute Force attacks.
- SSH Password Spraying.
- Failed authentication followed by successful login.

## Alerting

Scheduled Splunk alerts were configured to identify suspicious SSH authentication activity.

## Results

The lab successfully demonstrated:

- Centralized collection of Ubuntu SSH authentication logs.
- Identification of repeated failed login attempts.
- Detection of suspicious source IP activity.
- Successful triggering of Splunk security alerts.

## Tools & Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- Kali Linux
- Ubuntu Linux
- Hydra
- SSH
- SPL

## Disclaimer

This project was conducted in a controlled lab environment using systems and accounts created for educational and defensive security testing purposes.
