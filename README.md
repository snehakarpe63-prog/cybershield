# CyberShield

## Defensive Website Security Monitoring and Analysis Platform

CyberShield is a defensive cybersecurity web application that helps authorized users analyze the basic security posture of a website or domain.

## Problem Statement

Website owners and students learning cybersecurity often need a simple way to understand the basic security posture of a website without using complex security tools.

## Main Features

### Authentication

- User registration
- User login
- Logout
- Password hashing
- Session-based authentication
- User-specific scan access

### Security Scanning

- Domain validation
- DNS IPv4 resolution
- HTTP/HTTPS checks
- TLS certificate verification
- TLS certificate expiry information
- Security header analysis

### Scan History

- View previous scans
- Search domains
- Filter by risk level
- View saved reports
- Download reports
- Delete scans

## Technology Stack

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- Flask

### Database
- MySQL

## API Endpoints

```text
POST   /api/register
POST   /api/login
POST   /api/logout
GET    /api/me
POST   /api/scan
GET    /api/scans
GET    /api/scans/<scan_id>
DELETE /api/scans/<scan_id>