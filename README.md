# Secure Banking Application

## Description
A console-based banking application written in Java for ISS 2101 Secure Coding. It demonstrates
Object-Oriented Programming and the secure coding techniques covered in the course. All data is stored in plain
text files (no database).

## Student Details
- **Name:** Kudzaishe Andrea
- **Registration Number:** H250512W

## Features
- Registration and login (with optional two-factor authentication)
- Three roles: **Customer**, **Auditor**, **Administrator**
- Customers: create Savings or Current accounts, view balances, deposit, withdraw, view transaction history
- Administrators: list users, unlock locked users, assign roles, view and verify the audit log
- Auditors: read-only access to the audit log and its integrity check
- Data saved to `data/users.txt`, `data/accounts.txt`, `data/transactions.txt` and `data/audit.log`, loaded at start-up
