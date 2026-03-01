
# ShieldGate Security API

ShieldGate is a Java Spring Boot backend API focused on secure authentication, account abuse detection, rate limiting, and audit logging.  
It is designed as a portfolio project to demonstrate backend engineering, security-focused logic, and cloud deployment on Azure.

---

## 🚀 Features
- User registration and authentication (JWT-based)
- Secure password hashing (BCrypt)
- Login attempt tracking
- Account lockout after repeated failed attempts
- Rate limiting to mitigate brute-force attacks
- Security audit logging
- Role-based access (USER / ADMIN)
- Cloud-ready deployment to Microsoft Azure

---

## 🛠️ Tech Stack
- Java 17 / 21
- Spring Boot
- Spring Security
- Spring Data JPA
- RESTful APIs
- Maven
- Azure App Service
- Azure SQL Database (planned)
- Azure Application Insights (planned)

---

## 📐 Architecture Overview
- Controllers expose REST endpoints
- Services contain business and security logic
- Repositories handle persistence
- Security layer manages authentication, authorization, and JWT handling
- Audit events capture security-relevant actions

---

## 🔐 Security Design
ShieldGate focuses on common real-world security concerns, including:
- Brute-force login protection
- Account lockout policies
- Rate limiting per IP and account
- Audit trails for security events

---

## 📦 Status
🚧 **Work in progress**  
This project is actively being developed in stages, with incremental commits reflecting real-world development practices.

---

## 📄 License
MIT
