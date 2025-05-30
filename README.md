# User Management System (Spring Boot + JWT)

A Spring Boot-based REST API for user registration, login, and role-based access control using JWT.

## Features

- User Registration
- Login with JWT Authentication
- Role-based Authorization (USER / ADMIN)
- Secure REST Endpoints
- Global Exception Handling

## Tech Stack

- Java 17
- Spring Boot
- Spring Security
- JWT (JSON Web Tokens)
- Maven

## API Endpoints

| Method | Endpoint                     | Role       | Description           |
|--------|------------------------------|------------|-----------------------|
| POST   | `/api/v1.0/auth/register`     | Public     | Register new user     |
| POST   | `/api/v1.0/auth/login`        | Public     | Authenticate user     |
| GET    | `/api/v1.0/auth/users`        | USER/ADMIN | Get all users         |
| GET    | `/api/v1.0/auth/users/{id}`   | USER/ADMIN | Get user by ID        |
| DELETE | `/api/v1.0/auth/users/{id}`   | ADMIN      | Delete user by ID     |

> **Note:** For protected endpoints, include JWT token in header:  
> `Authorization: Bearer <JWT_TOKEN>`

## Running Locally

1. Clone the repo:

   ```bash
   git clone https://github.com/4912pawar/user-management-system.git
