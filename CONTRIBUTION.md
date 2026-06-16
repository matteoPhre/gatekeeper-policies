# Contributing to gatekeeper-policies

Thank you for your interest in contributing to `gatekeeper-policies`! This document provides the guidelines and workflows for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a professional, respectful, and inclusive environment for everyone.

## Getting Started

### Prerequisites
* **Node.js**: >= 22.0.0
* **npm**: >= 10.0.0

### Local Setup
1. Fork the repository and clone it locally:
   git clone `'https://github.com/matteoPhre/gatekeeper-policies.git'`
   cd gatekeeper-policies

2. Install the dependencies:
   npm install

---

## Development Workflow

This project enforces strict Type Checking, Linting, and Testing to ensure code quality and security.

### Code Style & Linting
We use ESLint to enforce consistent code style. Check your code before committing:
   npm run lint

### Type Checking
TypeScript features a strict configuration. Ensure there are no type mismatches or implicit `any` definitions:
   npm run typecheck

### Running Tests
We use Vitest for unit testing. Every new feature or bug fix must include corresponding tests.
* Run tests once: npm run test
* Run tests in watch mode: npm run test:watch

---

## Security Guidelines

Since this is an identity and security-focused library, we perform strict dependency and package audits before every release.

Before submitting a Pull Request, run the full validation suite locally to ensure your changes do not break the security policy:
   npm run release:check

This command automatically executes:
1. Type checking (`tsc --noEmit`)
2. Production build
3. Test suite execution (`vitest`)
4. Production dependency audit (`npm audit --omit=dev`)
5. Dry-run package packing to inspect the final bundle

---

## Pull Request Process

1. Create a new branch from `main` using a descriptive name (e.g., `feat/add-length-policy` or `fix/expiry-loop`).
2. Implement your changes, including unit tests.
3. Verify that `npm run release:check` passes with zero errors.
4. Commit your changes following clear, concise commit messages.
5. Push your branch and open a Pull Request against the `main` branch.

All Pull Requests require code review and a passing CI/CD pipeline before being merged.

## License

By contributing to `gatekeeper-policies`, you agree that your contributions will be licensed under the project's [Apache-2.0 License](LICENSE).