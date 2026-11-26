# Security policy

## Supported versions
Only the latest commit on `main` is maintained. This is a portfolio project, not a released product.

## Reporting a vulnerability
Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting (the "Report a vulnerability" button on the repository's Security tab) if it is shown, or contact the maintainer through the GitHub profile `@faroukkhaled`. I will answer when I can. There is no bug bounty and no guaranteed response time.

## What counts
`banking-soc-simulation` includes a small HTTP server (`banksoc serve`) with no authentication. It binds to localhost by default and must not be exposed. Bugs in input validation, output escaping or the API in scope.

Findings about the detection rules themselves (missed attacks, false positives) are normal bugs: open a regular issue.

## Safe use
All sample data is synthetic or from public datasets. Do not put real credentials, customer data or production logs in issues or pull requests.
