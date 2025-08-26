# Subzy Test Fixtures

This directory contains test fixtures for the subzy subdomain takeover detection plugin.

## Files

- `vulnerable_github.json` - Single vulnerable GitHub Pages subdomain
- `vulnerable_s3.json` - Single vulnerable Amazon S3 subdomain  
- `vulnerable_heroku.json` - Single vulnerable Heroku subdomain
- `not_vulnerable.json` - Single non-vulnerable subdomain
- `multiple_results.json` - Array of multiple results with mixed vulnerabilities
- `error_result.json` - Result with connection error
- `line_delimited.jsonl` - Line-delimited JSON format (JSONL)
- `wrapped_response.json` - Results wrapped in response object with summary
- `edge_cases.json` - Various edge cases and service providers

## Usage

These fixtures are used in the parser tests to ensure proper parsing of subzy output in different formats and scenarios.

## Test Scenarios Covered

1. **Single Vulnerable Results**: GitHub Pages, S3, Heroku takeovers
2. **Non-Vulnerable Results**: Normal functioning subdomains
3. **Multiple Results**: Arrays of mixed results
4. **Error Handling**: Connection timeouts and errors
5. **Format Variations**: JSON arrays, single objects, line-delimited, wrapped responses
6. **Edge Cases**: Special characters, various service providers, different status codes
7. **Verification States**: Both verified and unverified vulnerabilities

## Adding New Fixtures

When adding new test fixtures:

1. Follow the SubzyResult JSON schema
2. Include realistic service names and fingerprints
3. Use proper timestamps in RFC3339 format
4. Test both vulnerable and non-vulnerable scenarios
5. Include edge cases and error conditions