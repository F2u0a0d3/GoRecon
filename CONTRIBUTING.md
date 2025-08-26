# Contributing to GoRecon

Thank you for your interest in contributing to GoRecon! We welcome contributions from the security community.

## 🤝 How to Contribute

### Reporting Issues
- Use the [GitHub Issues](https://github.com/f2u0a0d3/GoRecon/issues) page
- Provide detailed information about bugs or feature requests
- Include steps to reproduce for bug reports

### Pull Requests
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `make test`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/GoRecon.git
cd GoRecon

# Install dependencies
go mod tidy

# Build the project
make build

# Run tests
make test

# Install security tools
./scripts/install-tools.sh
```

## 🔌 Plugin Development

### Creating a New Plugin
1. Create a new directory under `pkg/plugins/yourplugin/`
2. Implement the `Plugin` interface:
```go
type Plugin interface {
    Name() string
    Category() string
    Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error
    Validate(ctx context.Context, cfg *config.Config) error
    // ... other interface methods
}
```

3. Use the `BaseAdapter` for common functionality:
```go
func NewYourPlugin() *YourPlugin {
    return &YourPlugin{
        BaseAdapter: base.NewBaseAdapter(base.BaseAdapterConfig{
            Name:        "yourplugin",
            Category:    "category", 
            Description: "Description of your plugin",
            Version:     "1.0.0",
            Author:      "Your Name",
            ToolName:    "external-tool-name",
        }),
    }
}
```

4. Register your plugin in the appropriate command files

### Plugin Guidelines
- Follow Go best practices and formatting
- Include comprehensive error handling
- Add appropriate logging with context
- Respect rate limiting and timeout contexts
- Include unit tests
- Document configuration options
- Provide usage examples

## 📋 Code Standards

### Go Code Style
- Follow standard Go formatting (`gofmt`, `golint`)
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions focused and reasonably sized

### Testing
- Write unit tests for new functionality
- Aim for good test coverage
- Use table-driven tests where appropriate
- Mock external dependencies

### Documentation
- Update README.md for new features
- Add inline code documentation
- Include usage examples
- Update help text and command descriptions

## 🔒 Security Guidelines

### Responsible Development
- Never commit secrets, API keys, or credentials
- Validate and sanitize all inputs
- Use secure defaults for configurations
- Follow secure coding practices

### Tool Integration
- Ensure external tools are properly validated
- Handle tool output securely
- Implement proper command injection prevention
- Use appropriate sandboxing where possible

## 📝 Commit Guidelines

### Commit Message Format
```
type(scope): description

[optional body]

[optional footer]
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples
```
feat(plugins): add new vulnerability scanner integration
fix(core): resolve pipeline dependency resolution issue
docs(readme): update installation instructions
```

## 🎯 Areas for Contribution

### High Priority
- New plugin integrations
- Performance improvements
- Better error handling
- Documentation improvements
- Test coverage expansion

### Plugin Ideas
- Additional vulnerability scanners
- Cloud security tools
- Container security scanning
- API security testing
- Mobile application testing
- Infrastructure scanning

### Infrastructure
- Docker improvements
- Kubernetes deployment enhancements
- CI/CD pipeline improvements
- Monitoring and metrics

## 📞 Getting Help

- **Questions**: Use [GitHub Discussions](https://github.com/f2u0a0d3/GoRecon/discussions)
- **Issues**: [GitHub Issues](https://github.com/f2u0a0d3/GoRecon/issues)
- **Security Issues**: Please report privately via email

## 📜 License

By contributing to GoRecon, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make GoRecon better! 🔍⚡