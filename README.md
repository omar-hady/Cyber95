# Windows 95 Cybersecurity Interactive OS

A specialized cybersecurity educational platform built with Jekyll, featuring an authentic Windows 95 interface with interactive cybersecurity demos, challenges, and educational content.

## 🚀 Features

### File Explorer Cyber Partitions
- **C:\ – Bug Hunting**: Bug bounty articles and write-ups
- **D:\ – Penetration Testing**: Penetration testing methodology and guides
- **F:\ – Write-ups**: Detailed security write-ups and case studies
- **X:\ – Hidden Challenges**: Unlockable challenges (use Ctrl+Shift+X)
- **Network:\ – Network Neighborhood**: Simulated vulnerable servers
- **Malware:\ – Malware Museum**: Historical malware information
- **BlueTeam:\ – Incident Response**: Blue team tools and techniques

### Interactive Cybersecurity Demos
- **XSS Demo**: Mini browser window for testing XSS payloads
- **Burp Suite**: Simulated web application testing interface
- **Log Analyzer**: Interactive log analysis with pattern detection
- **CMD-based Tools**: Nmap simulation and other command-line tools

### Hidden Challenges (X:\)
- **Steganography Challenge**: Find hidden messages in images
- **Password Cracker**: JavaScript-based password puzzle
- **Log Analysis Puzzle**: Detect attacks in log files

### Network Neighborhood Simulation
- **FTP Server**: Vulnerable configuration with logs
- **Mail Server**: Open relay and spam detection
- **Web Server**: Directory listing and attack logs

### Malware Museum Partition
- **ILOVEYOU.vbs**: VBScript worm information
- **Melissa.doc**: Macro virus details
- **WannaCry.exe**: Ransomware analysis

### Blue Team Partition
- **Wireshark**: Network traffic analysis
- **IDS**: Intrusion detection alerts
- **Forensics**: Digital forensics tools

### Achievements System
- **XSS Hunter**: Complete XSS demo
- **Port Scanner**: Run nmap command
- **Hidden Drive Discoverer**: Unlock X: drive
- **Forensics Analyst**: Solve log analysis challenge
- **Elite Hacker**: Use hack command

## 🎮 How to Use

### Getting Started
1. **Open File Explorer**: Double-click the File Explorer icon
2. **Navigate Partitions**: Click on different drive letters to explore content
3. **Read Articles**: Double-click on posts to open them in new windows
4. **Try Demos**: Use Start > Cybersecurity Tools to access interactive demos

### Hidden Features
- **Unlock X: Drive**: Press Ctrl+Shift+X to unlock hidden challenges
- **CMD Commands**: Press backtick (`) to open command prompt
- **Achievements**: Check Start > Cybersecurity Tools > Achievements

### Interactive Demos
- **XSS Demo**: Try payloads like `<script>alert('XSS')</script>`
- **Burp Suite**: View intercepted requests and responses
- **Log Analyzer**: Paste logs to detect security events

## 🛠 Technical Implementation

### Architecture
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Jekyll static site generator
- **Styling**: Custom Windows 95 CSS framework
- **Interactivity**: Vanilla JavaScript with modular architecture

### Key Components
- **Windows95Blog Class**: Main application controller
- **Window Management**: Draggable, resizable windows
- **File System Simulation**: Virtual file explorer with cybersecurity content
- **Achievement System**: LocalStorage-based progress tracking
- **Sound System**: Authentic Windows 95 sound effects

### File Structure
```
Windows 95/
├── assets/
│   ├── css/win95.css          # Main stylesheet
│   ├── js/win95.js           # Core application logic
│   ├── icons/                # Windows 95 icons
│   └── sounds/               # Sound effects
├── _posts/                   # Blog posts (cybersecurity content)
├── _layouts/                 # Jekyll templates
└── _config.yml              # Jekyll configuration
```

## 📚 Educational Content

### Bug Bounty (C:\)
- Advanced XSS techniques
- Bug bounty success stories
- Responsible disclosure practices

### Penetration Testing (D:\)
- Professional methodology
- Tool usage guides
- Legal and ethical considerations

### Write-ups (F:\)
- Detailed vulnerability reports
- Exploitation chains
- Remediation strategies

### Interactive Learning
- **Hands-on Demos**: Real-time vulnerability testing
- **Challenge-based Learning**: Solve security puzzles
- **Progressive Difficulty**: From basic to advanced concepts

## 🎯 Learning Objectives

### Technical Skills
- Web application security testing
- Network reconnaissance techniques
- Malware analysis fundamentals
- Incident response procedures

### Professional Development
- Bug bounty program participation
- Penetration testing methodology
- Security report writing
- Ethical hacking practices

### Practical Experience
- Interactive vulnerability demos
- Real-world attack scenarios
- Defensive security tools
- Forensic analysis techniques

## 🔧 Customization

### Adding New Content
1. **Create Posts**: Add markdown files to `_posts/` with appropriate categories
2. **Update Partitions**: Modify `loadFileList()` in `win95.js`
3. **Add Demos**: Create new window templates and setup methods

### Modifying Features
- **Achievements**: Edit `unlockAchievement()` method
- **Challenges**: Update `setupHiddenChallenges()` method
- **Styling**: Modify `win95.css` for visual changes

### Extending Functionality
- **New Window Types**: Add templates and setup methods
- **Additional Commands**: Extend CMD functionality
- **Sound Effects**: Add new audio files and references

## 🚀 Deployment

### Local Development
```bash
# Install dependencies
bundle install

# Start development server
bundle exec jekyll serve --livereload
```

### Production Deployment
- **GitHub Pages**: Push to repository with GitHub Pages enabled
- **Netlify**: Connect repository for automatic deployment
- **Vercel**: Deploy with Vercel for static hosting

## 📖 Documentation

### For Users
- **Getting Started Guide**: Basic usage instructions
- **Feature Documentation**: Detailed feature explanations
- **Troubleshooting**: Common issues and solutions

### For Developers
- **API Reference**: JavaScript method documentation
- **Architecture Guide**: System design and components
- **Contributing Guidelines**: How to contribute to the project

## 🤝 Contributing

### How to Contribute
1. **Fork the Repository**: Create your own copy
2. **Create Feature Branch**: Work on new features
3. **Add Content**: Create cybersecurity posts and demos
4. **Submit Pull Request**: Share your improvements

### Content Guidelines
- **Educational Focus**: Prioritize learning value
- **Accuracy**: Ensure technical accuracy
- **Ethical Considerations**: Promote responsible security practices
- **Accessibility**: Make content accessible to all skill levels

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Windows 95 Design**: Inspired by the classic Windows 95 interface
- **Cybersecurity Community**: Knowledge and techniques from the security community
- **Open Source Tools**: Built with open source technologies
- **Educational Resources**: Based on established cybersecurity curricula

## 📞 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Join community discussions on GitHub Discussions
- **Documentation**: Check the documentation for detailed guides

---

**Note**: This platform is designed for educational purposes only. All content promotes ethical hacking and responsible security practices. Users are responsible for ensuring they have proper authorization before testing any systems.
