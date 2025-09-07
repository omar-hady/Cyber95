# Windows 95 Blog - Interactive Features

This document describes the interactive features that have been added to the Windows 95 Blog project.

## 🎯 Overview

The Windows 95 Blog has been extended with several interactive features that enhance the educational experience while maintaining the authentic Windows 95 aesthetic.

## 🚀 New Features

### 1. Interactive Security Demos

**Location**: Blog posts with `.xss-demo`, `.sqli-demo`, or `.csrf-demo` classes

**Features**:
- **XSS Demo**: Interactive payload tester showing vulnerable vs. safe output
- **SQL Injection Demo**: Fake login form demonstrating SQL injection attacks
- **CSRF Demo**: Simulated CSRF attack with educational content

**How to Use**:
1. Open posts like "XSS Attack Demo" or "SQL Injection Demo"
2. Enter payloads in the input fields
3. Click "Execute" or "Login" to see the results
4. Earn achievements for trying different attack vectors

**Example Posts**:
- `_posts/2025-01-03-xss-demo.md`
- `_posts/2025-01-03-sqli-demo.md`

### 2. Retro Printer Simulation

**Location**: Post windows with "Print" button

**Features**:
- Windows 95-style print queue window
- Real-time status updates (Spooling → Printing → Completed)
- Automatic PDF download (as text file) when printing completes
- Print sound effects (with fallback to system beep)
- Multiple print jobs support

**How to Use**:
1. Open any blog post
2. Click the "Print" button in the toolbar
3. Watch the print queue window show the printing progress
4. Download the generated text file when complete

### 3. Security Quiz Game

**Location**: Start Menu → Games → Quiz.exe

**Features**:
- 5 cybersecurity multiple-choice questions
- Real-time score tracking
- Achievement system integration
- "Security Expert" achievement for 80%+ score
- Play again functionality

**How to Use**:
1. Click Start Menu → Games → Quiz.exe
2. Answer the questions by clicking on options
3. Click "Next" to proceed
4. View your final score and earn achievements

### 4. Security News Feed

**Location**: File Explorer → News:\ drive

**Features**:
- Static JSON-based news articles
- Post-style windows for reading articles
- Categories: Vulnerability, Breach, Ransomware, Phishing, Update, Law Enforcement
- Educational content about current security topics

**How to Use**:
1. Open File Explorer
2. Navigate to News:\ drive
3. Double-click any news article to read it
4. Articles open in dedicated news windows

**Data Source**: `assets/data/news.json`

### 5. Virus Museum

**Location**: File Explorer → Virus:\ drive

**Features**:
- Educational information about famous computer viruses
- Visual effects (color flashing) when opening virus files
- Historical context and impact information
- Non-malicious, purely educational content

**Available Viruses**:
- **ILOVEYOU.vbs** (2000) - VBScript Worm with red flash effect
- **Melissa.doc** (1999) - Macro Virus with blue flash effect  
- **WannaCry.exe** (2017) - Ransomware with green flash effect

**How to Use**:
1. Open File Explorer
2. Navigate to Virus:\ drive
3. Double-click any virus file to learn about it
4. Watch the visual effects and read the educational content

## 🎮 Achievement System

The blog includes an achievement system that rewards users for exploring different features:

- **XSS Explorer**: Try XSS payloads in the demo
- **SQL Injection Master**: Attempt SQL injection in the demo
- **CSRF Investigator**: Use the CSRF demo
- **Security Expert**: Score 80%+ on the cybersecurity quiz
- **Elite Hacker**: Use the `hack` command in Command Prompt

## 🎵 Audio Features

- **Print Sound**: Plays when printing starts (with fallback to system beep)
- **Volume Control**: System tray volume slider with localStorage persistence
- **WiFi Status**: Toggle WiFi connection status in system tray

## 🗂️ File System Structure

### New Drives
- **C:\** - Bug Bounty posts
- **D:\** - Penetration Testing posts  
- **F:\** - Write-ups
- **News:\** - Security news articles
- **Virus:\** - Educational virus museum

### New Applications
- **Quiz.exe** - Cybersecurity quiz game
- **Print Queue** - Print job management

## 🛠️ Technical Implementation

### JavaScript Architecture
- **Main System**: `assets/js/win95.js` - Core Windows 95 functionality
- **Interactive Demos**: `assets/js/demos.js` - Security demo implementations
- **Global Instance**: `window.win95Blog` - Accessible throughout the application

### CSS Styling
- **Windows 95 Theme**: Authentic retro styling maintained
- **New Components**: Quiz, print queue, news, virus museum styles
- **Visual Effects**: Color flashing animations for virus museum
- **Responsive Design**: Works on different screen sizes

### Data Sources
- **News**: `assets/data/news.json` - Static news articles
- **Virus Data**: Embedded in JavaScript - Educational virus information
- **Quiz Questions**: Embedded in JavaScript - Cybersecurity questions

## 🎨 UI Components

### New Window Types
- **Quiz Window**: Multiple choice interface with score tracking
- **Print Queue Window**: Table showing print job status
- **News Window**: Article display with metadata
- **Virus Window**: Educational content with visual effects

### Enhanced Existing Windows
- **Post Windows**: Added print functionality with toolbar
- **File Explorer**: New drives and file types
- **Start Menu**: Added Quiz.exe to Games section

## 🔧 Configuration

### Adding New News Articles
Edit `assets/data/news.json`:
```json
{
    "title": "Article Title",
    "date": "YYYY-MM-DD", 
    "content": "Article content...",
    "category": "Category Name"
}
```

### Adding New Quiz Questions
Edit the `questions` array in `setupQuiz()` method in `assets/js/win95.js`:
```javascript
{
    question: "Your question?",
    options: ["Option 1", "Option 2", "Option 3", "Option 4"],
    correct: 0  // Index of correct answer
}
```

### Adding New Virus Entries
Edit the `virusData` array in `loadVirusData()` method in `assets/js/win95.js`:
```javascript
{
    name: "VirusName.exe",
    type: "Virus Type",
    year: "YYYY",
    description: "Description...",
    content: "Detailed content...",
    effect: "color-flash"  // CSS class for visual effect
}
```

## 🚀 Getting Started

1. **Start the Blog**: Open the main page to see the Windows 95 desktop
2. **Explore Demos**: Open File Explorer and navigate to C:\ to find demo posts
3. **Take the Quiz**: Start Menu → Games → Quiz.exe
4. **Read News**: File Explorer → News:\ drive
5. **Visit Museum**: File Explorer → Virus:\ drive
6. **Print Posts**: Open any post and click the Print button

## 🎯 Educational Value

These features provide hands-on learning experiences for:
- **Web Security**: Interactive XSS and SQL injection demos
- **Cybersecurity Knowledge**: Quiz with real-world questions
- **Security Awareness**: Current news and historical context
- **Virus Education**: Understanding of famous malware without risk

The retro Windows 95 interface makes learning engaging and memorable while maintaining educational value.
