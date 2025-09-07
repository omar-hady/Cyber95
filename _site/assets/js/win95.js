// Windows 95 Cybersecurity Interactive OS JavaScript
class Windows95Blog {
    constructor() {
        this.windows = new Map();
        this.windowCounter = 0;
        this.currentZIndex = 100;
        this.searchData = null;
        this.currentPath = 'drives';
        this.pathHistory = [];
        this.pathHistoryIndex = -1;
        this.windowStateKey = 'win95_windows_state';
        this.printQueue = [];
        this.newsData = null;
        this.virusData = null;
        this.soundEnabled = true;
        this.volume = 0.3;
        this.achievements = [];
        this.hiddenChallenges = new Map();
        this.networkServers = new Map();
        this.malwareMuseum = new Map();
        this.blueTeamTools = new Map();
        this.clipboardText = '';
        this.activeWindowId = null;
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.startClock();
        this.loadSearchData();
        this.loadNewsData();
        this.loadVirusData();
        this.setupKeyboardShortcuts();
        this.initializeCybersecurityFeatures();
        this.restoreWindowsState();
        this.playSound('start');
    }

    initializeCybersecurityFeatures() {
        // Initialize hidden challenges
        this.setupHiddenChallenges();
        
        // Initialize network servers
        this.setupNetworkServers();
        
        // Initialize malware museum
        this.setupMalwareMuseum();
        
        // Initialize blue team tools
        this.setupBlueTeamTools();
        
        // Load achievements
        this.loadAchievements();
    }

    setupHiddenChallenges() {
        this.hiddenChallenges.set('steganography', {
            name: 'Hidden Message Challenge',
            description: 'Find the hidden message in the image',
            type: 'steganography',
            solved: false,
            solution: 'SECRET_KEY_1995',
            hint: 'Look closely at the image data...'
        });
        
        this.hiddenChallenges.set('crackme', {
            name: 'Password Cracker',
            description: 'Crack the password protection',
            type: 'crackme',
            solved: false,
            solution: 'HACKER_1995',
            hint: 'Try common password patterns...'
        });
        
        this.hiddenChallenges.set('loganalysis', {
            name: 'Log Analysis Puzzle',
            description: 'Analyze the log files to find the attack',
            type: 'loganalysis',
            solved: false,
            solution: 'SQL_INJECTION_ATTEMPT',
            hint: 'Look for unusual database queries...'
        });
    }

    setupNetworkServers() {
        this.networkServers.set('ftp-server', {
            name: 'FTP Server',
            description: 'File Transfer Protocol Server',
            vulnerable: true,
            config: {
                port: 21,
                anonymous_access: true,
                root_access: false,
                logs: [
                    '2025-01-03 10:15:23 - Anonymous login attempt',
                    '2025-01-03 10:16:45 - Failed password attempt: admin',
                    '2025-01-03 10:17:12 - Directory traversal attempt: ../../../etc/passwd'
                ]
            }
        });
        
        this.networkServers.set('mail-server', {
            name: 'Mail Server',
            description: 'SMTP Mail Server',
            vulnerable: true,
            config: {
                port: 25,
                open_relay: true,
                authentication: false,
                logs: [
                    '2025-01-03 10:20:15 - Open relay abuse detected',
                    '2025-01-03 10:21:33 - Spam email sent to 1000 recipients',
                    '2025-01-03 10:22:45 - Mail bombing attempt blocked'
                ]
            }
        });
        
        this.networkServers.set('web-server', {
            name: 'Web Server',
            description: 'HTTP Web Server',
            vulnerable: true,
            config: {
                port: 80,
                version: 'Apache/1.3.0',
                directory_listing: true,
                logs: [
                    '2025-01-03 10:25:12 - Directory listing accessed: /admin/',
                    '2025-01-03 10:26:34 - SQL injection attempt: \' OR 1=1--',
                    '2025-01-03 10:27:56 - XSS payload detected: <script>alert()</script>'
                ]
            }
        });
    }

    setupMalwareMuseum() {
        this.malwareMuseum.set('iloveyou', {
            name: 'ILOVEYOU.vbs',
            type: 'VBScript Worm',
            year: '2000',
            description: 'The ILOVEYOU virus was one of the most destructive computer viruses ever created.',
            impact: 'Estimated $10 billion in damages globally',
            payload: 'Overwrote files and sent itself to everyone in the victim\'s address book',
            effect: 'red-flash',
            screenshots: [
                'Love letter for you.txt',
                'LOVE-LETTER-FOR-YOU.TXT.vbs'
            ]
        });
        
        this.malwareMuseum.set('melissa', {
            name: 'Melissa.doc',
            type: 'Macro Virus',
            year: '1999',
            description: 'Melissa was one of the first major macro viruses to spread via email.',
            impact: 'Widespread email server overloads',
            payload: 'Infected Word documents and spread through email attachments',
            effect: 'blue-flash',
            screenshots: [
                'Important Message from [Name]',
                'Here is that document you asked for...'
            ]
        });
        
        this.malwareMuseum.set('wannacry', {
            name: 'WannaCry.exe',
            type: 'Ransomware',
            year: '2017',
            description: 'WannaCry was a ransomware attack that affected hundreds of thousands of computers.',
            impact: 'Affected over 150 countries',
            payload: 'Encrypted files and demanded Bitcoin payments for decryption',
            effect: 'green-flash',
            screenshots: [
                'WannaCry ransom note',
                'Bitcoin payment demand'
            ]
        });
    }

    setupBlueTeamTools() {
        this.blueTeamTools.set('wireshark', {
            name: 'Wireshark',
            description: 'Network protocol analyzer',
            logs: [
                '10:30:15 - Suspicious traffic detected from 192.168.1.100',
                '10:31:22 - Port scan detected on ports 21,22,23,80,443',
                '10:32:45 - SQL injection attempt blocked',
                '10:33:12 - XSS payload filtered successfully'
            ]
        });
        
        this.blueTeamTools.set('ids', {
            name: 'Intrusion Detection System',
            description: 'Network security monitoring',
            alerts: [
                'ALERT: Multiple failed login attempts from 192.168.1.100',
                'ALERT: Unusual file access pattern detected',
                'ALERT: Potential data exfiltration attempt',
                'ALERT: Suspicious process creation detected'
            ]
        });
        
        this.blueTeamTools.set('forensics', {
            name: 'Forensic Analysis',
            description: 'Digital forensics tools',
            evidence: [
                'Deleted file recovered: suspicious.exe',
                'Registry key modified: HKCU\\Software\\Malware',
                'Network connection log: 192.168.1.100:4444',
                'Process memory dump: malicious_code_found'
            ]
        });
    }
    
    setupEventListeners() {
        // Desktop icons: single-click selects, double-click opens (authentic Win95 behavior)
        document.querySelectorAll('.desktop-icon').forEach(icon => {
            // Single click: select only
            icon.addEventListener('click', (e) => {
                e.preventDefault();
                // Clear previous selection and select this icon
                document.querySelectorAll('.desktop-icon').forEach(i => i.classList.remove('selected'));
                icon.classList.add('selected');
            });
            // Double click: open once
            icon.addEventListener('dblclick', (e) => {
                e.preventDefault();
                const windowType = e.currentTarget.dataset.window;
                if (windowType === 'my-computer') {
                    // My Computer opens File Explorer to drives view
                    this.playSound('click');
                    this.currentPath = 'drives';
                    const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'file-explorer');
                    if (!existingWindow) {
                        this.openWindow('file-explorer');
                    } else {
                        this.focusWindow(existingWindow.element.dataset.windowId);
                        this.loadFileList();
                        this.updateAddressBar();
                    }
                } else if (windowType === 'file-explorer') {
                    this.playSound('click');
                    this.openWindow(windowType);
                } else if (windowType) {
                    const existingWindow = Array.from(this.windows.values()).find(w => w.type === windowType);
                    if (!existingWindow) {
                        this.playSound('click');
                        this.openWindow(windowType);
                    } else {
                        this.focusWindow(existingWindow.element.dataset.windowId);
                    }
                }
            });
        });
        
        // Start button
        const startButton = document.getElementById('start-button');
        if (startButton) {
            startButton.addEventListener('click', (e) => {
                e.stopPropagation();
                this.playSound('click');
                this.toggleStartMenu();
            });
        }
        
        // Start menu items
        document.querySelectorAll('.start-menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const windowType = e.currentTarget.dataset.window;
                const path = e.currentTarget.dataset.path;
                
                if (windowType === 'my-computer') {
                    // My Computer opens File Explorer to drives view
                    this.currentPath = 'drives';
                    const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'file-explorer');
                    if (!existingWindow) {
                        this.openWindow('file-explorer');
                    } else {
                        this.focusWindow(existingWindow.element.dataset.windowId);
                        this.loadFileList();
                        this.updateAddressBar();
                    }
                } else if (path && windowType === 'explorer') {
                    // Open explorer with specific path
                    this.currentPath = path;
                    const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'file-explorer');
                    if (!existingWindow) {
                        this.openWindow('file-explorer');
                    } else {
                        this.focusWindow(existingWindow.element.dataset.windowId);
                        this.loadFileList();
                        this.updateAddressBar();
                    }
                } else if (windowType && windowType.includes('-quiz')) {
                    // Handle quiz windows
                    const existingWindow = Array.from(this.windows.values()).find(w => w.type === windowType);
                    if (!existingWindow) {
                        this.openWindow(windowType);
                    } else {
                        this.focusWindow(existingWindow.element.dataset.windowId);
                    }
                } else if (windowType) {
                    // Check if window already exists
                    const existingWindow = Array.from(this.windows.values()).find(w => w.type === windowType);
                    if (!existingWindow) {
                        this.openWindow(windowType);
                    } else {
                        // Focus existing window
                        this.focusWindow(existingWindow.element.dataset.windowId);
                    }
                }
                this.hideStartMenu();
            });
        });
        
        // Click outside to close start menu
        document.addEventListener('click', (e) => {
            const startMenu = document.getElementById('start-menu');
            const startButton = document.getElementById('start-button');
            if (startMenu && !startMenu.contains(e.target) && !startButton?.contains(e.target)) {
                this.hideStartMenu();
            }
        });
        
        // Prevent start menu from closing when clicking inside
        const startMenu = document.getElementById('start-menu');
        if (startMenu) {
            startMenu.addEventListener('click', (e) => {
                e.stopPropagation();
            });
        }

        // Clock click opens Calendar
        const clock = document.getElementById('taskbar-clock');
        if (clock) {
            clock.addEventListener('click', () => {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'calendar');
                if (!existingWindow) {
                    this.openWindow('calendar');
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            });
        }

        // System tray
        const trayWifi = document.getElementById('tray-wifi');
        const trayVol = document.getElementById('tray-volume');
        const trayAv = document.getElementById('tray-av');
        const attachPopup = (iconEl, templateId, onReady) => {
            if (iconEl) {
                iconEl.addEventListener('click', (e) => {
                    e.stopPropagation();
                    // remove existing
                    document.querySelectorAll('.tray-popup').forEach(p=>p.remove());
                    const tpl = document.getElementById(templateId);
                    if (!tpl) return;
                    const el = tpl.content.cloneNode(true).firstElementChild;
                    document.body.appendChild(el);
                    onReady && onReady(el);
                    const closer = ()=> el.remove();
                    setTimeout(()=> document.addEventListener('click', closer, { once: true }), 0);
                });
            }
        };
        let wifiConnected = false;
        attachPopup(trayWifi, 'tray-wifi-popup', (el)=>{
            const status = el.querySelector('#wifi-status');
            const btn = el.querySelector('#wifi-toggle');
            if (status && btn) {
                status.textContent = wifiConnected ? 'Connected' : 'Disconnected';
                btn.addEventListener('click', ()=>{ wifiConnected = !wifiConnected; status.textContent = wifiConnected ? 'Connected' : 'Disconnected'; });
            }
        });
        let volume = parseInt(localStorage.getItem('win95_volume')||'100',10);
        attachPopup(trayVol, 'tray-volume-popup', (el)=>{
            const slider = el.querySelector('#volume-slider');
            if (slider) {
                slider.value = String(volume);
                slider.addEventListener('input', ()=>{ volume = parseInt(slider.value,10); localStorage.setItem('win95_volume', String(volume)); });
            }
        });
        attachPopup(trayAv, 'tray-av-popup');
    }
    
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Backtick key opens CMD
            if (e.key === '`' || e.key === '~') {
                e.preventDefault();
                this.openWindow('cmd');
            }
            
            // Escape closes start menu
            if (e.key === 'Escape') {
                this.hideStartMenu();
            }
            
            // Ctrl+Shift+X opens hidden X: drive
            if (e.ctrlKey && e.shiftKey && e.key === 'X') {
                e.preventDefault();
                this.unlockHiddenDrive();
            }
        });
    }
    
    startClock() {
        const updateClock = () => {
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            document.getElementById('clock-time').textContent = timeString;
        };
        
        updateClock();
        setInterval(updateClock, 1000);
    }
    
    async loadSearchData() {
        try {
            console.log('Loading search data...');
            const response = await fetch('/search.json');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            this.searchData = await response.json();
            console.log('Search data loaded successfully:', this.searchData.length, 'posts');
            
            // Refresh any open File Explorer windows
            const fileExplorerWindow = document.querySelector('[data-window-id] .file-explorer');
            if (fileExplorerWindow) {
                console.log('Refreshing File Explorer with loaded data');
                this.loadFileList();
            }
            
            // Refresh any open Internet Explorer windows
            const ieWindows = document.querySelectorAll('[data-window-id] .internet');
            ieWindows.forEach(ieWindow => {
                const list = ieWindow.querySelector('#ie-list');
                if (list) {
                    list.innerHTML = '';
                    this.searchData.forEach(post => {
                        const icon = `<img src="${(window.JEKYLL_BASE || '')}/assets/icons/mshtml_32528.ico" style=\"width:16px;height:16px;image-rendering:pixelated;\"/>`;
                        const item = this.createFileItem(post.title, icon, 'post', post);
                        list.appendChild(item);
                    });
                }
            });
        } catch (error) {
            console.error('Failed to load search data:', error);
            this.searchData = [];
            // Show error message in any open file explorers
            const fileLists = document.querySelectorAll('#file-list');
            fileLists.forEach(fileList => {
                if (fileList.children.length === 0) {
                    fileList.innerHTML = '<div class="file-item no-posts"><div class="file-name">Error loading posts. Please refresh the page.</div></div>';
                }
            });
        }
    }
    
    toggleStartMenu() {
        const startMenu = document.getElementById('start-menu');
        const isVisible = startMenu.style.display !== 'none';
        startMenu.style.display = isVisible ? 'none' : 'block';
    }
    
    hideStartMenu() {
        document.getElementById('start-menu').style.display = 'none';
    }
    
    openWindow(type, data = null) {
        // Deduplicate: if window of same resource is open, focus it
        const singletonTypes = new Set(['file-explorer','cmd','internet','calculator','minesweeper','print-queue','achievements']);
        if (singletonTypes.has(type)) {
            const existing = Array.from(this.windows.values()).find(w => w.type === type);
            if (existing) {
                this.focusWindow(existing.element.dataset.windowId);
                return existing.element.dataset.windowId;
            }
        }
        if (type === 'post' && data && data.title) {
            const existingPost = Array.from(this.windows.values()).find(w => w.type === 'post' && w.data && w.data.title === data.title);
            if (existingPost) {
                this.focusWindow(existingPost.element.dataset.windowId);
                return existingPost.element.dataset.windowId;
            }
        }
        if (type === 'notepad' && data && data.title) {
            const existingPad = Array.from(this.windows.values()).find(w => w.type === 'notepad' && w.data && w.data.title === data.title);
            if (existingPad) {
                this.focusWindow(existingPad.element.dataset.windowId);
                return existingPad.element.dataset.windowId;
            }
        }

        const windowId = `window-${++this.windowCounter}`;
        const window = this.createWindow(windowId, type, data);
        
        this.windows.set(windowId, {
            element: window,
            type: type,
            data: data,
            zIndex: ++this.currentZIndex
        });
        
        window.style.zIndex = this.currentZIndex;
        // Random initial position
        window.style.left = Math.max(8, Math.floor(Math.random()*200)) + 'px';
        window.style.top = Math.max(8, Math.floor(Math.random()*120)) + 'px';
        document.getElementById('windows-container').appendChild(window);
        this.addTaskButton(windowId, type);
        this.focusWindow(windowId);
        this.saveWindowsState();
        
        return windowId;
    }
    
    createWindow(windowId, type, data) {
        const template = document.getElementById(`${type}-template`);
        if (!template) {
            throw new Error(`Template not found for window type: ${type}`);
        }
        
        const windowTemplate = document.getElementById('window-template');
        const windowElement = windowTemplate.content.cloneNode(true);
        const windowDiv = windowElement.querySelector('.window');
        const windowBody = windowDiv.querySelector('.window-body');
        const titleBar = windowDiv.querySelector('.title-bar-text');
        
        windowDiv.dataset.windowId = windowId;
        
        // Set window title
        const titles = {
            'file-explorer': 'File Explorer',
            'recycle-bin': 'Recycle Bin',
            'cmd': 'Command Prompt',
            'post': data ? data.title : 'Post',
            'calendar': 'Calendar',
            'internet': 'Internet Explorer',
            'notepad': data && data.title ? `Notepad - ${data.title}` : 'Notepad',
            'calculator': 'Calculator',
            'minesweeper': 'Minesweeper',
            'file-viewer': 'File Viewer',
            'quiz': 'Quiz.exe',
            'print-queue': 'Print Queue',
            'news': 'Security News',
            'virus': 'Virus Museum',
            'network-neighborhood': 'Network Neighborhood',
            'malware-museum': 'Malware Museum',
            'blue-team': 'Blue Team Tools',
            'hidden-challenges': 'Hidden Challenges',
            'xss-demo': 'XSS Demo',
            'burp-suite': 'Burp Suite',
            'log-analyzer': 'Log Analyzer',
            'steganography': 'Steganography Challenge',
            'crackme': 'Password Cracker',
            'achievements': 'Achievements',
            'control-panel': 'Control Panel'
        };
        titleBar.textContent = titles[type] || type;
        
        // Clone and append content
        const content = template.content.cloneNode(true);
        windowBody.appendChild(content);
        
        // Setup window controls
        this.setupWindowControls(windowDiv, windowId);
        
        // Setup type-specific functionality
        this.setupWindowType(windowDiv, type, data);
        
        return windowDiv;
    }
    
    setupWindowControls(windowElement, windowId) {
        const titleBar = windowElement.querySelector('.title-bar');
        const minimizeBtn = windowElement.querySelector('.minimize');
        const maximizeBtn = windowElement.querySelector('.maximize');
        const closeBtn = windowElement.querySelector('.close');
        
        // Make window draggable
        let isDragging = false;
        let startX, startY, startLeft, startTop;
        
        titleBar.addEventListener('mousedown', (e) => {
            if (e.target === titleBar || e.target === titleBar.querySelector('.title-bar-text')) {
                isDragging = true;
                startX = e.clientX;
                startY = e.clientY;
                const rect = windowElement.getBoundingClientRect();
                startLeft = rect.left;
                startTop = rect.top;
                this.focusWindow(windowId);
            }
        });
        
        document.addEventListener('mousemove', (e) => {
            if (isDragging) {
                const deltaX = e.clientX - startX;
                const deltaY = e.clientY - startY;
                windowElement.style.left = `${startLeft + deltaX}px`;
                windowElement.style.top = `${startTop + deltaY}px`;
            }
        });
        
        document.addEventListener('mouseup', () => {
            if (isDragging) { this.saveWindowsState(); }
            isDragging = false;
        });
        
        // Window controls
        minimizeBtn.addEventListener('click', () => {
            this.playSound('minimize');
            this.minimizeWindow(windowId);
            this.saveWindowsState();
        });
        
        maximizeBtn.addEventListener('click', () => {
            this.playSound('maximize');
            this.maximizeWindow(windowId);
            this.saveWindowsState();
        });
        
        closeBtn.addEventListener('click', () => {
            this.playSound('click');
            this.closeWindow(windowId);
            this.saveWindowsState();
        });
        
        // Focus on click
        windowElement.addEventListener('mousedown', () => {
            this.focusWindow(windowId);
        });
        
        // Setup window resizing
        this.setupWindowResizing(windowElement, windowId);
        
        // Setup window snapping
        this.setupWindowSnapping(windowElement, windowId);
    }
    
    setupWindowType(windowElement, type, data) {
        switch (type) {
            case 'file-explorer':
                this.setupFileExplorer(windowElement);
                break;
            case 'cmd':
                this.setupCmdWindow(windowElement);
                break;
            case 'post':
                this.setupPostWindow(windowElement, data);
                break;
            case 'recycle-bin':
                this.setupRecycle(windowElement);
                break;
            case 'calendar':
                this.setupCalendar(windowElement);
                break;
            case 'internet':
                this.setupInternet(windowElement);
                break;
            case 'file-viewer':
                this.setupFileViewer(windowElement, data);
                break;
            case 'notepad':
                this.setupNotepad(windowElement, data);
                break;
            case 'calculator':
                this.setupCalculator(windowElement);
                break;
            case 'minesweeper':
                this.setupMinesweeper(windowElement);
                break;
            case 'quiz':
                this.setupQuiz(windowElement);
                break;
            case 'xss-quiz':
            case 'sqli-quiz':
            case 'forensics-quiz':
            case 'network-quiz':
            case 'webapp-quiz':
                this.setupQuizWindow(windowElement, windowType);
                break;
            case 'print-queue':
                this.setupPrintQueue(windowElement);
                break;
            case 'news':
                this.setupNews(windowElement, data);
                break;
            case 'virus':
                this.setupVirus(windowElement, data);
                break;
            case 'hidden-challenges':
                this.setupHiddenChallengesWindow(windowElement, data);
                break;
            case 'network-neighborhood':
                this.setupNetworkNeighborhoodWindow(windowElement, data);
                break;
            case 'malware-museum':
                this.setupMalwareMuseumWindow(windowElement, data);
                break;
            case 'blue-team':
                this.setupBlueTeamWindow(windowElement, data);
                break;
            case 'xss-demo':
                this.setupXSSDemoWindow(windowElement, data);
                break;
            case 'burp-suite':
                this.setupBurpSuiteWindow(windowElement, data);
                break;
            case 'log-analyzer':
                this.setupLogAnalyzerWindow(windowElement, data);
                break;
            case 'achievements':
                this.setupAchievementsWindow(windowElement);
                break;
            case 'control-panel':
                this.setupControlPanel(windowElement);
                break;
        }
    }

    setupControlPanel(windowElement) {
        const buttons = windowElement.querySelectorAll('.toolbar-button');
        const tabs = windowElement.querySelectorAll('.cp-tab');
        const showTab = (name)=>{
            tabs.forEach(t=>{ t.style.display = t.dataset.tab === name ? 'block' : 'none'; });
        };
        buttons.forEach(btn=>{
            btn.addEventListener('click', ()=>{ showTab(btn.dataset.tab); });
        });
        // Display: wallpapers
        const select = windowElement.querySelector('#cp-wallpaper-select');
        const applyBtn = windowElement.querySelector('#cp-apply-wallpaper');
        const wallpapers = [
            '/assets/icons/explorer_100.ico',
            '/assets/icons/mshtml_32528.ico',
            '/assets/icons/notepad_1.ico'
        ];
        if (select) {
            select.innerHTML = wallpapers.map(w=>`<option value="${w}">${w.split('/').pop()}</option>`).join('');
        }
        if (applyBtn && select) {
            applyBtn.addEventListener('click', ()=>{
                const val = select.value;
                document.body.style.backgroundImage = `url(${val})`;
                document.body.style.backgroundSize = 'cover';
                document.body.style.backgroundRepeat = 'no-repeat';
            });
        }
        // Sounds toggle
        const soundsToggle = windowElement.querySelector('#cp-sounds-toggle');
        if (soundsToggle) {
            soundsToggle.checked = !!this.soundEnabled;
            soundsToggle.addEventListener('change', ()=>{
                this.soundEnabled = soundsToggle.checked;
            });
        }
    }
    
    setupFileExplorer(windowElement) {
        const backBtn = windowElement.querySelector('#back-btn');
        const forwardBtn = windowElement.querySelector('#forward-btn');
        const upBtn = windowElement.querySelector('#up-btn');
        const addressInput = windowElement.querySelector('#address-input');
        const searchInput = windowElement.querySelector('#search-input');
        const fileList = windowElement.querySelector('#file-list');
        const statusBar = windowElement.querySelector('#explorer-status-bar');
        const statusFiles = windowElement.querySelector('#status-files');
        const statusSelected = windowElement.querySelector('#status-selected');
        const selectedFileName = windowElement.querySelector('#selected-file-name');
        const selectedFileSize = windowElement.querySelector('#selected-file-size');
        const statusSpace = windowElement.querySelector('#status-space');
        
        // Initialize tabs
        this.setupExplorerTabs(windowElement);
        
        // Navigation buttons
        backBtn.addEventListener('click', () => {
            this.playSound('click');
            this.navigateBack();
        });
        forwardBtn.addEventListener('click', () => {
            this.playSound('click');
            this.navigateForward();
        });
        upBtn.addEventListener('click', () => {
            this.playSound('click');
            this.navigateUp();
        });
        
        // Address bar functionality
        addressInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.playSound('click');
                this.navigateToPath(e.target.value);
            }
        });
        
        addressInput.addEventListener('blur', (e) => {
            this.updateAddressBar();
        });
        
        // Search functionality
        searchInput.addEventListener('input', (e) => {
            this.searchPosts(e.target.value);
        });
        
        // Tree view navigation
        this.setupTreeView(windowElement);
        
        // Load initial content
        this.loadFileList();
        
        // Ensure search data is loaded
        if (!this.searchData) {
            console.log('Search data not loaded, waiting for it...');
            const checkData = () => {
                if (this.searchData && this.searchData.length > 0) {
                    console.log('Search data loaded, refreshing file list');
                    this.loadFileList();
                } else {
                    setTimeout(checkData, 100);
                }
            };
            checkData();
        }
    }
    
    setupTreeView(windowElement) {
        const treeItems = windowElement.querySelectorAll('.tree-item');
        
        treeItems.forEach(item => {
            const toggle = item.querySelector('.tree-toggle');
            const label = item.querySelector('.tree-label');
            
            // Handle toggle clicks
            if (toggle) {
                toggle.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.playSound('click');
                    this.toggleTreeItem(item);
                });
            }
            
            // Handle item clicks
            item.addEventListener('click', (e) => {
                this.playSound('click');
                this.selectTreeItem(item);
                
                // Navigate to the selected path
                if (item.dataset.drive) {
                    this.currentPath = item.dataset.drive;
                } else if (item.dataset.path) {
                    this.currentPath = item.dataset.path;
                }
                
                this.loadFileList();
                this.updateAddressBar();
            });
        });
    }
    
    toggleTreeItem(item) {
        const isExpanded = item.dataset.expanded === 'true';
        const toggle = item.querySelector('.tree-toggle');
        const children = item.nextElementSibling;
        
        if (isExpanded) {
            // Collapse
            item.dataset.expanded = 'false';
            toggle.textContent = '+';
            if (children && children.classList.contains('tree-children')) {
                children.style.display = 'none';
            }
        } else {
            // Expand
            item.dataset.expanded = 'true';
            toggle.textContent = '-';
            if (children && children.classList.contains('tree-children')) {
                children.style.display = 'block';
            }
        }
    }
    
    selectTreeItem(item) {
        // Remove selection from all items
        const allItems = item.closest('.tree-view').querySelectorAll('.tree-item');
        allItems.forEach(i => i.classList.remove('selected'));
        
        // Select current item
        item.classList.add('selected');
    }
    
    setupCmdWindow(windowElement) {
        const cmdInput = windowElement.querySelector('#cmd-input');
        const cmdOutput = windowElement.querySelector('#cmd-output');
        
        cmdInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const command = cmdInput.value.trim();
                this.executeCommand(command, cmdOutput);
                cmdInput.value = '';
            }
        });
        
        // Focus input
        setTimeout(() => cmdInput.focus(), 100);
    }
    
    setupPostWindow(windowElement, data) {
        const postContent = windowElement.querySelector('#post-content');
        const printBtn = windowElement.querySelector('#print-post');
        const saveBtn = windowElement.querySelector('#save-post');
        const zoomInBtn = windowElement.querySelector('#zoom-in');
        const zoomOutBtn = windowElement.querySelector('#zoom-out');
        const postStatus = windowElement.querySelector('#post-status');
        const postPageInfo = windowElement.querySelector('#post-page-info');
        
        // Initialize zoom level
        let zoomLevel = 1;
        
        if (data) {
            // Create a proper post display with title and content
            let htmlContent = `<h1>${data.title || 'Untitled Post'}</h1>`;
            
            if (data.date) {
                htmlContent += `<p class="post-date">${new Date(data.date).toLocaleDateString()}</p>`;
            }
            
            if (data.categories && data.categories.length > 0) {
                htmlContent += `<p class="post-categories">Categories: ${data.categories.join(', ')}</p>`;
            }
            
            if (data.excerpt) {
                htmlContent += `<div class="post-excerpt">${data.excerpt}</div>`;
            }
            
            // For content, we need to fetch the full HTML content
            // Since search.json strips HTML, we'll need to fetch the actual post
            if (data.url) {
                this.loadPostContent(data.url, postContent, htmlContent);
            } else if (data.content) {
                htmlContent += `<div class="post-body">${data.content}</div>`;
                postContent.innerHTML = htmlContent;
            } else {
                htmlContent += `<div class="post-body">No content available.</div>`;
                postContent.innerHTML = htmlContent;
            }
            
            // Update status
            if (postStatus) {
                postStatus.textContent = 'Ready';
            }
            if (postPageInfo) {
                postPageInfo.textContent = 'Page 1 of 1';
            }
        }
        
        // Print functionality
        if (printBtn && data) {
            printBtn.addEventListener('click', () => {
                this.playSound('click');
                this.printPost(data);
            });
        }
        
        // Save functionality (permission denied)
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                this.playSound('click');
                this.showPermissionDenied();
            });
        }
        
        // Zoom functionality
        if (zoomInBtn) {
            zoomInBtn.addEventListener('click', () => {
                this.playSound('click');
                zoomLevel = Math.min(zoomLevel + 0.1, 2.0);
                postContent.style.fontSize = `${16 * zoomLevel}px`;
                if (postStatus) {
                    postStatus.textContent = `Zoom: ${Math.round(zoomLevel * 100)}%`;
                }
            });
        }
        
        if (zoomOutBtn) {
            zoomOutBtn.addEventListener('click', () => {
                this.playSound('click');
                zoomLevel = Math.max(zoomLevel - 0.1, 0.5);
                postContent.style.fontSize = `${16 * zoomLevel}px`;
                if (postStatus) {
                    postStatus.textContent = `Zoom: ${Math.round(zoomLevel * 100)}%`;
                }
            });
        }
        
        // Menu functionality
        this.setupPostMenus(windowElement, data);
    }
    
    setupPostMenus(windowElement, data) {
        // File menu
        const printOption = windowElement.querySelector('#print-option');
        const saveOption = windowElement.querySelector('#save-option');
        const exitOption = windowElement.querySelector('#exit-option');
        
        if (printOption && data) {
            printOption.addEventListener('click', () => {
                this.playSound('click');
                this.printPost(data);
            });
        }
        
        if (saveOption) {
            saveOption.addEventListener('click', () => {
                this.playSound('click');
                this.showPermissionDenied();
            });
        }
        
        if (exitOption) {
            exitOption.addEventListener('click', () => {
                this.playSound('click');
                const window = windowElement.closest('.window95');
                if (window) {
                    this.closeWindow(window);
                }
            });
        }
        
        // Edit menu
        const copyOption = windowElement.querySelector('#copy-option');
        const selectAllOption = windowElement.querySelector('#select-all-option');
        
        if (copyOption) {
            copyOption.addEventListener('click', () => {
                this.playSound('click');
                this.copyPostContent(windowElement);
            });
        }
        
        if (selectAllOption) {
            selectAllOption.addEventListener('click', () => {
                this.playSound('click');
                this.selectAllPostContent(windowElement);
            });
        }
    }
    
    showPermissionDenied() {
        // Create a simple alert dialog
        const dialog = document.createElement('div');
        dialog.className = 'dialog95';
        dialog.innerHTML = `
            <div class="dialog-content">
                <div class="dialog-header">Access Denied</div>
                <div class="dialog-body">
                    <p>You do not have permission to save this file.</p>
                    <p>This is a read-only document.</p>
                </div>
                <div class="dialog-buttons">
                    <button class="dialog-button" onclick="this.closest('.dialog95').remove()">OK</button>
                </div>
            </div>
        `;
        document.body.appendChild(dialog);
    }
    
    copyPostContent(windowElement) {
        const postContent = windowElement.querySelector('#post-content');
        if (postContent) {
            const text = postContent.innerText || postContent.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const postStatus = windowElement.querySelector('#post-status');
                if (postStatus) {
                    postStatus.textContent = 'Content copied to clipboard';
                    setTimeout(() => {
                        postStatus.textContent = 'Ready';
                    }, 2000);
                }
            });
        }
    }
    
    selectAllPostContent(windowElement) {
        const postContent = windowElement.querySelector('#post-content');
        if (postContent) {
            const range = document.createRange();
            range.selectNodeContents(postContent);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
        }
    }
    
    async loadPostContent(url, postContent, htmlContent) {
        try {
            // Fetch the actual post HTML
            const response = await fetch(url);
            const html = await response.text();
            
            // Extract the post content from the HTML
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const postBody = doc.querySelector('.post-content');
            
            if (postBody) {
                // Get the content inside the post-content div
                const content = postBody.innerHTML;
                htmlContent += `<div class="post-body">${content}</div>`;
            } else {
                htmlContent += `<div class="post-body">Content could not be loaded.</div>`;
            }
            
            postContent.innerHTML = htmlContent;
            
            // Reinitialize demos for the loaded content
            this.initializePostDemos(postContent);
        } catch (error) {
            console.error('Failed to load post content:', error);
            htmlContent += `<div class="post-body">Error loading content: ${error.message}</div>`;
            postContent.innerHTML = htmlContent;
        }
    }
    
    initializePostDemos(container) {
        // Initialize XSS Demo
        const xssContainer = container.querySelector('.xss-demo');
        if (xssContainer) {
            const input = xssContainer.querySelector('.xss-input');
            const output = xssContainer.querySelector('.xss-output');
            const executeBtn = xssContainer.querySelector('.xss-execute');

            if (input && output && executeBtn) {
                executeBtn.addEventListener('click', () => {
                    this.executeXSSDemo(input.value, output);
                });

                input.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        this.executeXSSDemo(input.value, output);
                    }
                });
            }
        }

        // Initialize SQL Injection Demo
        const sqliContainer = container.querySelector('.sqli-demo');
        if (sqliContainer) {
            const usernameInput = sqliContainer.querySelector('.sqli-username');
            const passwordInput = sqliContainer.querySelector('.sqli-password');
            const loginBtn = sqliContainer.querySelector('.sqli-login');
            const resultDiv = sqliContainer.querySelector('.sqli-result');

            if (usernameInput && passwordInput && loginBtn && resultDiv) {
                loginBtn.addEventListener('click', () => {
                    this.executeSQLiDemo(usernameInput.value, passwordInput.value, resultDiv);
                });

                [usernameInput, passwordInput].forEach(input => {
                    input.addEventListener('keypress', (e) => {
                        if (e.key === 'Enter') {
                            this.executeSQLiDemo(usernameInput.value, passwordInput.value, resultDiv);
                        }
                    });
                });
            }
        }
    }
    
    executeXSSDemo(payload, outputElement) {
        const safePayload = this.sanitizeXSS(payload);
        const vulnerablePayload = payload;

        outputElement.innerHTML = `
            <div class="demo-result">
                <h4>Vulnerable Output (No Sanitization):</h4>
                <div class="vulnerable-output">${vulnerablePayload}</div>
                <h4>Safe Output (With Sanitization):</h4>
                <div class="safe-output">${safePayload}</div>
                <div class="demo-explanation">
                    <strong>Explanation:</strong> The vulnerable output shows how XSS payloads can execute, 
                    while the safe output shows proper sanitization.
                </div>
            </div>
        `;

        if (payload.toLowerCase().includes('<script>') || payload.toLowerCase().includes('javascript:')) {
            this.unlockAchievement('XSS Explorer');
        }
    }

    sanitizeXSS(input) {
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    executeSQLiDemo(username, password, resultElement) {
        const isSQLi = this.detectSQLi(username) || this.detectSQLi(password);
        
        if (isSQLi) {
            resultElement.innerHTML = `
                <div class="sqli-success">
                    <h4>🚨 SQL Injection Detected!</h4>
                    <div class="query-display">
                        <strong>Malicious Query:</strong><br>
                        <code>SELECT * FROM users WHERE username='${username}' AND password='${password}'</code>
                    </div>
                    <div class="sqli-explanation">
                        <strong>What happened:</strong> The input contains SQL injection payloads that could 
                        manipulate the database query. In a real application, this could lead to:
                        <ul>
                            <li>Unauthorized access to user accounts</li>
                            <li>Data extraction from the database</li>
                            <li>Database manipulation or deletion</li>
                        </ul>
                    </div>
                </div>
            `;
            this.unlockAchievement('SQL Injection Master');
        } else {
            const isValid = this.simulateLogin(username, password);
            resultElement.innerHTML = `
                <div class="login-result ${isValid ? 'success' : 'failed'}">
                    <h4>${isValid ? '✅ Login Successful' : '❌ Login Failed'}</h4>
                    <div class="query-display">
                        <strong>Query:</strong><br>
                        <code>SELECT * FROM users WHERE username='${username}' AND password='${password}'</code>
                    </div>
                    <div class="login-explanation">
                        ${isValid ? 
                            'Valid credentials provided.' : 
                            'Invalid username or password. Try SQL injection payloads like: <code>\' OR \'1\'=\'1</code>'
                        }
                    </div>
                </div>
            `;
        }
    }

    detectSQLi(input) {
        const sqliPatterns = [
            /' OR '1'='1/i,
            /' OR 1=1/i,
            /' UNION SELECT/i,
            /' DROP TABLE/i,
            /' DELETE FROM/i,
            /' INSERT INTO/i,
            /' UPDATE SET/i,
            /' OR 'x'='x/i,
            /' OR 'a'='a/i,
            /' OR 1=1--/i,
            /' OR 1=1#/i,
            /' OR 1=1\/\*/i
        ];
        
        return sqliPatterns.some(pattern => pattern.test(input));
    }

    simulateLogin(username, password) {
        const validLogins = [
            { user: 'admin', pass: 'admin123' },
            { user: 'user', pass: 'password' },
            { user: 'test', pass: 'test123' }
        ];
        
        return validLogins.some(login => 
            login.user === username && login.pass === password
        );
    }
    
    loadFileList() {
        const fileList = document.querySelector('#file-list');
        if (!fileList) return;
        
        // Show loading animation for partitions
        if (this.currentPath === 'C:\\' || this.currentPath === 'D:\\' || this.currentPath === 'F:\\' || 
            this.currentPath === 'X:\\' || this.currentPath === 'Network:\\' || this.currentPath === 'Malware:\\' || 
            this.currentPath === 'BlueTeam:\\') {
            this.showLoadingAnimation(fileList, 'Searching...');
        }
        
        fileList.innerHTML = '';
        
        if (this.currentPath === 'drives' || !this.currentPath) {
            this.loadDrives(fileList);
        } else if (this.currentPath === 'C:\\') {
            this.loadPostsInCategory(fileList, 'bug-bounty');
        } else if (this.currentPath === 'D:\\') {
            this.loadPostsInCategory(fileList, 'penetration-testing');
        } else if (this.currentPath === 'E:\\') {
            this.loadForensics(fileList);
        } else if (this.currentPath === 'F:\\') {
            this.loadPostsInCategory(fileList, 'write-ups');
        } else if (this.currentPath === 'X:\\') {
            this.loadHiddenChallenges(fileList);
        } else if (this.currentPath === 'Network:\\') {
            this.loadNetworkServers(fileList);
        } else if (this.currentPath === 'Malware:\\') {
            this.loadMalwareMuseum(fileList);
        } else if (this.currentPath === 'BlueTeam:\\') {
            this.loadBlueTeamTools(fileList);
        } else {
            // Fallback: treat as category name
            this.loadPostsInCategory(fileList, this.currentPath);
        }
        
        // Update tree view selection
        this.updateTreeSelection();
        
        // Update status bar
        this.updateStatusBar();
    }
    
    updateTreeSelection() {
        const treeItems = document.querySelectorAll('.tree-item');
        treeItems.forEach(item => {
            item.classList.remove('selected');
            if ((item.dataset.drive && item.dataset.drive === this.currentPath) ||
                (item.dataset.path && item.dataset.path === this.currentPath)) {
                item.classList.add('selected');
            }
        });
    }
    
    loadDrives(fileList) {
        const drives = [
            { name: 'C:\\ – Bug Hunting', path: 'C:\\', icon: '/assets/icons/diskcopy_1.ico', free: '512MB', total: '1GB' },
            { name: 'D:\\ – Penetration Testing', path: 'D:\\', icon: '/assets/icons/diskcopy_1.ico', free: '768MB', total: '1GB' },
            { name: 'E:\\ – Forensics', path: 'E:\\', icon: '/assets/icons/diskcopy_1.ico', free: '384MB', total: '1GB' },
            { name: 'F:\\ – Write-ups', path: 'F:\\', icon: '/assets/icons/diskcopy_1.ico', free: '256MB', total: '512MB' },
            { name: 'X:\\ – Hidden Challenges', path: 'X:\\', icon: '/assets/icons/diskcopy_1.ico', free: '128MB', total: '256MB', hidden: true },
            { name: 'Network:\\ – Network Neighborhood', path: 'Network:\\', icon: '/assets/icons/mshtml_32528.ico', free: '64MB', total: '128MB' },
            { name: 'Malware:\\ – Malware Museum', path: 'Malware:\\', icon: '/assets/icons/mshtml_32528.ico', free: '32MB', total: '64MB' },
            { name: 'BlueTeam:\\ – Incident Response', path: 'BlueTeam:\\', icon: '/assets/icons/mshtml_32528.ico', free: '128MB', total: '256MB' }
        ];
        drives.forEach(d => {
            // Skip hidden drives unless unlocked
            if (d.hidden && !this.isHiddenDriveUnlocked()) {
                return;
            }
            
            const item = document.createElement('div');
            item.className = 'file-item drive-item';
            item.innerHTML = `
                <div class="file-icon"><img src="${d.icon}" style="width:24px;height:24px;image-rendering:pixelated;"/></div>
                <div class="file-name">${d.name}</div>
                <div class="disk-space">${d.free} free of ${d.total}</div>
            `;
            item.addEventListener('dblclick', ()=>{
                this.playSound('click');
                this.navigateToDrive(d.path);
            });
            fileList.appendChild(item);
        });
    }

    loadForensics(fileList) {
        const files = [
            { name: 'system.log', content: '[1995-08-24 09:00] Boot OK\n[1995-08-24 09:03] User login: guest\n[1995-08-24 09:07] ALERT: Multiple failed SSH logins from 10.0.0.7' },
            { name: 'memory.dmp', content: 'MEMORY DUMP (FAKE)\n0x0000: 7f 45 4c 46 ...\nHint: Look for suspicious strings or stack traces.' },
            { name: 'webserver.log', content: '10.0.0.5 - - [24/Aug/1995:09:12:14] "GET /index.html HTTP/1.0" 200 -\n10.0.0.7 - - [24/Aug/1995:09:13:02] "GET /?id=1%20OR%201=1 HTTP/1.0" 200 -' }
        ];
        files.forEach(f => {
            const item = document.createElement('div');
            item.className = 'file-item';
            item.innerHTML = `
                <div class="file-icon"><img src="/assets/icons/notepad_1.ico" style="width:16px;height:16px;image-rendering:pixelated;"/></div>
                <div class="file-name">${f.name}</div>
            `;
            // Single click selects
            item.addEventListener('click', () => {
                document.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));
                item.classList.add('selected');
                this.updateStatusBar();
            });
            // Double click opens in Notepad
            item.addEventListener('dblclick', () => {
                this.playSound('click');
                this.openWindow('notepad', { title: f.name, content: f.content });
            });
            fileList.appendChild(item);
        });
    }
    
    loadPostsInCategory(fileList, category) {
        if (!this.searchData) {
            console.log('Search data not loaded yet, waiting...');
            // Wait for search data to load
            setTimeout(() => this.loadPostsInCategory(fileList, category), 100);
            return;
        }
        
        console.log(`Loading posts for category: ${category}`);
        console.log(`Available posts:`, this.searchData);
        
        const posts = this.searchData.filter(post => {
            const cats = (post.categories || []).map(c=>String(c).toLowerCase());
            const hasCategory = cats.includes(String(category).toLowerCase());
            console.log(`Post "${post.title}" categories:`, cats, 'matches', category, ':', hasCategory);
            return hasCategory;
        });
        
        console.log(`Found ${posts.length} posts for category ${category}`);
        
        // If no posts found, try alternative categories
        if (posts.length === 0) {
            const alternativeCategories = {
                'bug-bounty': ['general', 'web-security'],
                'penetration-testing': ['methodology', 'web-security'],
                'write-ups': ['bug-bounty', 'general']
            };
            
            const alternatives = alternativeCategories[category] || [];
            for (const altCategory of alternatives) {
                const altPosts = this.searchData.filter(post => {
                    const cats = (post.categories || []).map(c=>String(c).toLowerCase());
                    return cats.includes(altCategory.toLowerCase());
                });
                if (altPosts.length > 0) {
                    console.log(`Found ${altPosts.length} posts in alternative category: ${altCategory}`);
                    altPosts.forEach(post => {
                        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
                        const postItem = this.createFileItem(post.title, icon, 'post', post);
                        fileList.appendChild(postItem);
                    });
                    return;
                }
            }
        }
        
        if (posts.length === 0) {
            // Show a message when no posts are found
            const noPostsItem = document.createElement('div');
            noPostsItem.className = 'file-item no-posts';
            noPostsItem.innerHTML = `
                <div class="file-icon"><img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/></div>
                <div class="file-name">No posts found in this category</div>
            `;
            fileList.appendChild(noPostsItem);
            return;
        }
        
        posts.forEach(post => {
            const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
            const postItem = this.createFileItem(post.title, icon, 'post', post);
            fileList.appendChild(postItem);
        });
    }
    
    createFileItem(name, icon, type, data = null) {
        const item = document.createElement('div');
        item.className = 'file-item';
        const iconHtml = icon && icon.startsWith('<') ? icon : `<img src="${icon}" style="width:24px;height:24px;image-rendering:pixelated;"/>`;
        item.innerHTML = `
            <div class="file-icon">${iconHtml}</div>
            <div class="file-name">${name}</div>
        `;
        
        // Add click handler for selection
        item.addEventListener('click', (e) => {
            // Remove selection from all items
            document.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));
            // Select this item
            item.classList.add('selected');
            this.updateStatusBar();
        });
        
        item.addEventListener('dblclick', () => {
            this.playSound('open');
            if (type === 'category') {
                this.navigateToCategory(name);
            } else if (type === 'post') {
                this.showLoadingPopup('Loading...');
                setTimeout(() => {
                    this.openPostWindow(data);
                }, 500);
            } else if (type === 'news') {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'news' && w.data?.title === data?.title);
                if (!existingWindow) {
                    this.openWindow('news', data);
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            } else if (type === 'virus') {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'virus' && w.data?.name === data?.name);
                if (!existingWindow) {
                    this.openWindow('virus', data);
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            } else if (type === 'hidden-challenge') {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'hidden-challenges' && w.data?.name === data?.name);
                if (!existingWindow) {
                    this.openWindow('hidden-challenges', data);
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            } else if (type === 'network-server') {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'network-neighborhood' && w.data?.name === data?.name);
                if (!existingWindow) {
                    this.openWindow('network-neighborhood', data);
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            } else if (type === 'malware') {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'malware-museum' && w.data?.name === data?.name);
                if (!existingWindow) {
                    this.openWindow('malware-museum', data);
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            } else if (type === 'blue-team-tool') {
                const existingWindow = Array.from(this.windows.values()).find(w => w.type === 'blue-team' && w.data?.name === data?.name);
                if (!existingWindow) {
                    this.openWindow('blue-team', data);
                } else {
                    this.focusWindow(existingWindow.element.dataset.windowId);
                }
            }
        });
        
        return item;
    }
    
    navigateToCategory(category) {
        this.addToHistory(this.currentPath);
        this.currentPath = category;
        this.loadFileList();
        this.updateAddressBar();
    }

    navigateToDrive(drive) {
        this.addToHistory(this.currentPath);
        this.currentPath = drive;
        this.loadFileList();
        this.updateAddressBar();
    }
    
    navigateBack() {
        if (this.pathHistoryIndex > 0) {
            this.pathHistoryIndex--;
            this.currentPath = this.pathHistory[this.pathHistoryIndex];
            this.loadFileList();
            this.updateAddressBar();
        }
    }
    
    navigateForward() {
        if (this.pathHistoryIndex < this.pathHistory.length - 1) {
            this.pathHistoryIndex++;
            this.currentPath = this.pathHistory[this.pathHistoryIndex];
            this.loadFileList();
            this.updateAddressBar();
        }
    }
    
    navigateUp() {
        if (this.currentPath !== 'drives') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'drives';
            this.loadFileList();
            this.updateAddressBar();
        }
    }
    
    navigateToPath(path) {
        // Handle different path formats
        const cleanPath = path.trim().toLowerCase();
        
        if (cleanPath === 'drives' || cleanPath === 'my computer' || cleanPath === 'mycomputer') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'drives';
        } else if (cleanPath === 'c:\\' || cleanPath === 'c:') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'C:\\';
        } else if (cleanPath === 'd:\\' || cleanPath === 'd:') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'D:\\';
        } else if (cleanPath === 'f:\\' || cleanPath === 'f:') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'F:\\';
        } else if (cleanPath === 'x:\\' || cleanPath === 'x:') {
            if (!this.isHiddenDriveUnlocked()) {
                this.playSound('error');
                this.showMessage('Access denied. Hidden drive not unlocked. Use Ctrl+Shift+X to unlock.');
                return;
            }
            this.addToHistory(this.currentPath);
            this.currentPath = 'X:\\';
        } else if (cleanPath === 'network:\\' || cleanPath === 'network:') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'Network:\\';
        } else if (cleanPath === 'malware:\\' || cleanPath === 'malware:') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'Malware:\\';
        } else if (cleanPath === 'blueteam:\\' || cleanPath === 'blueteam:') {
            this.addToHistory(this.currentPath);
            this.currentPath = 'BlueTeam:\\';
        } else {
            // Invalid path
            this.playSound('error');
            this.updateAddressBar();
            return;
        }
        
        this.loadFileList();
        this.updateAddressBar();
    }
    
    addToHistory(path) {
        this.pathHistory = this.pathHistory.slice(0, this.pathHistoryIndex + 1);
        this.pathHistory.push(path);
        this.pathHistoryIndex = this.pathHistory.length - 1;
    }
    
    updateAddressBar() {
        const addressInput = document.querySelector('#address-input');
        if (addressInput) {
            addressInput.value = this.currentPath || 'drives';
        }
    }
    
    searchPosts(query) {
        if (!query.trim()) {
            this.loadFileList();
            return;
        }
        
        if (!this.searchData) return;
        
        const fileList = document.querySelector('#file-list');
        if (!fileList) return;
        
        fileList.innerHTML = '';
        
        const results = this.searchData.filter(post => {
            const title = (post.title||'').toLowerCase();
            const excerpt = (post.excerpt||'').toLowerCase();
            const content = (post.content||'').toLowerCase();
            const categories = (post.categories||[]).map(c => String(c).toLowerCase());
            const tags = (post.tags||[]).map(t => String(t).toLowerCase());
            
            const searchTerm = query.toLowerCase();
            return title.includes(searchTerm) || 
                   excerpt.includes(searchTerm) || 
                   content.includes(searchTerm) ||
                   categories.some(cat => cat.includes(searchTerm)) ||
                   tags.some(tag => tag.includes(searchTerm));
        });
        
        results.forEach(post => {
            const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
            const postItem = this.createFileItem(post.title, icon, 'post', post);
            fileList.appendChild(postItem);
        });
        
        // Update status bar
        this.updateStatusBar();
    }
    
    openPostWindow(postData) {
        this.openWindow('post', postData);
    }
    
    executeCommand(command, outputElement) {
        const parts = command.split(' ');
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);
        
        let output = '';
        
        switch (cmd) {
            case 'help':
                output = `Available commands:
help - Show this help message
ls - List all posts
cat <title> - Display post content
open <title> - Open post in new window
search <term> - Search posts
echo <text> - Display text
clear - Clear screen
nmap - Fake port scan
whoami - Show current user
hack - Initiate hack
cd <path> - Change directory
pwd - Show current directory
achievements - Show achievements
xss-demo - Open XSS demo
burp - Open Burp Suite demo
log-analyzer - Open log analyzer`;
                break;
                
            case 'ls':
                if (!this.searchData) {
                    output = 'No posts available';
                } else {
                    output = this.searchData.map(post => post.title).join('\n');
                }
                break;
                
            case 'cat':
                if (args.length === 0) {
                    output = 'Usage: cat <title>';
                } else {
                    const title = args.join(' ');
                    const post = this.searchData?.find(p => p.title === title);
                    if (post) {
                        // Strip HTML tags and show content
                        const tempDiv = document.createElement('div');
                        tempDiv.innerHTML = post.content;
                        output = tempDiv.textContent || tempDiv.innerText || '';
                    } else {
                        output = `Post not found: ${title}`;
                    }
                }
                break;
                
            case 'open':
                if (args.length === 0) {
                    output = 'Usage: open <title>';
                } else {
                    const title = args.join(' ');
                    const post = this.searchData?.find(p => p.title === title);
                    if (post) {
                        this.openPostWindow(post);
                        output = `Opening: ${title}`;
                    } else {
                        this.playSound('error');
                        this.showMessage('This program has performed an illegal operation and will be shut down.');
                        output = `Post not found: ${title}`;
                    }
                }
                break;
                
            case 'search':
                if (args.length === 0) {
                    output = 'Usage: search <term>';
                } else {
                    const term = args.join(' ');
                    const results = this.searchData?.filter(post => {
                        const searchText = `${post.title} ${post.excerpt} ${post.content}`.toLowerCase();
                        return searchText.includes(term.toLowerCase());
                    }) || [];
                    
                    if (results.length === 0) {
                        output = `No results found for: ${term}`;
                    } else {
                        output = results.map(post => `${post.title} - ${post.url}`).join('\n');
                    }
                }
                break;
                
            case 'echo':
                output = args.join(' ');
                break;
            case 'nmap':
                output = `Starting Nmap 2.02 ( fake ) at 1995-08-24
Nmap scan report for localhost (127.0.0.1)
Not shown: 995 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy`;
                this.unlockAchievement('Port Scanner');
                break;
            case 'whoami':
                output = Math.random() > 0.5 ? 'admin' : 'guest';
                break;
            case 'hack':
                this.matrixHack(outputElement);
                this.unlockAchievement('Elite Hacker');
                return;
            case 'cd':
                if (args.length > 0) {
                    const path = args[0];
                    if (path === 'X:\\' || path === 'X:') {
                        if (!this.isHiddenDriveUnlocked()) {
                            output = 'Access denied. Hidden drive not unlocked.';
                        } else {
                            this.navigateToPath(path);
                            output = `Changed directory to ${path}`;
                        }
                    } else {
                        this.navigateToPath(path);
                        output = `Changed directory to ${path}`;
                    }
                } else {
                    output = 'Usage: cd <path>';
                }
                break;
            case 'ls':
                if (!this.searchData) {
                    output = 'No posts available';
                } else {
                    output = this.searchData.map(post => post.title).join('\n');
                }
                break;
            case 'pwd':
                output = `Current directory: ${this.currentPath}`;
                break;
            case 'mycomputer':
            case 'my computer':
                this.currentPath = 'drives';
                const existingFileExplorer = Array.from(this.windows.values()).find(w => w.type === 'file-explorer');
                if (!existingFileExplorer) {
                    this.openWindow('file-explorer');
                    output = 'Opening My Computer...';
                } else {
                    this.focusWindow(existingFileExplorer.element.dataset.windowId);
                    this.loadFileList();
                    this.updateAddressBar();
                    output = 'Focusing My Computer...';
                }
                break;
            case 'achievements':
                const existingAchievements = Array.from(this.windows.values()).find(w => w.type === 'achievements');
                if (!existingAchievements) {
                    this.openWindow('achievements');
                    output = 'Opening achievements window...';
                } else {
                    this.focusWindow(existingAchievements.element.dataset.windowId);
                    output = 'Focusing existing achievements window...';
                }
                break;
            case 'xss-demo':
                const existingXSS = Array.from(this.windows.values()).find(w => w.type === 'xss-demo');
                if (!existingXSS) {
                    this.openWindow('xss-demo');
                    output = 'Opening XSS demo...';
                } else {
                    this.focusWindow(existingXSS.element.dataset.windowId);
                    output = 'Focusing existing XSS demo...';
                }
                break;
            case 'burp':
                const existingBurp = Array.from(this.windows.values()).find(w => w.type === 'burp-suite');
                if (!existingBurp) {
                    this.openWindow('burp-suite');
                    output = 'Opening Burp Suite demo...';
                } else {
                    this.focusWindow(existingBurp.element.dataset.windowId);
                    output = 'Focusing existing Burp Suite demo...';
                }
                break;
            case 'log-analyzer':
                const existingLogAnalyzer = Array.from(this.windows.values()).find(w => w.type === 'log-analyzer');
                if (!existingLogAnalyzer) {
                    this.openWindow('log-analyzer');
                    output = 'Opening log analyzer...';
                } else {
                    this.focusWindow(existingLogAnalyzer.element.dataset.windowId);
                    output = 'Focusing existing log analyzer...';
                }
                break;
                
            case 'clear':
                outputElement.innerHTML = '';
                return;
                
            default:
                output = `Command not found: ${cmd}. Type 'help' for available commands.`;
        }
        
        // Add command and output to display
        const commandLine = document.createElement('div');
        commandLine.className = 'cmd-line';
        commandLine.innerHTML = `
            <span class="cmd-prompt">C:\\></span>
            <span class="cmd-text">${command}</span>
        `;
        outputElement.appendChild(commandLine);
        
        if (output) {
            const outputLines = output.split('\n');
            outputLines.forEach(line => {
                const outputLine = document.createElement('div');
                outputLine.className = 'cmd-line';
                outputLine.innerHTML = `<span class="cmd-text">${line}</span>`;
                outputElement.appendChild(outputLine);
            });
        }
        
        // Scroll to bottom
        outputElement.scrollTop = outputElement.scrollHeight;
    }

    matrixHack(outputElement) {
        const overlay = document.createElement('div');
        overlay.style.position = 'absolute';
        overlay.style.inset = '24px 8px 8px 8px';
        overlay.style.background = 'black';
        overlay.style.color = '#0f0';
        overlay.style.fontFamily = 'Courier New, monospace';
        overlay.style.padding = '8px';
        overlay.style.overflow = 'hidden';

        const parent = outputElement.closest('.window-body');
        parent.appendChild(overlay);

        let elapsed = 0;
        const interval = setInterval(() => {
            const line = Array.from({ length: 60 }, () => Math.random() > 0.5 ? '1' : '0').join('');
            const div = document.createElement('div');
            div.textContent = line;
            overlay.appendChild(div);
            overlay.scrollTop = overlay.scrollHeight;
            elapsed += 100;
            if (elapsed >= 5000) {
                clearInterval(interval);
                overlay.remove();
                // open random post
                const posts = this.searchData || [];
                if (posts.length > 0) {
                    const random = posts[Math.floor(Math.random() * posts.length)];
                    this.openPostWindow(random);
                }
            }
        }, 100);
    }
    
    addTaskButton(windowId, type) {
        const taskbarTasks = document.getElementById('taskbar-tasks');
        const taskButton = document.createElement('div');
        taskButton.className = 'task-button';
        taskButton.textContent = this.getWindowTitle(type);
        taskButton.dataset.windowId = windowId;
        
        taskButton.addEventListener('click', () => {
            this.focusWindow(windowId);
        });
        
        taskbarTasks.appendChild(taskButton);
    }
    
    removeTaskButton(windowId) {
        const taskButton = document.querySelector(`[data-window-id="${windowId}"]`);
        if (taskButton) {
            taskButton.remove();
        }
    }
    
    getWindowTitle(type) {
        const titles = {
            'file-explorer': 'File Explorer',
            'recycle-bin': 'Recycle Bin',
            'cmd': 'Command Prompt',
            'post': 'Post',
            'calendar': 'Calendar',
            'internet': 'Internet Explorer',
            'notepad': 'Notepad',
            'calculator': 'Calculator',
            'minesweeper': 'Minesweeper',
            'file-viewer': 'File Viewer'
        };
        return titles[type] || type;
    }
    
    focusWindow(windowId) {
        const windowData = this.windows.get(windowId);
        if (!windowData) return;
        
        // Update z-index
        windowData.zIndex = ++this.currentZIndex;
        windowData.element.style.zIndex = windowData.zIndex;
        
        // Update task button
        document.querySelectorAll('.task-button').forEach(btn => {
            btn.classList.remove('active');
        });
        const taskButton = document.querySelector(`[data-window-id="${windowId}"]`);
        if (taskButton) {
            taskButton.classList.add('active');
        }
        
        // Show window if minimized
        if (windowData.element.classList.contains('minimized')) {
            windowData.element.classList.remove('minimized');
        }
        
        // Ensure window is visible and focused
        windowData.element.style.display = 'block';
        windowData.element.focus();
        
        // Bring to front
        windowData.element.style.zIndex = this.currentZIndex;
    }
    
    minimizeWindow(windowId) {
        const windowData = this.windows.get(windowId);
        if (windowData) {
            windowData.element.classList.add('minimized');
            this.saveWindowsState();
        }
    }
    
    maximizeWindow(windowId) {
        const windowData = this.windows.get(windowId);
        if (windowData) {
            const isMaximized = windowData.element.classList.contains('maximized');
            windowData.element.classList.toggle('maximized', !isMaximized);
            this.saveWindowsState();
        }
    }
    
    closeWindow(windowId) {
        const windowData = this.windows.get(windowId);
        if (windowData) {
            windowData.element.remove();
            this.windows.delete(windowId);
            this.removeTaskButton(windowId);
            this.saveWindowsState();
        }
    }

    // Explorer Tab Management
    setupExplorerTabs(windowElement) {
        const tabsContainer = windowElement.querySelector('#explorer-tabs');
        const addTabBtn = windowElement.querySelector('#explorer-tab-add');
        
        // Add new tab functionality
        addTabBtn.addEventListener('click', () => {
            this.playSound('click');
            this.addExplorerTab(windowElement, 'New Tab', 'drives');
        });
        
        // Setup existing tab close buttons
        const closeButtons = windowElement.querySelectorAll('.explorer-tab-close');
        closeButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.playSound('click');
                const tabId = btn.dataset.tab;
                this.closeExplorerTab(windowElement, tabId);
            });
        });
        
        // Setup tab switching
        const tabs = windowElement.querySelectorAll('.explorer-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                this.playSound('click');
                const tabId = tab.dataset.tab;
                this.switchExplorerTab(windowElement, tabId);
            });
        });
    }

    addExplorerTab(windowElement, title, path) {
        const tabsContainer = windowElement.querySelector('#explorer-tabs');
        const addTabBtn = windowElement.querySelector('#explorer-tab-add');
        
        const tabId = `tab-${Date.now()}`;
        const tab = document.createElement('div');
        tab.className = 'explorer-tab';
        tab.dataset.tab = tabId;
        tab.innerHTML = `
            <span>${title}</span>
            <span class="explorer-tab-close" data-tab="${tabId}">×</span>
        `;
        
        // Insert before add button
        tabsContainer.insertBefore(tab, addTabBtn);
        
        // Setup tab events
        tab.addEventListener('click', () => {
            this.playSound('click');
            this.switchExplorerTab(windowElement, tabId);
        });
        
        tab.querySelector('.explorer-tab-close').addEventListener('click', (e) => {
            e.stopPropagation();
            this.playSound('click');
            this.closeExplorerTab(windowElement, tabId);
        });
        
        // Switch to new tab
        this.switchExplorerTab(windowElement, tabId);
        
        // Navigate to path
        if (path) {
            this.navigateToPath(path);
        }
    }

    closeExplorerTab(windowElement, tabId) {
        const tab = windowElement.querySelector(`[data-tab="${tabId}"]`);
        if (tab) {
            tab.remove();
            
            // If this was the active tab, switch to another
            if (tab.classList.contains('active')) {
                const remainingTabs = windowElement.querySelectorAll('.explorer-tab');
                if (remainingTabs.length > 0) {
                    this.switchExplorerTab(windowElement, remainingTabs[0].dataset.tab);
                }
            }
        }
    }

    switchExplorerTab(windowElement, tabId) {
        const tabs = windowElement.querySelectorAll('.explorer-tab');
        tabs.forEach(tab => tab.classList.remove('active'));
        
        const activeTab = windowElement.querySelector(`[data-tab="${tabId}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }
    }

    // Status Bar and Loading Methods
    updateStatusBar() {
        const statusFiles = document.querySelector('#status-files');
        const statusSelected = document.querySelector('#status-selected');
        const selectedFileName = document.querySelector('#selected-file-name');
        const selectedFileSize = document.querySelector('#selected-file-size');
        const statusSpace = document.querySelector('#status-space');
        
        if (!statusFiles) return;
        
        const fileList = document.querySelector('#file-list');
        const files = fileList ? fileList.querySelectorAll('.file-item') : [];
        const selectedFiles = fileList ? fileList.querySelectorAll('.file-item.selected') : [];
        
        // Update file count
        statusFiles.textContent = `${files.length} files`;
        
        // Update selected file info
        if (selectedFiles.length > 0) {
            const selectedFile = selectedFiles[0];
            const fileName = selectedFile.querySelector('.file-name').textContent;
            statusSelected.style.display = 'block';
            selectedFileName.textContent = fileName;
            selectedFileSize.textContent = '2.5 KB'; // Mock size
        } else {
            statusSelected.style.display = 'none';
        }
        
        // Update disk space based on current path
        const spaceInfo = {
            'drives': '512MB free of 1GB',
            'C:\\': '256MB free of 1GB',
            'D:\\': '512MB free of 1GB',
            'F:\\': '128MB free of 512MB',
            'X:\\': '64MB free of 256MB',
            'Network:\\': '32MB free of 128MB',
            'Malware:\\': '16MB free of 64MB',
            'BlueTeam:\\': '64MB free of 256MB'
        };
        
        if (statusSpace) {
            statusSpace.textContent = spaceInfo[this.currentPath] || '512MB free of 1GB';
        }
    }

    showLoadingAnimation(container, message) {
        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-box">
                <div class="loading-icon searching-animation">
                    <img src="/assets/icons/explorer_102.ico" alt="Searching" style="width:32px;height:32px;image-rendering:pixelated;"/>
                </div>
                <div class="loading-text">${message}</div>
            </div>
        `;
        
        container.appendChild(overlay);
        
        // Remove after 2 seconds
        setTimeout(() => {
            if (overlay.parentNode) {
                overlay.remove();
            }
        }, 2000);
    }

    showLoadingPopup(message) {
        const popup = document.createElement('div');
        popup.className = 'loading-popup';
        popup.textContent = message;
        
        document.body.appendChild(popup);
        
        // Remove after 1.5 seconds
        setTimeout(() => {
            if (popup.parentNode) {
                popup.remove();
            }
        }, 1500);
    }
}

// Initialize when DOM is loaded (single instance)
document.addEventListener('DOMContentLoaded', () => {
    if (!window.win95Blog) {
        window.win95Blog = new Windows95Blog();
    }
});

// Extensions
Windows95Blog.prototype.saveWindowsState = function() {
    try {
        const list = [];
        this.windows.forEach((w, id) => {
            const el = w.element;
            list.push({
                id,
                type: w.type,
                data: w.data && w.data.title ? { title: w.data.title } : null,
                left: el.style.left || '100px',
                top: el.style.top || '80px',
                minimized: el.classList.contains('minimized'),
                maximized: el.classList.contains('maximized')
            });
        });
        localStorage.setItem(this.windowStateKey, JSON.stringify(list));
    } catch {}
};

Windows95Blog.prototype.restoreWindowsState = function(afterData=false) {
    try {
        const raw = localStorage.getItem(this.windowStateKey);
        if (!raw) return;
        const list = JSON.parse(raw);
        list.forEach(item => {
            // Recreate window
            const id = this.openWindow(item.type, this.findPostDataIfNeeded(item, afterData));
            const w = this.windows.get(id);
            if (!w) return;
            const el = w.element;
            el.style.left = item.left;
            el.style.top = item.top;
            el.classList.toggle('minimized', !!item.minimized);
            el.classList.toggle('maximized', !!item.maximized);
        });
    } catch {}
};

Windows95Blog.prototype.findPostDataIfNeeded = function(item, afterData) {
    if (item.type !== 'post' || !item.data || !item.data.title) return null;
    if (!this.searchData || this.searchData.length === 0) return null;
    return this.searchData.find(p => p.title === item.data.title) || null;
};

Windows95Blog.prototype.unlockAchievement = function(title) {
    try {
        const key = 'win95_achievements';
        const list = JSON.parse(localStorage.getItem(key) || '[]');
        if (!list.includes(title)) {
            list.push(title);
            localStorage.setItem(key, JSON.stringify(list));
            const tpl = document.getElementById('achievement-template');
            if (!tpl) return;
            const el = tpl.content.cloneNode(true).firstElementChild;
            el.querySelector('.ach-title').textContent = title;
            el.style.position = 'fixed';
            el.style.right = '8px';
            el.style.bottom = '48px';
            el.style.background = '#c0c0c0';
            el.style.border = '2px outset #c0c0c0';
            el.style.padding = '6px 8px';
            el.style.fontSize = '12px';
            el.style.zIndex = '2000';
            document.body.appendChild(el);
            setTimeout(()=> el.remove(), 3000);
        }
    } catch {}
};
Windows95Blog.prototype.setupCalendar = function(windowElement) {
    let year = 1995;
    const title = windowElement.querySelector('#cal-title');
    const grid = windowElement.querySelector('#calendar-grid');
    const render = () => {
        title.textContent = year;
        grid.innerHTML = '';
        for (let m = 0; m < 12; m++) {
            const month = document.createElement('div');
            month.className = 'calendar-month';
            const name = new Date(year, m, 1).toLocaleString('en-US', { month: 'long' });
            month.innerHTML = `<h4>${name}</h4>`;
            const table = document.createElement('table');
            const header = document.createElement('tr');
            'Su Mo Tu We Th Fr Sa'.split(' ').forEach(d => {
                const th = document.createElement('th'); th.textContent = d; header.appendChild(th);
            });
            table.appendChild(header);
            let d = new Date(year, m, 1);
            let row = document.createElement('tr');
            for (let i = 0; i < d.getDay(); i++) { const td = document.createElement('td'); td.className = 'empty'; row.appendChild(td); }
            while (d.getMonth() === m) {
                const td = document.createElement('td'); td.textContent = d.getDate(); row.appendChild(td);
                if (d.getDay() === 6) { table.appendChild(row); row = document.createElement('tr'); }
                d.setDate(d.getDate() + 1);
            }
            if (row.children.length) table.appendChild(row);
            month.appendChild(table);
            grid.appendChild(month);
        }
    };
    windowElement.querySelector('#cal-prev').addEventListener('click', () => { year--; render(); });
    windowElement.querySelector('#cal-next').addEventListener('click', () => { year++; render(); });
    render();
};

Windows95Blog.prototype.setupInternet = function(windowElement) {
    const overlay = windowElement.querySelector('#dialup-overlay');
    const steps = windowElement.querySelectorAll('.dialup-steps .step');
    
    // Play dialup sound
    this.playSound('dialup');
    
    // Enhanced dial-up simulation
    let currentStep = 0;
    const stepInterval = setInterval(() => {
        if (currentStep < steps.length) {
            // Remove active from all steps
            steps.forEach(step => step.classList.remove('active'));
            // Activate current step
            if (steps[currentStep]) {
                steps[currentStep].classList.add('active');
            }
            currentStep++;
        } else {
            clearInterval(stepInterval);
        }
    }, 2000);
    
    setTimeout(async () => {
        overlay.style.display = 'none';
        // ensure searchData is loaded before rendering
        const ensure = async () => {
            let tries = 0;
            while ((!this.searchData || this.searchData.length === 0) && tries < 50) {
                await new Promise(r=>setTimeout(r,100));
                tries++;
            }
        };
        await ensure();
        renderBlogList();
    }, 8000); // Reduced to 8 seconds for better experience
    
    const list = windowElement.querySelector('#ie-list');
    const pages = {
        google: windowElement.querySelector('#ie-google'),
        blog: windowElement.querySelector('#ie-blog'),
        easter: windowElement.querySelector('#ie-easter')
    };
    const tabs = windowElement.querySelector('#ie-tabs');
    
    const setActive = (name)=>{
        list.style.display = 'none';
        Object.values(pages).forEach(p=> p.style.display='none');
        if (name === 'blog-list') list.style.display = 'block';
        else pages[name].style.display = 'block';
        tabs.querySelectorAll('.ie-tab').forEach(t=> t.classList.remove('active'));
        const active = tabs.querySelector(`.ie-tab[data-page="${name}"]`);
        active && active.classList.add('active');
    };
    
    const renderBlogList = () => {
        list.innerHTML = '';
        if (!this.searchData || this.searchData.length === 0) {
            list.innerHTML = '<div class="loading-animation">Loading posts...</div>';
            return;
        }
        (this.searchData || []).forEach(post => {
            const icon = `<img src="${(window.JEKYLL_BASE || '')}/assets/icons/mshtml_32528.ico" style=\"width:16px;height:16px;image-rendering:pixelated;\"/>`;
            const item = this.createFileItem(post.title, icon, 'post', post);
            list.appendChild(item);
        });
        setActive('blog-list');
    };
    
    const renderGoogle = () => {
        const q = windowElement.querySelector('#google-query');
        const btn = windowElement.querySelector('#google-search');
        const out = windowElement.querySelector('#google-results');
        btn.onclick = () => {
            const term = (q.value||'').toLowerCase();
            const results = (this.searchData||[]).filter(p=> (p.title+' '+p.excerpt+' '+p.content).toLowerCase().includes(term));
            out.innerHTML = results.map(r=> `<div class="search-result">- ${r.title}</div>`).join('');
        };
        setActive('google');
    };
    
    const renderBlogSearch = () => {
        const q = windowElement.querySelector('#blog-query');
        const out = windowElement.querySelector('#blog-results');
        q.oninput = () => {
            const term = (q.value||'').toLowerCase();
            const results = (this.searchData||[]).filter(p=> (p.title+' '+p.excerpt+' '+p.content).toLowerCase().includes(term));
            out.innerHTML = results.map(r=> `<div class="search-result">- ${r.title}</div>`).join('');
        };
        setActive('blog');
    };
    
    tabs.querySelectorAll('.ie-tab').forEach(tab=>{
        tab.addEventListener('click', ()=>{
            const page = tab.dataset.page;
            if (page === 'google') renderGoogle();
            else if (page === 'blog') renderBlogSearch();
            else if (page === 'easter') setActive('easter');
        });
    });
    
    // Setup toolbar buttons
    const backBtn = windowElement.querySelector('#ie-back');
    const forwardBtn = windowElement.querySelector('#ie-forward');
    const stopBtn = windowElement.querySelector('#ie-stop');
    const refreshBtn = windowElement.querySelector('#ie-refresh');
    const homeBtn = windowElement.querySelector('#ie-home');
    
    if (backBtn) backBtn.addEventListener('click', () => { this.playSound('click'); });
    if (forwardBtn) forwardBtn.addEventListener('click', () => { this.playSound('click'); });
    if (stopBtn) stopBtn.addEventListener('click', () => { this.playSound('click'); });
    if (refreshBtn) refreshBtn.addEventListener('click', () => { this.playSound('click'); renderBlogList(); });
    if (homeBtn) homeBtn.addEventListener('click', () => { this.playSound('click'); renderBlogList(); });
    
    // Fallback render in case data already loaded
    setTimeout(renderBlogList, 10200);
};

Windows95Blog.prototype.setupFileViewer = function(windowElement, data) {
    const pre = windowElement.querySelector('#file-viewer-content');
    pre.textContent = data && data.content ? data.content : '';
};

Windows95Blog.prototype.setupNotepad = function(windowElement) {
    const textarea = windowElement.querySelector('#notepad-textarea');
    const saveBtn = windowElement.querySelector('#notepad-save');
    const newBtn = windowElement.querySelector('#notepad-new');
    const deleteBtn = windowElement.querySelector('#notepad-delete');
    const cutBtn = windowElement.querySelector('#notepad-cut');
    const copyBtn = windowElement.querySelector('#notepad-copy');
    const pasteBtn = windowElement.querySelector('#notepad-paste');
    
    // Load saved content
    this.loadNotepadContent(textarea);
    
    // Auto-save on input
    textarea.addEventListener('input', () => {
        this.saveNotepadContent(textarea.value);
    });
    
    // Manual save button
    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            this.playSound('click');
            this.saveNotepadContent(textarea.value);
            this.showNotepadMessage('Document saved!');
        });
    }
    
    // New document button
    if (newBtn) {
        newBtn.addEventListener('click', () => {
            this.playSound('click');
            if (textarea.value.trim() && !confirm('Save current document?')) {
                return;
            }
            textarea.value = '';
            this.saveNotepadContent('');
            this.showNotepadMessage('New document created!');
        });
    }
    
    // Delete to recycle bin button
    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            this.playSound('click');
            if (textarea.value.trim() && confirm('Move current document to Recycle Bin?')) {
                const content = textarea.value;
                const timestamp = new Date().toLocaleString();
                this.addToRecycleBin(`draft_${timestamp}.txt`, content);
                textarea.value = '';
                this.saveNotepadContent('');
                this.showNotepadMessage('Document moved to Recycle Bin!');
            }
        });
    }
    
    // Cut button
    if (cutBtn) {
        cutBtn.addEventListener('click', () => {
            this.playSound('click');
            this.cutNotepadText(textarea);
        });
    }
    
    // Copy button
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            this.playSound('click');
            this.copyNotepadText(textarea);
        });
    }
    
    // Paste button
    if (pasteBtn) {
        pasteBtn.addEventListener('click', () => {
            this.playSound('click');
            this.pasteNotepadText(textarea);
        });
    }
    
    // Keyboard clipboard integration
    textarea.addEventListener('keydown', (e) => {
        const key = e.key.toLowerCase();
        if ((e.ctrlKey || e.metaKey) && key === 'v') {
            e.preventDefault();
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const before = textarea.value.slice(0, start);
            const after = textarea.value.slice(end);
            textarea.value = before + (this.clipboardText || '') + after;
            textarea.selectionStart = textarea.selectionEnd = start + (this.clipboardText||'').length;
            this.saveNotepadContent(textarea.value);
        }
        if ((e.ctrlKey || e.metaKey) && key === 'c') {
            this.clipboardText = textarea.value.substring(textarea.selectionStart, textarea.selectionEnd);
        }
    });

    // Setup menu functionality
    this.setupNotepadMenus(windowElement, textarea);
};

Windows95Blog.prototype.setupNotepadMenus = function(windowElement, textarea) {
    // File menu
    const newOption = windowElement.querySelector('#notepad-new-option');
    const openOption = windowElement.querySelector('#notepad-open-option');
    const saveOption = windowElement.querySelector('#notepad-save-option');
    const saveAsOption = windowElement.querySelector('#notepad-save-as-option');
    const exitOption = windowElement.querySelector('#notepad-exit-option');
    
    if (newOption) {
        newOption.addEventListener('click', () => {
            this.playSound('click');
            if (textarea.value.trim() && !confirm('Save current document?')) {
                return;
            }
            textarea.value = '';
            this.saveNotepadContent('');
            this.showNotepadMessage('New document created!');
        });
    }
    
    if (openOption) {
        openOption.addEventListener('click', () => {
            this.playSound('click');
            this.showNotepadMessage('Open functionality not implemented');
        });
    }
    
    if (saveOption) {
        saveOption.addEventListener('click', () => {
            this.playSound('click');
            this.saveNotepadContent(textarea.value);
            this.showNotepadMessage('Document saved!');
        });
    }
    
    if (saveAsOption) {
        saveAsOption.addEventListener('click', () => {
            this.playSound('click');
            this.showNotepadMessage('Save As functionality not implemented');
        });
    }
    
    if (exitOption) {
        exitOption.addEventListener('click', () => {
            this.playSound('click');
            const window = windowElement.closest('.window95');
            if (window) {
                this.closeWindow(window);
            }
        });
    }
    
    // Edit menu
    const undoOption = windowElement.querySelector('#notepad-undo-option');
    const cutOption = windowElement.querySelector('#notepad-cut-option');
    const copyOption = windowElement.querySelector('#notepad-copy-option');
    const pasteOption = windowElement.querySelector('#notepad-paste-option');
    const deleteOption = windowElement.querySelector('#notepad-delete-option');
    const selectAllOption = windowElement.querySelector('#notepad-select-all-option');
    
    if (undoOption) {
        undoOption.addEventListener('click', () => {
            this.playSound('click');
            this.showNotepadMessage('Undo functionality not implemented');
        });
    }
    
    if (cutOption) {
        cutOption.addEventListener('click', () => {
            this.playSound('click');
            this.cutNotepadText(textarea);
        });
    }
    
    if (copyOption) {
        copyOption.addEventListener('click', () => {
            this.playSound('click');
            this.copyNotepadText(textarea);
        });
    }
    
    if (pasteOption) {
        pasteOption.addEventListener('click', () => {
            this.playSound('click');
            this.pasteNotepadText(textarea);
        });
    }
    
    if (deleteOption) {
        deleteOption.addEventListener('click', () => {
            this.playSound('click');
            this.deleteNotepadText(textarea);
        });
    }
    
    if (selectAllOption) {
        selectAllOption.addEventListener('click', () => {
            this.playSound('click');
            textarea.select();
        });
    }
    
    // Search menu
    const findOption = windowElement.querySelector('#notepad-find-option');
    const findNextOption = windowElement.querySelector('#notepad-find-next-option');
    
    if (findOption) {
        findOption.addEventListener('click', () => {
            this.playSound('click');
            this.showNotepadMessage('Find functionality not implemented');
        });
    }
    
    if (findNextOption) {
        findNextOption.addEventListener('click', () => {
            this.playSound('click');
            this.showNotepadMessage('Find Next functionality not implemented');
        });
    }
};

Windows95Blog.prototype.cutNotepadText = function(textarea) {
    const selectedText = textarea.value.substring(textarea.selectionStart, textarea.selectionEnd);
    if (selectedText) {
        navigator.clipboard.writeText(selectedText).then(() => {
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            textarea.value = textarea.value.substring(0, start) + textarea.value.substring(end);
            textarea.selectionStart = textarea.selectionEnd = start;
            this.showNotepadMessage('Text cut to clipboard');
        });
    }
};

Windows95Blog.prototype.copyNotepadText = function(textarea) {
    const selectedText = textarea.value.substring(textarea.selectionStart, textarea.selectionEnd);
    if (selectedText) {
        navigator.clipboard.writeText(selectedText).then(() => {
            this.showNotepadMessage('Text copied to clipboard');
        });
    }
};

Windows95Blog.prototype.pasteNotepadText = function(textarea) {
    navigator.clipboard.readText().then(text => {
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        textarea.value = textarea.value.substring(0, start) + text + textarea.value.substring(end);
        textarea.selectionStart = textarea.selectionEnd = start + text.length;
        this.showNotepadMessage('Text pasted from clipboard');
    }).catch(() => {
        this.showNotepadMessage('Failed to paste text');
    });
};

Windows95Blog.prototype.deleteNotepadText = function(textarea) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    if (start !== end) {
        textarea.value = textarea.value.substring(0, start) + textarea.value.substring(end);
        textarea.selectionStart = textarea.selectionEnd = start;
        this.showNotepadMessage('Text deleted');
    }
};

Windows95Blog.prototype.loadNotepadContent = function(textarea) {
    try {
        const content = localStorage.getItem('win95_notepad_content') || '';
        textarea.value = content;
    } catch (error) {
        console.error('Failed to load notepad content:', error);
    }
};

Windows95Blog.prototype.saveNotepadContent = function(content) {
    try {
        localStorage.setItem('win95_notepad_content', content);
    } catch (error) {
        console.error('Failed to save notepad content:', error);
    }
};

Windows95Blog.prototype.showNotepadMessage = function(message) {
    // Create a temporary message display
    const messageDiv = document.createElement('div');
    messageDiv.textContent = message;
    messageDiv.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: #c0c0c0;
        border: 2px outset #c0c0c0;
        padding: 8px 16px;
        z-index: 2000;
        font-size: 12px;
    `;
    document.body.appendChild(messageDiv);
    setTimeout(() => messageDiv.remove(), 2000);
};

Windows95Blog.prototype.setupCalculator = function(windowElement) {
    const display = windowElement.querySelector('#calc-display');
    const buttons = windowElement.querySelector('#calc-buttons');
    const keys = ['7','8','9','/','4','5','6','*','1','2','3','-','0','.','=','+'];
    keys.forEach(k => {
        const b = document.createElement('button'); b.textContent = k; buttons.appendChild(b);
        b.addEventListener('click', () => {
            if (k === '=') {
                try { display.value = String(Function(`return (${display.value})`)()); } catch { display.value = 'Error'; }
            } else {
                display.value += k;
            }
        });
    });
};

Windows95Blog.prototype.setupMinesweeper = function(windowElement) {
    const grid = windowElement.querySelector('#mine-grid');
    const status = windowElement.querySelector('#mine-status');
    const size = 9, bombs = 10;
    let board = [], revealed = 0, gameOver = false;
    const dirs = [[-1,-1],[-1,0],[-1,1],[0,-1],[0,1],[1,-1],[1,0],[1,1]];
    const idx = (r,c)=> r*size+c;
    const inb = (r,c)=> r>=0&&r<size&&c>=0&&c<size;
    const reset = ()=>{
        board = Array(size*size).fill(0);
        grid.innerHTML=''; revealed=0; gameOver=false; status.textContent='Have fun!';
        let placed=0; while(placed<bombs){ const p=Math.floor(Math.random()*board.length); if(board[p]!==9){ board[p]=9; placed++; }}
        for(let r=0;r<size;r++) for(let c=0;c<size;c++) if(board[idx(r,c)]!==9){
            let n=0; dirs.forEach(([dr,dc])=>{ const rr=r+dr, cc=c+dc; if(inb(rr,cc)&&board[idx(rr,cc)]===9) n++; }); board[idx(r,c)]=n;
        }
        for(let i=0;i<board.length;i++){
            const cell=document.createElement('div'); cell.className='mine-cell'; cell.dataset.i=i; grid.appendChild(cell);
            cell.addEventListener('click', ()=>reveal(i));
        }
    };
    const reveal=(i)=>{
        const cell=grid.children[i]; if(!cell||cell.classList.contains('revealed')||gameOver) return;
        cell.classList.add('revealed');
        if(board[i]===9){ cell.textContent='*'; cell.classList.add('bomb'); status.textContent='Boom! Game over.'; gameOver=true; return; }
        revealed++; if(board[i]>0){ cell.textContent=board[i]; } else { // flood fill
            const q=[i]; const seen=new Set([i]);
            while(q.length){ const x=q.shift(); const r=Math.floor(x/size), c=x%size; dirs.forEach(([dr,dc])=>{ const rr=r+dr, cc=c+dc; const ii=idx(rr,cc); if(inb(rr,cc)&&!seen.has(ii)&&board[ii]!==9){ const el=grid.children[ii]; if(!el.classList.contains('revealed')){ el.classList.add('revealed'); revealed++; if(board[ii]>0){ el.textContent=board[ii]; } else { q.push(ii); } } seen.add(ii); }}); }
        }
        if(revealed===size*size-bombs){ status.textContent='You win!'; gameOver=true; }
    };
    windowElement.querySelector('#mine-reset').addEventListener('click', reset);
    reset();
};

Windows95Blog.prototype.enableDesktopIconDrag = function() {
    const container = document.getElementById('desktop');
    const icons = document.querySelectorAll('.desktop-icon');
    const gridSize = 80; // snap size
    const occupied = new Set();
    const keyFor = (l,t)=> `${Math.round(parseInt(l)/gridSize)}:${Math.round(parseInt(t)/gridSize)}`;
    icons.forEach(icon => {
        const key = `icon-pos-${icon.id}`;
        const saved = localStorage.getItem(key);
        if (saved) {
            try { const { left, top } = JSON.parse(saved); icon.style.position='absolute'; icon.style.left=left; icon.style.top=top; } catch {}
        }
        let dragging=false, sx=0, sy=0, sl=0, st=0;
        icon.addEventListener('mousedown', (e)=>{ dragging=true; sx=e.clientX; sy=e.clientY; const r=icon.getBoundingClientRect(); sl=r.left; st=r.top; icon.style.position='absolute'; e.preventDefault(); });
        document.addEventListener('mousemove', (e)=>{ if(!dragging) return; const dx=e.clientX-sx, dy=e.clientY-sy; icon.style.left=`${sl+dx}px`; icon.style.top=`${st+dy}px`; });
        document.addEventListener('mouseup', ()=>{ if(!dragging) return; dragging=false; 
            // snap to grid
            let l = parseInt(icon.style.left||'0'); let t = parseInt(icon.style.top||'0');
            l = Math.round(l / gridSize) * gridSize; t = Math.round(t / gridSize) * gridSize;
            // prevent overlap
            let attempt=0; let posKey = keyFor(l,t);
            while (occupied.has(posKey) && attempt < 100) { t += gridSize; posKey = keyFor(l,t); attempt++; }
            icon.style.left = `${l}px`; icon.style.top = `${t}px`;
            occupied.add(posKey);
            localStorage.setItem(key, JSON.stringify({ left: icon.style.left, top: icon.style.top }));
        });
    });
};

Windows95Blog.prototype.setupRecycle = function(windowElement) {
    const list = windowElement.querySelector('#recycle-file-list');
    const emptyMessage = windowElement.querySelector('#recycle-empty-message');
    
    // Load drafts from localStorage
    this.loadRecycleBinDrafts(list, emptyMessage);
    
    // Add some default system files
    const systemFiles = [
        { name: 'system.log', content: '[1995-08-24 09:00] Boot OK\n[1995-08-24 09:01] Dial-up ready\n[1995-08-24 09:02] User: guest' }
    ];
    
    systemFiles.forEach(f => {
        const item = document.createElement('div');
        item.className = 'file-item';
        item.innerHTML = `<div class="file-icon"><img src="/assets/icons/comdlg32_528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/></div><div class="file-name">${f.name}</div>`;
        item.addEventListener('dblclick', ()=>{
            this.playSound('click');
            this.openWindow('file-viewer', { title: f.name, content: f.content });
        });
        list.appendChild(item);
    });
};

Windows95Blog.prototype.loadRecycleBinDrafts = function(list, emptyMessage) {
    try {
        const drafts = JSON.parse(localStorage.getItem('win95_recycle_drafts') || '[]');
        
        if (drafts.length === 0) {
            if (emptyMessage) {
                emptyMessage.style.display = 'block';
            }
            return;
        }
        
        if (emptyMessage) {
            emptyMessage.style.display = 'none';
        }
        
        drafts.forEach(draft => {
            const item = document.createElement('div');
            item.className = 'file-item';
            item.innerHTML = `
                <div class="file-icon"><img src="/assets/icons/notepad_1.ico" style="width:16px;height:16px;image-rendering:pixelated;"/></div>
                <div class="file-name">${draft.name}</div>
                <div class="file-date">${new Date(draft.date).toLocaleDateString()}</div>
            `;
            item.addEventListener('dblclick', ()=>{
                this.playSound('click');
                this.openWindow('file-viewer', { title: draft.name, content: draft.content });
            });
            list.appendChild(item);
        });
    } catch (error) {
        console.error('Failed to load recycle bin drafts:', error);
    }
};

Windows95Blog.prototype.addToRecycleBin = function(name, content) {
    try {
        const drafts = JSON.parse(localStorage.getItem('win95_recycle_drafts') || '[]');
        drafts.push({
            name: name,
            content: content,
            date: new Date().toISOString()
        });
        localStorage.setItem('win95_recycle_drafts', JSON.stringify(drafts));
    } catch (error) {
        console.error('Failed to add to recycle bin:', error);
    }
};

// (Removed duplicate DOMContentLoaded initializer)

// Extensions
Windows95Blog.prototype.loadHiddenChallenges = function(fileList) {
    this.hiddenChallenges.forEach((challenge, key) => {
        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
        const challengeItem = this.createFileItem(challenge.name, icon, 'hidden-challenge', challenge);
        fileList.appendChild(challengeItem);
    });
};

Windows95Blog.prototype.loadNetworkServers = function(fileList) {
    this.networkServers.forEach((server, key) => {
        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
        const serverItem = this.createFileItem(server.name, icon, 'network-server', server);
        fileList.appendChild(serverItem);
    });
};

Windows95Blog.prototype.loadMalwareMuseum = function(fileList) {
    this.malwareMuseum.forEach((malware, key) => {
        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
        const malwareItem = this.createFileItem(malware.name, icon, 'malware', malware);
        fileList.appendChild(malwareItem);
    });
};

Windows95Blog.prototype.loadBlueTeamTools = function(fileList) {
    this.blueTeamTools.forEach((tool, key) => {
        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
        const toolItem = this.createFileItem(tool.name, icon, 'blue-team-tool', tool);
        fileList.appendChild(toolItem);
    });
};

Windows95Blog.prototype.isHiddenDriveUnlocked = function() {
    return localStorage.getItem('win95_hidden_drive_unlocked') === 'true';
};

Windows95Blog.prototype.unlockHiddenDrive = function() {
    localStorage.setItem('win95_hidden_drive_unlocked', 'true');
    this.unlockAchievement('Hidden Drive Discoverer');
    this.showMessage('Hidden drive X:\\ unlocked! Use cd X:\\ to access hidden challenges.');
    this.loadFileList(); // Refresh to show the hidden drive
};

Windows95Blog.prototype.loadAchievements = function() {
    try {
        const saved = localStorage.getItem('win95_achievements');
        this.achievements = saved ? JSON.parse(saved) : [];
    } catch (error) {
        this.achievements = [];
    }
};

Windows95Blog.prototype.showAchievementNotification = function(title) {
    const notification = document.createElement('div');
    notification.className = 'achievement-notification';
    notification.innerHTML = `
        <div class="achievement-content">
            <div class="achievement-icon">🏆</div>
            <div class="achievement-text">
                <div class="achievement-title">Achievement Unlocked!</div>
                <div class="achievement-name">${title}</div>
            </div>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
};

Windows95Blog.prototype.showMessage = function(message) {
    const messageBox = document.createElement('div');
    messageBox.className = 'message-box';
    messageBox.innerHTML = `
        <div class="message-content">
            <div class="message-text">${message}</div>
            <button class="message-ok">OK</button>
        </div>
    `;
    
    document.body.appendChild(messageBox);
    
    messageBox.querySelector('.message-ok').addEventListener('click', () => {
        messageBox.remove();
    });
};

// New Cybersecurity Window Setup Methods
Windows95Blog.prototype.setupHiddenChallengesWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    if (data) {
        content.innerHTML = `
            <div class="challenge-window">
                <h3>${data.name}</h3>
                <p>${data.description}</p>
                <div class="challenge-hint">
                    <strong>Hint:</strong> ${data.hint}
                </div>
                <div class="challenge-input">
                    <input type="text" id="challenge-solution" placeholder="Enter solution...">
                    <button id="challenge-submit">Submit</button>
                </div>
                <div id="challenge-result"></div>
            </div>
        `;
        
        const submitBtn = content.querySelector('#challenge-submit');
        const solutionInput = content.querySelector('#challenge-solution');
        const resultDiv = content.querySelector('#challenge-result');
        
        submitBtn.addEventListener('click', () => {
            const solution = solutionInput.value.trim();
            if (solution === data.solution) {
                data.solved = true;
                resultDiv.innerHTML = '<div class="success">✅ Challenge solved! Achievement unlocked!</div>';
                this.unlockAchievement(`${data.name} Master`);
            } else {
                resultDiv.innerHTML = '<div class="error">❌ Incorrect solution. Try again!</div>';
            }
        });
    }
};

Windows95Blog.prototype.setupNetworkNeighborhoodWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    if (data) {
        content.innerHTML = `
            <div class="server-window">
                <h3>${data.name}</h3>
                <p>${data.description}</p>
                <div class="server-config">
                    <h4>Server Configuration:</h4>
                    <ul>
                        <li>Port: ${data.config.port}</li>
                        <li>Anonymous Access: ${data.config.anonymous_access ? 'Yes' : 'No'}</li>
                        <li>Root Access: ${data.config.root_access ? 'Yes' : 'No'}</li>
                        ${data.config.version ? `<li>Version: ${data.config.version}</li>` : ''}
                        ${data.config.directory_listing ? '<li>Directory Listing: Enabled</li>' : ''}
                    </ul>
                </div>
                <div class="server-logs">
                    <h4>Recent Logs:</h4>
                    <div class="log-entries">
                        ${data.config.logs.map(log => `<div class="log-entry">${log}</div>`).join('')}
                    </div>
                </div>
            </div>
        `;
    }
};

Windows95Blog.prototype.setupMalwareMuseumWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    if (data) {
        content.innerHTML = `
            <div class="malware-window">
                <h3>${data.name}</h3>
                <div class="malware-info">
                    <p><strong>Type:</strong> ${data.type}</p>
                    <p><strong>Year:</strong> ${data.year}</p>
                    <p><strong>Impact:</strong> ${data.impact}</p>
                </div>
                <div class="malware-description">
                    <h4>Description:</h4>
                    <p>${data.description}</p>
                </div>
                <div class="malware-payload">
                    <h4>Payload:</h4>
                    <p>${data.payload}</p>
                </div>
                <div class="malware-screenshots">
                    <h4>Screenshots:</h4>
                    <ul>
                        ${data.screenshots.map(screenshot => `<li>${screenshot}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;
        
        // Add visual effect
        if (data.effect) {
            content.classList.add(data.effect);
            setTimeout(() => content.classList.remove(data.effect), 2000);
        }
    }
};

Windows95Blog.prototype.setupBlueTeamWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    if (data) {
        content.innerHTML = `
            <div class="blue-team-window">
                <h3>${data.name}</h3>
                <p>${data.description}</p>
                <div class="tool-logs">
                    <h4>Recent Activity:</h4>
                    <div class="log-entries">
                        ${(data.logs || data.alerts || data.evidence).map(log => `<div class="log-entry">${log}</div>`).join('')}
                    </div>
                </div>
            </div>
        `;
    }
};

Windows95Blog.prototype.setupXSSDemoWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    content.innerHTML = `
        <div class="xss-demo-window">
            <h3>XSS Demo - Mini Browser</h3>
            <div class="demo-browser">
                <div class="browser-url-bar">
                    <span>URL:</span>
                    <input type="text" id="xss-url" value="http://vulnerable-site.com/search" readonly>
                </div>
                <div class="browser-content">
                    <div class="search-form">
                        <input type="text" id="xss-input" placeholder="Enter search term...">
                        <button id="xss-search">Search</button>
                    </div>
                    <div id="xss-result" class="search-result">
                        <p>Enter a search term above to see results.</p>
                    </div>
                </div>
            </div>
            <div class="demo-instructions">
                <h4>Try these XSS payloads:</h4>
                <ul>
                    <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                    <li><code>&lt;svg onload=alert('XSS')&gt;</code></li>
                </ul>
            </div>
        </div>
    `;
    
    const searchBtn = content.querySelector('#xss-search');
    const input = content.querySelector('#xss-input');
    const result = content.querySelector('#xss-result');
    
    searchBtn.addEventListener('click', () => {
        const payload = input.value;
        result.innerHTML = `
            <h4>Search Results for: "${payload}"</h4>
            <div class="vulnerable-output">${payload}</div>
            <p><em>Note: This demonstrates a vulnerable site that doesn't sanitize input.</em></p>
        `;
        
        if (payload.toLowerCase().includes('<script>') || payload.toLowerCase().includes('alert(')) {
            this.unlockAchievement('XSS Hunter');
        }
    });
};

Windows95Blog.prototype.setupBurpSuiteWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    content.innerHTML = `
        <div class="burp-suite-window">
            <h3>Burp Suite - Intercepted Request</h3>
            <div class="burp-tabs">
                <div class="burp-tab active" data-tab="request">Request</div>
                <div class="burp-tab" data-tab="response">Response</div>
            </div>
            <div class="burp-content">
                <div id="burp-request" class="burp-panel active">
                    <pre>GET /login.php HTTP/1.1
Host: vulnerable-site.com
User-Agent: Mozilla/5.0
Accept: text/html
Cookie: session=abc123

username=admin&password=test123</pre>
                </div>
                <div id="burp-response" class="burp-panel">
                    <pre>HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=def456

&lt;html&gt;
&lt;body&gt;
Login failed. Invalid credentials.
&lt;/body&gt;
&lt;/html&gt;</pre>
                </div>
            </div>
            <div class="burp-actions">
                <button id="burp-forward">Forward</button>
                <button id="burp-drop">Drop</button>
                <button id="burp-modify">Modify</button>
            </div>
        </div>
    `;
    
    // Tab switching
    const tabs = content.querySelectorAll('.burp-tab');
    const panels = content.querySelectorAll('.burp-panel');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            
            tab.classList.add('active');
            const panel = content.querySelector(`#burp-${tab.dataset.tab}`);
            if (panel) panel.classList.add('active');
        });
    });
};

Windows95Blog.prototype.setupLogAnalyzerWindow = function(windowElement, data) {
    const content = windowElement.querySelector('.window-body');
    content.innerHTML = `
        <div class="log-analyzer-window">
            <h3>Log Analyzer</h3>
            <div class="log-input">
                <textarea id="log-input" placeholder="Paste log entries here...">2025-01-03 10:15:23 - User login: admin
2025-01-03 10:16:45 - Database query: SELECT * FROM users WHERE id=1
2025-01-03 10:17:12 - Error: SQL syntax error
2025-01-03 10:18:34 - User login: guest
2025-01-03 10:19:56 - Database query: SELECT * FROM users WHERE id=' OR '1'='1
2025-01-03 10:20:15 - Error: Multiple rows returned</textarea>
            </div>
            <div class="log-actions">
                <button id="analyze-logs">Analyze Logs</button>
                <button id="clear-logs">Clear</button>
            </div>
            <div id="log-analysis" class="log-analysis"></div>
        </div>
    `;
    
    const analyzeBtn = content.querySelector('#analyze-logs');
    const clearBtn = content.querySelector('#clear-logs');
    const analysisDiv = content.querySelector('#log-analysis');
    
    analyzeBtn.addEventListener('click', () => {
        const logs = content.querySelector('#log-input').value;
        const analysis = this.analyzeLogs(logs);
        analysisDiv.innerHTML = analysis;
        
        if (logs.includes("' OR '1'='1")) {
            this.unlockAchievement('Forensics Analyst');
        }
    });
    
    clearBtn.addEventListener('click', () => {
        content.querySelector('#log-input').value = '';
        analysisDiv.innerHTML = '';
    });
};

Windows95Blog.prototype.setupAchievementsWindow = function(windowElement) {
    const content = windowElement.querySelector('.window-body');
    
    // Load quiz results from localStorage
    const quizResults = JSON.parse(localStorage.getItem('win95_quiz_results') || '{}');
    
    content.innerHTML = `
        <div class="achievements-window">
            <h3>Achievements & Progress</h3>
            
            <div class="achievements-section">
                <h4>🏆 Unlocked Achievements</h4>
                <div class="achievements-list">
                    ${this.achievements.length > 0 ? 
                        this.achievements.map(achievement => `<div class="achievement-item">🏆 ${achievement}</div>`).join('') :
                        '<p>No achievements unlocked yet. Keep exploring and taking quizzes!</p>'
                    }
                </div>
            </div>
            
            <div class="quiz-results-section">
                <h4>📊 Quiz Results</h4>
                ${Object.keys(quizResults).length > 0 ? 
                    Object.entries(quizResults).map(([quizName, result]) => `
                        <div class="quiz-result-item">
                            <div class="quiz-result-header">
                                <strong>${quizName}</strong>
                                <span class="quiz-result-score">${result.score}/${result.total} (${result.percentage}%)</span>
                            </div>
                            <div class="quiz-result-details">
                                <small>Attempts: ${result.attempts} | Date: ${new Date(result.date).toLocaleDateString()}</small>
                            </div>
                        </div>
                    `).join('') :
                    '<p>No quiz results yet. Try taking some quizzes from the Start Menu!</p>'
                }
            </div>
            
            <div class="achievements-footer">
                <p><em>Complete quizzes to unlock achievements and track your progress!</em></p>
            </div>
        </div>
    `;
};

Windows95Blog.prototype.analyzeLogs = function(logs) {
    const lines = logs.split('\n');
    let analysis = '<h4>Log Analysis Results:</h4><ul>';
    
    lines.forEach(line => {
        if (line.includes("' OR '1'='1")) {
            analysis += '<li class="alert">🚨 SQL Injection attempt detected!</li>';
        }
        if (line.includes('Error: SQL syntax error')) {
            analysis += '<li class="warning">⚠️ Database error detected</li>';
        }
        if (line.includes('Multiple rows returned')) {
            analysis += '<li class="info">ℹ️ Unusual query result</li>';
        }
    });
    
    analysis += '</ul>';
    return analysis;
};
Windows95Blog.prototype.loadNewsData = async function() {
    try {
        const response = await fetch('/assets/data/news.json');
        this.newsData = await response.json();
    } catch (error) {
        console.error('Failed to load news data:', error);
        this.newsData = [
            {
                title: "New Zero-Day Vulnerability Discovered",
                date: "2025-01-03",
                content: "Security researchers have discovered a new zero-day vulnerability affecting multiple web applications. The vulnerability allows for remote code execution and affects versions 1.0 through 2.3 of the affected software.",
                category: "Vulnerability"
            },
            {
                title: "Major Data Breach at Tech Company",
                date: "2025-01-02",
                content: "A major technology company has reported a data breach affecting over 1 million users. The breach was discovered during routine security monitoring and has been contained.",
                category: "Breach"
            }
        ];
    }
};

Windows95Blog.prototype.loadVirusData = function() {
    this.virusData = [
        {
            name: "ILOVEYOU.vbs",
            type: "VBScript Worm",
            year: "2000",
            description: "The ILOVEYOU virus was one of the most destructive computer viruses ever created. It spread via email with the subject 'ILOVEYOU' and infected millions of computers worldwide.",
            content: "This virus overwrote files and sent itself to everyone in the victim's address book. It caused an estimated $10 billion in damages globally.",
            effect: "red-flash"
        },
        {
            name: "Melissa.doc",
            type: "Macro Virus",
            year: "1999",
            description: "Melissa was one of the first major macro viruses to spread via email. It infected Word documents and spread through email attachments.",
            content: "The virus was named after a stripper in Florida. It caused widespread email server overloads and led to the arrest of its creator.",
            effect: "blue-flash"
        },
        {
            name: "WannaCry.exe",
            type: "Ransomware",
            year: "2017",
            description: "WannaCry was a ransomware attack that affected hundreds of thousands of computers in over 150 countries. It exploited a Windows vulnerability.",
            content: "The attack encrypted files and demanded Bitcoin payments for decryption. It particularly affected healthcare systems and government agencies.",
            effect: "green-flash"
        }
    ];
};

Windows95Blog.prototype.loadNewsFiles = function(fileList) {
    if (!this.newsData) return;
    
    this.newsData.forEach(news => {
        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
        const newsItem = this.createFileItem(news.title, icon, 'news', news);
        fileList.appendChild(newsItem);
    });
};

Windows95Blog.prototype.loadVirusFiles = function(fileList) {
    if (!this.virusData) return;
    
    this.virusData.forEach(virus => {
        const icon = '<img src="/assets/icons/mshtml_32528.ico" style="width:16px;height:16px;image-rendering:pixelated;"/>';
        const virusItem = this.createFileItem(virus.name, icon, 'virus', virus);
        fileList.appendChild(virusItem);
    });
};

Windows95Blog.prototype.setupQuiz = function(windowElement) {
    // Legacy quiz - keeping for backward compatibility
    const questions = [
        {
            question: "What does XSS stand for?",
            options: ["Cross-Site Scripting", "Cross-Site Security", "Cross-Site Session", "Cross-Site Service"],
            correct: 0
        },
        {
            question: "Which of the following is NOT a type of SQL injection?",
            options: ["Union-based", "Boolean-based", "Time-based", "Cookie-based"],
            correct: 3
        },
        {
            question: "What is the primary purpose of a CSRF token?",
            options: ["Encrypt data", "Prevent cross-site request forgery", "Authenticate users", "Store session data"],
            correct: 1
        },
        {
            question: "Which HTTP method is typically used for CSRF attacks?",
            options: ["GET", "POST", "PUT", "DELETE"],
            correct: 1
        },
        {
            question: "What is the most effective way to prevent SQL injection?",
            options: ["Input validation", "Prepared statements", "Output encoding", "HTTPS"],
            correct: 1
        }
    ];

    let currentQuestion = 0;
    let score = 0;
    let selectedAnswer = -1;

    const questionDiv = windowElement.querySelector('#quiz-question');
    const optionsDiv = windowElement.querySelector('#quiz-options');
    const scoreSpan = windowElement.querySelector('#quiz-score');
    const totalSpan = windowElement.querySelector('#quiz-total');
    const nextBtn = windowElement.querySelector('#quiz-next');
    const restartBtn = windowElement.querySelector('#quiz-restart');
    const resultsDiv = windowElement.querySelector('#quiz-results');
    const finalScoreDiv = windowElement.querySelector('#quiz-final-score');
    const playAgainBtn = windowElement.querySelector('#quiz-play-again');

    totalSpan.textContent = questions.length;

    const showQuestion = () => {
        const q = questions[currentQuestion];
        questionDiv.innerHTML = `<h4>Question ${currentQuestion + 1}: ${q.question}</h4>`;
        
        optionsDiv.innerHTML = '';
        q.options.forEach((option, index) => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'quiz-option';
            optionDiv.innerHTML = `
                <input type="radio" name="answer" value="${index}" id="option${index}">
                <label for="option${index}">${option}</label>
            `;
            optionDiv.addEventListener('click', () => {
                selectedAnswer = index;
                optionsDiv.querySelectorAll('input').forEach(input => input.checked = false);
                optionDiv.querySelector('input').checked = true;
            });
            optionsDiv.appendChild(optionDiv);
        });
        
        selectedAnswer = -1;
    };

    const showResults = () => {
        const percentage = Math.round((score / questions.length) * 100);
        finalScoreDiv.innerHTML = `
            <p>You scored ${score} out of ${questions.length} (${percentage}%)</p>
            <p>${percentage >= 80 ? 'Excellent! 🏆' : percentage >= 60 ? 'Good job! 👍' : 'Keep studying! 📚'}</p>
        `;
        resultsDiv.style.display = 'block';
        windowElement.querySelector('.quiz-content').style.display = 'none';
        
        if (percentage >= 80) {
            this.unlockAchievement('Security Expert');
        }
    };

    nextBtn.addEventListener('click', () => {
        if (selectedAnswer === -1) return;
        
        if (selectedAnswer === questions[currentQuestion].correct) {
            score++;
        }
        
        scoreSpan.textContent = score;
        currentQuestion++;
        
        if (currentQuestion >= questions.length) {
            showResults();
        } else {
            showQuestion();
        }
    });

    restartBtn.addEventListener('click', () => {
        currentQuestion = 0;
        score = 0;
        selectedAnswer = -1;
        scoreSpan.textContent = '0';
        resultsDiv.style.display = 'none';
        windowElement.querySelector('.quiz-content').style.display = 'block';
        showQuestion();
    });

    playAgainBtn.addEventListener('click', () => {
        restartBtn.click();
    });

    showQuestion();
};

Windows95Blog.prototype.setupQuizWindow = function(windowElement, quizType) {
    // Load quiz data from JSON
    fetch('/assets/data/quizzes.json')
        .then(response => response.json())
        .then(quizzes => {
            const quiz = quizzes[quizType];
            if (!quiz) {
                windowElement.querySelector('.window-body').innerHTML = '<p>Quiz not found!</p>';
                return;
            }
            
            // Set window title
            windowElement.querySelector('.title-bar-text').textContent = quiz.title;
            
            // Setup quiz content
            this.setupQuizContent(windowElement, quiz);
        })
        .catch(error => {
            console.error('Error loading quiz:', error);
            windowElement.querySelector('.window-body').innerHTML = '<p>Error loading quiz!</p>';
        });
};

Windows95Blog.prototype.setupQuizContent = function(windowElement, quiz) {
    const windowBody = windowElement.querySelector('.window-body');
    
    // Create quiz HTML structure
    windowBody.innerHTML = `
        <div class="quiz95">
            <div class="quiz-header">
                <h3>${quiz.title}</h3>
                <p class="quiz-description">${quiz.description}</p>
                <div class="quiz-score">Score: <span id="quiz-score">0</span>/<span id="quiz-total">${quiz.questions.length}</span></div>
            </div>
            <div class="quiz-content">
                <div id="quiz-question" class="quiz-question"></div>
                <div id="quiz-options" class="quiz-options"></div>
                <div class="quiz-controls">
                    <button class="toolbar-button" id="quiz-next">Next</button>
                    <button class="toolbar-button" id="quiz-restart">Restart</button>
                </div>
            </div>
            <div id="quiz-results" class="quiz-results" style="display: none;">
                <h3>Quiz Complete!</h3>
                <div id="quiz-final-score"></div>
                <div id="quiz-explanations"></div>
                <button class="toolbar-button" id="quiz-play-again">Play Again</button>
            </div>
        </div>
    `;
    
    let currentQuestion = 0;
    let score = 0;
    let selectedAnswer = -1;
    let userAnswers = [];
    
    const questionDiv = windowElement.querySelector('#quiz-question');
    const optionsDiv = windowElement.querySelector('#quiz-options');
    const scoreSpan = windowElement.querySelector('#quiz-score');
    const nextBtn = windowElement.querySelector('#quiz-next');
    const restartBtn = windowElement.querySelector('#quiz-restart');
    const resultsDiv = windowElement.querySelector('#quiz-results');
    const finalScoreDiv = windowElement.querySelector('#quiz-final-score');
    const explanationsDiv = windowElement.querySelector('#quiz-explanations');
    const playAgainBtn = windowElement.querySelector('#quiz-play-again');
    
    const showQuestion = () => {
        const q = quiz.questions[currentQuestion];
        questionDiv.innerHTML = `<h4>Question ${currentQuestion + 1}: ${q.question}</h4>`;
        
        optionsDiv.innerHTML = '';
        q.options.forEach((option, index) => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'quiz-option';
            optionDiv.innerHTML = `
                <input type="radio" name="answer" value="${index}" id="option${index}">
                <label for="option${index}">${option}</label>
            `;
            optionDiv.addEventListener('click', () => {
                selectedAnswer = index;
                optionsDiv.querySelectorAll('input').forEach(input => input.checked = false);
                optionDiv.querySelector('input').checked = true;
            });
            optionsDiv.appendChild(optionDiv);
        });
        
        selectedAnswer = -1;
    };
    
    const showResults = () => {
        const percentage = Math.round((score / quiz.questions.length) * 100);
        finalScoreDiv.innerHTML = `
            <p>You scored ${score} out of ${quiz.questions.length} (${percentage}%)</p>
            <p>${percentage >= 80 ? 'Excellent! 🏆' : percentage >= 60 ? 'Good job! 👍' : 'Keep studying! 📚'}</p>
        `;
        
        // Show explanations
        explanationsDiv.innerHTML = '<h4>Review:</h4>';
        quiz.questions.forEach((q, index) => {
            const userAnswer = userAnswers[index];
            const isCorrect = userAnswer === q.correct;
            const explanation = q.explanation || 'No explanation available.';
            
            explanationsDiv.innerHTML += `
                <div class="quiz-explanation ${isCorrect ? 'correct' : 'incorrect'}">
                    <p><strong>Question ${index + 1}:</strong> ${q.question}</p>
                    <p><strong>Your answer:</strong> ${q.options[userAnswer] || 'Not answered'}</p>
                    <p><strong>Correct answer:</strong> ${q.options[q.correct]}</p>
                    <p><strong>Explanation:</strong> ${explanation}</p>
                </div>
            `;
        });
        
        resultsDiv.style.display = 'block';
        windowElement.querySelector('.quiz-content').style.display = 'none';
        
        // Save results to localStorage
        this.saveQuizResults(quiz.title, score, quiz.questions.length, percentage);
        
        // Unlock achievements
        if (percentage >= 80) {
            this.unlockAchievement(`${quiz.title} Master`);
        } else if (percentage >= 60) {
            this.unlockAchievement(`${quiz.title} Graduate`);
        }
    };
    
    nextBtn.addEventListener('click', () => {
        if (selectedAnswer === -1) return;
        
        userAnswers[currentQuestion] = selectedAnswer;
        
        if (selectedAnswer === quiz.questions[currentQuestion].correct) {
            score++;
        }
        
        scoreSpan.textContent = score;
        currentQuestion++;
        
        if (currentQuestion >= quiz.questions.length) {
            showResults();
        } else {
            showQuestion();
        }
    });
    
    restartBtn.addEventListener('click', () => {
        currentQuestion = 0;
        score = 0;
        selectedAnswer = -1;
        userAnswers = [];
        scoreSpan.textContent = '0';
        resultsDiv.style.display = 'none';
        windowElement.querySelector('.quiz-content').style.display = 'block';
        showQuestion();
    });
    
    playAgainBtn.addEventListener('click', () => {
        restartBtn.click();
    });
    
    showQuestion();
};

Windows95Blog.prototype.saveQuizResults = function(quizTitle, score, total, percentage) {
    const results = JSON.parse(localStorage.getItem('win95_quiz_results') || '{}');
    results[quizTitle] = {
        score: score,
        total: total,
        percentage: percentage,
        date: new Date().toISOString(),
        attempts: (results[quizTitle]?.attempts || 0) + 1
    };
    localStorage.setItem('win95_quiz_results', JSON.stringify(results));
};

Windows95Blog.prototype.setupPrintQueue = function(windowElement) {
    const queueList = windowElement.querySelector('#print-queue-list');
    const clearBtn = windowElement.querySelector('#print-clear');

    const updateQueue = () => {
        queueList.innerHTML = '';
        this.printQueue.forEach((job, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${job.title}</td>
                <td>${job.status}</td>
                <td>${job.progress}</td>
            `;
            queueList.appendChild(row);
        });
    };

    clearBtn.addEventListener('click', () => {
        this.printQueue = [];
        updateQueue();
    });

    updateQueue();
};

Windows95Blog.prototype.setupNews = function(windowElement, data) {
    const content = windowElement.querySelector('#news-content');
    if (data) {
        content.innerHTML = `
            <h2>${data.title}</h2>
            <p class="news-date">${data.date}</p>
            <p class="news-category">Category: ${data.category}</p>
            <div class="news-body">${data.content}</div>
        `;
    }
};

Windows95Blog.prototype.setupVirus = function(windowElement, data) {
    const content = windowElement.querySelector('#virus-content');
    if (data) {
        content.innerHTML = `
            <h2>${data.name}</h2>
            <p class="virus-type">Type: ${data.type}</p>
            <p class="virus-year">Year: ${data.year}</p>
            <div class="virus-description">
                <h3>Description</h3>
                <p>${data.description}</p>
            </div>
            <div class="virus-details">
                <h3>Details</h3>
                <p>${data.content}</p>
            </div>
        `;
        
        // Add visual effect
        if (data.effect) {
            content.classList.add(data.effect);
            setTimeout(() => content.classList.remove(data.effect), 2000);
        }
    }
};

Windows95Blog.prototype.printPost = function(postData) {
    // Add to print queue
    const printJob = {
        id: Date.now(),
        title: postData.title,
        status: 'Spooling',
        progress: '0%'
    };
    
    this.printQueue.push(printJob);
    
    // Show print queue window
    this.openWindow('print-queue');
    
    // Simulate printing process
    setTimeout(() => {
        printJob.status = 'Printing page 1 of 1';
        printJob.progress = '50%';
        this.updatePrintQueue();
    }, 1000);
    
    setTimeout(() => {
        printJob.status = 'Completed';
        printJob.progress = '100%';
        this.updatePrintQueue();
        this.downloadPostAsPDF(postData);
    }, 3000);
    
    // Play print sound (if available)
    this.playPrintSound();
};

Windows95Blog.prototype.updatePrintQueue = function() {
    const queueWindow = document.querySelector('[data-window-id] .print-queue95');
    if (queueWindow) {
        const queueList = queueWindow.querySelector('#print-queue-list');
        if (queueList) {
            queueList.innerHTML = '';
            this.printQueue.forEach(job => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${job.title}</td>
                    <td>${job.status}</td>
                    <td>${job.progress}</td>
                `;
                queueList.appendChild(row);
            });
        }
    }
};

Windows95Blog.prototype.downloadPostAsPDF = function(postData) {
    // Create a simple text-based "PDF" download
    const content = `
WINDOWS 95 BLOG - ${postData.title}
Generated: ${new Date().toLocaleDateString()}

${postData.content.replace(/<[^>]*>/g, '')}

---
This document was generated by the Windows 95 Blog System
    `.trim();
    
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${postData.title.replace(/[^a-zA-Z0-9]/g, '_')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

Windows95Blog.prototype.playPrintSound = function() {
    this.playSound('print');
};

// Sound System
Windows95Blog.prototype.playSound = function(soundType) {
    if (!this.soundEnabled) return;
    
    try {
        const audio = new Audio(`/assets/sounds/${soundType}.wav`);
        audio.volume = this.volume;
        audio.play().catch(() => {
            // Fallback: generate synthetic sounds
            this.generateSyntheticSound(soundType);
        });
    } catch (error) {
        // Fallback: generate synthetic sounds
        this.generateSyntheticSound(soundType);
    }
};

Windows95Blog.prototype.generateSyntheticSound = function(soundType) {
    try {
        const context = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = context.createOscillator();
        const gainNode = context.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(context.destination);
        
        // Configure sound based on type
        switch (soundType) {
            case 'start':
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                gainNode.gain.value = this.volume * 0.3;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.3);
                break;
            case 'dialup':
                // Simulate dial-up modem sounds
                const dialupSequence = [
                    { freq: 1200, duration: 0.1 },
                    { freq: 2200, duration: 0.1 },
                    { freq: 1200, duration: 0.1 },
                    { freq: 2200, duration: 0.1 },
                    { freq: 1200, duration: 0.1 },
                    { freq: 2200, duration: 0.1 },
                    { freq: 1200, duration: 0.1 },
                    { freq: 2200, duration: 0.1 },
                    { freq: 1200, duration: 0.1 },
                    { freq: 2200, duration: 0.1 }
                ];
                
                let dialupTime = context.currentTime;
                dialupSequence.forEach((tone, index) => {
                    const osc = context.createOscillator();
                    const gain = context.createGain();
                    osc.connect(gain);
                    gain.connect(context.destination);
                    osc.frequency.value = tone.freq;
                    osc.type = 'sine';
                    gain.gain.value = this.volume * 0.2;
                    osc.start(dialupTime);
                    osc.stop(dialupTime + tone.duration);
                    dialupTime += tone.duration;
                });
                break;
            case 'error':
                oscillator.frequency.value = 200;
                oscillator.type = 'square';
                gainNode.gain.value = this.volume * 0.2;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.5);
                break;
            case 'minimize':
                oscillator.frequency.value = 600;
                oscillator.type = 'triangle';
                gainNode.gain.value = this.volume * 0.15;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.1);
                break;
            case 'maximize':
                oscillator.frequency.value = 1000;
                oscillator.type = 'triangle';
                gainNode.gain.value = this.volume * 0.15;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.1);
                break;
            case 'shutdown':
                oscillator.frequency.value = 400;
                oscillator.type = 'sawtooth';
                gainNode.gain.value = this.volume * 0.2;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.8);
                break;
            case 'print':
                oscillator.frequency.value = 800;
                oscillator.type = 'square';
                gainNode.gain.value = this.volume * 0.1;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.1);
                break;
            case 'click':
                oscillator.frequency.value = 1000;
                oscillator.type = 'sine';
                gainNode.gain.value = this.volume * 0.1;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.05);
                break;
            case 'open':
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                gainNode.gain.value = this.volume * 0.15;
                oscillator.start();
                oscillator.stop(context.currentTime + 0.1);
                break;
        }
    } catch (error) {
        console.log('Audio not available');
    }
};

// Advanced Window Management Methods
Windows95Blog.prototype.setupWindowResizing = function(windowElement, windowId) {
    const handles = windowElement.querySelectorAll('.window-resize-handle');
    let isResizing = false;
    let resizeHandle = null;
    let startX, startY, startWidth, startHeight, startLeft, startTop;
    
    handles.forEach(handle => {
        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            isResizing = true;
            resizeHandle = handle.className.split(' ')[1]; // Get the direction
            startX = e.clientX;
            startY = e.clientY;
            
            const rect = windowElement.getBoundingClientRect();
            startWidth = rect.width;
            startHeight = rect.height;
            startLeft = rect.left;
            startTop = rect.top;
            
            windowElement.classList.add('resizing');
            this.focusWindow(windowId);
        });
    });
    
    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        
        const deltaX = e.clientX - startX;
        const deltaY = e.clientY - startY;
        
        let newWidth = startWidth;
        let newHeight = startHeight;
        let newLeft = startLeft;
        let newTop = startTop;
        
        // Calculate new dimensions based on resize handle
        switch (resizeHandle) {
            case 'n':
                newHeight = Math.max(200, startHeight - deltaY);
                newTop = startTop + (startHeight - newHeight);
                break;
            case 's':
                newHeight = Math.max(200, startHeight + deltaY);
                break;
            case 'e':
                newWidth = Math.max(300, startWidth + deltaX);
                break;
            case 'w':
                newWidth = Math.max(300, startWidth - deltaX);
                newLeft = startLeft + (startWidth - newWidth);
                break;
            case 'nw':
                newWidth = Math.max(300, startWidth - deltaX);
                newHeight = Math.max(200, startHeight - deltaY);
                newLeft = startLeft + (startWidth - newWidth);
                newTop = startTop + (startHeight - newHeight);
                break;
            case 'ne':
                newWidth = Math.max(300, startWidth + deltaX);
                newHeight = Math.max(200, startHeight - deltaY);
                newTop = startTop + (startHeight - newHeight);
                break;
            case 'sw':
                newWidth = Math.max(300, startWidth - deltaX);
                newHeight = Math.max(200, startHeight + deltaY);
                newLeft = startLeft + (startWidth - newWidth);
                break;
            case 'se':
                newWidth = Math.max(300, startWidth + deltaX);
                newHeight = Math.max(200, startHeight + deltaY);
                break;
        }
        
        windowElement.style.width = `${newWidth}px`;
        windowElement.style.height = `${newHeight}px`;
        windowElement.style.left = `${newLeft}px`;
        windowElement.style.top = `${newTop}px`;
    });
    
    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            resizeHandle = null;
            windowElement.classList.remove('resizing');
            this.saveWindowsState();
        }
    });
};

Windows95Blog.prototype.setupWindowSnapping = function(windowElement, windowId) {
    let isDragging = false;
    let startX, startY, startLeft, startTop;
    
    const titleBar = windowElement.querySelector('.title-bar');
    
    titleBar.addEventListener('mousedown', (e) => {
        if (e.target === titleBar || e.target === titleBar.querySelector('.title-bar-text')) {
            isDragging = true;
            startX = e.clientX;
            startY = e.clientY;
            const rect = windowElement.getBoundingClientRect();
            startLeft = rect.left;
            startTop = rect.top;
        }
    });
    
    document.addEventListener('mouseup', (e) => {
        if (!isDragging) return;
        
        isDragging = false;
        const deltaX = e.clientX - startX;
        const deltaY = e.clientY - startY;
        
        // Only snap if there was significant movement
        if (Math.abs(deltaX) < 10 && Math.abs(deltaY) < 10) return;
        
        const windowRect = windowElement.getBoundingClientRect();
        const screenWidth = window.innerWidth;
        const screenHeight = window.innerHeight - 40; // Account for taskbar
        
        // Remove existing snap classes
        windowElement.classList.remove('snapped-left', 'snapped-right', 'snapped-top');
        
        // Check for snapping
        if (windowRect.top <= 0 && windowRect.height >= screenHeight * 0.8) {
            // Snap to top (maximize)
            windowElement.classList.add('snapped-top');
            this.playSound('maximize');
        } else if (windowRect.left <= 0 && windowRect.width >= screenWidth * 0.4) {
            // Snap to left
            windowElement.classList.add('snapped-left');
            this.playSound('click');
        } else if (windowRect.right >= screenWidth && windowRect.width >= screenWidth * 0.4) {
            // Snap to right
            windowElement.classList.add('snapped-right');
            this.playSound('click');
        }
        
        this.saveWindowsState();
    });
};

