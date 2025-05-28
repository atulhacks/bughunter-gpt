document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const scanningStatus = document.getElementById('scanningStatus');
    const resultsContainer = document.getElementById('resultsContainer');
    const historyContainer = document.getElementById('historyContainer');
    
    // Settings Panel Elements
    const settingsButton = document.getElementById('settingsButton');
    const settingsPanel = document.getElementById('settingsPanel');
    const settingsOverlay = document.getElementById('settingsOverlay');
    const closeSettings = document.getElementById('closeSettings');
    const saveSettings = document.getElementById('saveSettings');
    
    // History Elements
    const historyButton = document.getElementById('historyButton');
    const closeHistory = document.getElementById('closeHistory');
    const historyList = document.getElementById('historyList');
    const clearHistory = document.getElementById('clearHistory');
    
    // Theme Toggle
    const themeToggle = document.getElementById('themeToggle');
    
    // Load saved settings from localStorage
    let userSettings = JSON.parse(localStorage.getItem('bughunterSettings') || '{}');
    
    // Configuration with default values that can be overridden by user settings
    const CONFIG = {
        // GitHub API configuration
        github: {
            apiUrl: 'https://api.github.com',
            resultsPerPage: parseInt(userSettings.resultsPerPage || 10),
            maxPages: parseInt(userSettings.maxPages || 3),
            token: userSettings.githubToken || '',
            categories: [
                { keyword: 'vulnerability', label: 'Vulnerability', color: 'yellow' },
                { keyword: 'exploit', label: 'Exploit', color: 'red' },
                { keyword: 'cve', label: 'CVE', color: 'orange' },
                { keyword: 'security-issue', label: 'Security Issue', color: 'blue' },
                { keyword: 'security-vulnerability', label: 'Security Vulnerability', color: 'red' },
                { keyword: 'poc', label: 'Proof of Concept', color: 'purple' }
            ]
        },
        // Scanner configuration
        scanner: {
            timeout: parseInt(userSettings.timeout || 10000),
            maxDepth: 3,
            maxPages: parseInt(userSettings.maxPagesToScan || 20),
            contentAnalysis: userSettings.contentAnalysis !== false,
            headerAnalysis: userSettings.headerAnalysis !== false,
            userAgent: 'BugHunter-GPT-Scanner/2.0',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml',
                'Accept-Language': 'en-US,en;q=0.9'
            }
        }
    };

    // Common vulnerability patterns
    const VULNERABILITY_PATTERNS = [
        { pattern: 'sql-injection', name: 'SQL Injection', severity: 'high', regex: /('|%27)(\s)*(or|and|union|select|from|where|having|group|order|insert|update|delete)(\s)/i },
        { pattern: 'xss', name: 'Cross-Site Scripting (XSS)', severity: 'high', regex: /<script>|javascript:|on(load|click|mouseover|error)=|alert\(|eval\(|document\.cookie/i },
        { pattern: 'rce', name: 'Remote Code Execution', severity: 'critical', regex: /\b(exec|system|passthru|shell_exec|eval|popen|proc_open)\b/i },
        { pattern: 'csrf', name: 'Cross-Site Request Forgery', severity: 'medium', regex: /<form.*action=|method=("|')post("|')/i },
        { pattern: 'file-inclusion', name: 'File Inclusion', severity: 'high', regex: /\b(include|require|include_once|require_once)\b.*\$_(GET|POST|REQUEST|COOKIE)/i },
        { pattern: 'open-redirect', name: 'Open Redirect', severity: 'medium', regex: /\b(url|redirect|redir|location|redirect_to|return_url|next|goto)=/i },
        { pattern: 'ssrf', name: 'Server-Side Request Forgery', severity: 'high', regex: /\b(curl_exec|file_get_contents|fsockopen|pfsockopen)\b.*\$_(GET|POST|REQUEST|COOKIE)/i },
        { pattern: 'idor', name: 'Insecure Direct Object Reference', severity: 'high', regex: /\/(user|account|profile|order|item)\/\d+/i },
        { pattern: 'info-disclosure', name: 'Information Disclosure', severity: 'medium', regex: /phpinfo\(\)|server-status|server-info|\.git\/|\.svn\/|\.env|\.config/i },
        { pattern: 'broken-auth', name: 'Broken Authentication', severity: 'high', regex: /\/login|\/signin|\/register|\/reset-password|\/forgot-password/i }
    ];

    // App settings
    const appSettings = {
        saveHistory: userSettings.saveHistory !== false,
        theme: userSettings.theme || 'dark'
    };
    
    // Scan history storage
    let scanHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
    
    // Apply saved theme
    if (appSettings.theme === 'light') {
        document.body.classList.add('light-mode');
        themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    }
    
    // Initialize settings form with saved values
    function initializeSettingsForm() {
        // GitHub API settings
        document.getElementById('githubToken').value = CONFIG.github.token || '';
        document.getElementById('resultsPerPage').value = CONFIG.github.resultsPerPage;
        document.getElementById('maxPages').value = CONFIG.github.maxPages;
        
        // Scanner settings
        document.getElementById('timeout').value = CONFIG.scanner.timeout;
        document.getElementById('maxPagesToScan').value = CONFIG.scanner.maxPages;
        document.getElementById('contentAnalysis').checked = CONFIG.scanner.contentAnalysis;
        document.getElementById('headerAnalysis').checked = CONFIG.scanner.headerAnalysis;
        
        // Advanced settings
        document.getElementById('saveHistory').checked = appSettings.saveHistory;
    }

    /**
     * Fetch GitHub exploits related to the target domain
     * Enhanced with pagination and rate limit handling
     */
    async function fetchGitHubExploits(url) {
        try {
            const domain = new URL(url).hostname;
            const exploits = [];
            const processedRepos = new Set(); // To avoid duplicates

            for (const category of CONFIG.github.categories) {
                const searchQuery = `${domain} ${category.keyword}`;
                
                // Fetch with pagination
                for (let page = 1; page <= CONFIG.github.maxPages; page++) {
                    const headers = {
                        'Accept': 'application/vnd.github.v3+json'
                    };
                    
                    // Add token if available
                    if (CONFIG.github.token) {
                        headers['Authorization'] = `token ${CONFIG.github.token}`;
                    }
                    
                    const apiUrl = `${CONFIG.github.apiUrl}/search/repositories?q=${encodeURIComponent(searchQuery)}&sort=stars&order=desc&per_page=${CONFIG.github.resultsPerPage}&page=${page}`;
                    const response = await fetch(apiUrl, { headers });
                    
                    // Handle rate limiting
                    if (response.status === 403) {
                        const rateLimitReset = response.headers.get('X-RateLimit-Reset');
                        const waitTime = rateLimitReset ? (new Date(rateLimitReset * 1000) - new Date()) : 60000;
                        console.warn(`GitHub API rate limit exceeded. Try again in ${Math.ceil(waitTime/1000)} seconds.`);
                        break;
                    }
                    
                    if (!response.ok) {
                        throw new Error(`GitHub API error: ${response.status}`);
                    }

                    const data = await response.json();
                    
                    if (!data.items || data.items.length === 0) {
                        break; // No more results
                    }

                    // Process items and avoid duplicates
                    for (const item of data.items) {
                        if (!processedRepos.has(item.id)) {
                            processedRepos.add(item.id);
                            
                            // Enhanced metadata
                            exploits.push({
                                name: item.name,
                                description: item.description,
                                url: item.html_url,
                                apiUrl: item.url,
                                stars: item.stargazers_count,
                                category: category.label,
                                color: category.color,
                                lastUpdated: new Date(item.updated_at).toLocaleDateString(),
                                language: item.language,
                                owner: item.owner.login,
                                forks: item.forks_count,
                                openIssues: item.open_issues_count,
                                score: item.score,
                                relevanceScore: calculateRelevanceScore(item, domain, category.keyword)
                            });
                        }
                    }
                }
            }

            // Sort by relevance score
            return exploits.sort((a, b) => b.relevanceScore - a.relevanceScore);
        } catch (error) {
            console.error('Error fetching GitHub exploits:', error);
            throw error;
        }
    }

    /**
     * Calculate a relevance score for the repository based on various factors
     */
    function calculateRelevanceScore(repo, domain, keyword) {
        let score = 0;
        
        // Base score from GitHub
        score += repo.score * 0.5;
        
        // Stars contribute to relevance
        score += Math.min(repo.stargazers_count, 1000) / 100;
        
        // Recent updates are more relevant
        const daysSinceUpdate = (new Date() - new Date(repo.updated_at)) / (1000 * 60 * 60 * 24);
        score += Math.max(0, 100 - daysSinceUpdate) / 10;
        
        // Exact domain match in name or description
        if (repo.name.includes(domain) || (repo.description && repo.description.includes(domain))) {
            score += 20;
        }
        
        // Keyword in name is highly relevant
        if (repo.name.includes(keyword)) {
            score += 15;
        }
        
        return score;
    }

    /**
     * Check if a website is available and get basic information
     */
    async function checkWebsiteAvailability(url) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), CONFIG.scanner.timeout);
            
            const response = await fetch(url, {
                method: 'HEAD',
                headers: CONFIG.scanner.headers,
                signal: controller.signal,
                mode: 'no-cors' // This helps with CORS issues but limits response info
            });
            
            clearTimeout(timeoutId);
            
            return {
                available: true,
                status: response.status,
                headers: Object.fromEntries(response.headers.entries())
            };
        } catch (error) {
            console.error(`Error checking website availability: ${error.message}`);
            return {
                available: false,
                error: error.message
            };
        }
    }

    /**
     * Discover common endpoints and pages on the target website
     */
    async function discoverEndpoints(baseUrl) {
        const commonPaths = [
            '', // Root path
            'login', 'admin', 'wp-admin', 'administrator', 'dashboard',
            'api', 'api/v1', 'api/v2', 'graphql',
            'wp-content', 'wp-includes', 'wp-json',
            'robots.txt', 'sitemap.xml', '.git', '.env',
            'backup', 'backups', 'db', 'database',
            'phpinfo.php', 'info.php', 'server-status',
            'register', 'signup', 'user', 'users', 'account',
            'upload', 'uploads', 'file', 'files',
            'config', 'settings', 'setup', 'install'
        ];
        
        const pages = [];
        const baseUrlObj = new URL(baseUrl);
        
        for (const path of commonPaths) {
            try {
                const targetUrl = new URL(path, baseUrlObj).href;
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), CONFIG.scanner.timeout);
                
                const response = await fetch(targetUrl, {
                    method: 'HEAD',
                    headers: CONFIG.scanner.headers,
                    signal: controller.signal,
                    mode: 'no-cors'
                });
                
                clearTimeout(timeoutId);
                
                // Add to discovered pages
                pages.push({
                    url: targetUrl,
                    status: 'Scanned',
                    statusCode: response.status,
                    findings: []
                });
                
                // Add basic findings based on status code
                if (response.status === 200) {
                    pages[pages.length - 1].findings.push({
                        type: 'info',
                        message: `Accessible (${response.status})`
                    });
                    
                    // Check for sensitive endpoints
                    if (['admin', 'wp-admin', 'administrator', 'dashboard', 'phpinfo.php', 'info.php', 'server-status', '.git', '.env'].includes(path)) {
                        pages[pages.length - 1].findings.push({
                            type: 'warning',
                            message: `Potentially sensitive endpoint accessible`
                        });
                    }
                } else if (response.status === 403) {
                    pages[pages.length - 1].findings.push({
                        type: 'error',
                        message: `Access forbidden (${response.status})`
                    });
                } else if (response.status === 401) {
                    pages[pages.length - 1].findings.push({
                        type: 'warning',
                        message: `Authentication required (${response.status})`
                    });
                } else if (response.status >= 500) {
                    pages[pages.length - 1].findings.push({
                        type: 'error',
                        message: `Server error (${response.status})`
                    });
                }
                
                // Extract server information if available
                const server = response.headers.get('server');
                if (server) {
                    pages[pages.length - 1].findings.push({
                        type: 'info',
                        message: `Server: ${server}`
                    });
                }
                
                // Check for security headers
                const securityHeaders = [
                    { header: 'Content-Security-Policy', type: 'warning', message: 'Content-Security-Policy header missing' },
                    { header: 'X-XSS-Protection', type: 'warning', message: 'X-XSS-Protection header missing' },
                    { header: 'X-Content-Type-Options', type: 'warning', message: 'X-Content-Type-Options header missing' },
                    { header: 'X-Frame-Options', type: 'warning', message: 'X-Frame-Options header missing' },
                    { header: 'Strict-Transport-Security', type: 'warning', message: 'HSTS header missing' }
                ];
                
                for (const header of securityHeaders) {
                    if (!response.headers.get(header.header)) {
                        pages[pages.length - 1].findings.push({
                            type: header.type,
                            message: header.message
                        });
                    }
                }
                
            } catch (error) {
                // Add to discovered pages with error status
                pages.push({
                    url: new URL(path, baseUrlObj).href,
                    status: 'Error',
                    findings: [{
                        type: 'info',
                        message: `Error: ${error.message}`
                    }]
                });
            }
            
            // Respect rate limiting
            await new Promise(resolve => setTimeout(resolve, 200));
        }
        
        return pages;
    }

    /**
     * Perform basic content analysis for common vulnerabilities
     */
    async function analyzeContent(url) {
        try {
            const response = await fetch(url, {
                headers: CONFIG.scanner.headers,
                timeout: CONFIG.scanner.timeout
            });
            
            if (!response.ok) {
                return [];
            }
            
            const text = await response.text();
            const findings = [];
            
            // Check for common vulnerability patterns
            for (const pattern of VULNERABILITY_PATTERNS) {
                if (pattern.regex && pattern.regex.test(text)) {
                    findings.push({
                        type: pattern.severity === 'critical' ? 'critical' : 
                              pattern.severity === 'high' ? 'error' : 
                              pattern.severity === 'medium' ? 'warning' : 'info',
                        message: `Potential ${pattern.name} vulnerability detected`
                    });
                }
            }
            
            // Check for exposed email addresses
            const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
            const emails = text.match(emailRegex);
            if (emails && emails.length > 0) {
                findings.push({
                    type: 'warning',
                    message: `${emails.length} email address(es) exposed`
                });
            }
            
            // Check for comments that might contain sensitive information
            const commentRegex = /<!--[\s\S]*?-->/g;
            const comments = text.match(commentRegex);
            if (comments && comments.length > 0) {
                const sensitiveCommentRegex = /password|api key|token|secret|username|user name|pwd|pass/i;
                const sensitiveComments = comments.filter(comment => sensitiveCommentRegex.test(comment));
                
                if (sensitiveComments.length > 0) {
                    findings.push({
                        type: 'warning',
                        message: `${sensitiveComments.length} comment(s) may contain sensitive information`
                    });
                }
            }
            
            return findings;
        } catch (error) {
            console.error(`Error analyzing content: ${error.message}`);
            return [{
                type: 'info',
                message: `Content analysis error: ${error.message}`
            }];
        }
    }

    /**
     * Main scanning function that coordinates the entire process
     */
    async function scanWebsite(url) {
        try {
            // Step 1: Check website availability
            const availabilityCheck = await checkWebsiteAvailability(url);
            
            if (!availabilityCheck.available) {
                throw new Error(`Website is not available: ${availabilityCheck.error}`);
            }
            
            // Step 2: Discover endpoints
            const pages = await discoverEndpoints(url);
            
            // Step 3: Analyze content for each discovered page
            for (let i = 0; i < Math.min(pages.length, CONFIG.scanner.maxPages); i++) {
                if (pages[i].status === 'Scanned' && pages[i].statusCode === 200) {
                    const contentFindings = await analyzeContent(pages[i].url);
                    pages[i].findings.push(...contentFindings);
                }
            }
            
            // Step 4: Fetch potential exploits from GitHub
            const exploits = await fetchGitHubExploits(url);
            
            // Step 5: Summarize findings
            const summary = {
                totalPages: pages.length,
                vulnerabilities: {
                    critical: pages.reduce((count, page) => 
                        count + page.findings.filter(f => f.type === 'critical').length, 0),
                    high: pages.reduce((count, page) => 
                        count + page.findings.filter(f => f.type === 'error').length, 0),
                    medium: pages.reduce((count, page) => 
                        count + page.findings.filter(f => f.type === 'warning').length, 0),
                    low: pages.reduce((count, page) => 
                        count + page.findings.filter(f => f.type === 'info').length, 0)
                },
                scanTime: new Date().toISOString(),
                targetUrl: url
            };
            
            // Step 6: Save to scan history
            const scanResult = { pages, exploits, summary };
            saveToHistory(url, scanResult);
            
            return scanResult;
        } catch (error) {
            console.error('Error scanning website:', error);
            throw error;
        }
    }

    /**
     * Save scan results to local storage history
     */
    function saveToHistory(url, results) {
        if (!appSettings.saveHistory) return;
        
        // Limit history to 10 items
        if (scanHistory.length >= 10) {
            scanHistory.pop(); // Remove oldest
        }
        
        // Add new scan to beginning
        scanHistory.unshift({
            url,
            timestamp: new Date().toISOString(),
            summary: results.summary
        });
        
        // Save to localStorage
        localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
    }
    
    /**
     * Display scan history in the history panel
     */
    function displayHistory() {
        if (scanHistory.length === 0) {
            historyList.innerHTML = '<p class="text-gray-400">No scan history available.</p>';
            return;
        }
        
        const historyHTML = scanHistory.map((scan, index) => `
            <div class="bg-gray-800/30 rounded-lg p-4">
                <div class="flex justify-between items-center mb-2">
                    <h4 class="font-medium text-white">${new URL(scan.url).hostname}</h4>
                    <span class="text-xs text-gray-400">${new Date(scan.timestamp).toLocaleString()}</span>
                </div>
                <div class="grid grid-cols-4 gap-2 mb-3">
                    <div class="text-center">
                        <div class="text-sm font-bold text-white">${scan.summary.totalPages}</div>
                        <div class="text-xs text-gray-400">Pages</div>
                    </div>
                    <div class="text-center">
                        <div class="text-sm font-bold text-red-300">${scan.summary.vulnerabilities.critical}</div>
                        <div class="text-xs text-gray-400">Critical</div>
                    </div>
                    <div class="text-center">
                        <div class="text-sm font-bold text-orange-300">${scan.summary.vulnerabilities.high}</div>
                        <div class="text-xs text-gray-400">High</div>
                    </div>
                    <div class="text-center">
                        <div class="text-sm font-bold text-yellow-300">${scan.summary.vulnerabilities.medium}</div>
                        <div class="text-xs text-gray-400">Medium</div>
                    </div>
                </div>
                <div class="flex justify-end">
                    <button class="text-blue-400 hover:text-blue-300 text-sm px-3 py-1 rescan-button" data-url="${scan.url}">
                        <i class="fas fa-sync-alt mr-1"></i> Rescan
                    </button>
                </div>
            </div>
        `).join('');
        
        historyList.innerHTML = historyHTML;
        
        // Add event listeners to rescan buttons
        document.querySelectorAll('.rescan-button').forEach(button => {
            button.addEventListener('click', () => {
                urlInput.value = button.getAttribute('data-url');
                historyContainer.classList.add('hidden');
                scanButton.click();
            });
        });
    }
    
    /**
     * Save user settings to localStorage
     */
    function saveUserSettings() {
        const settings = {
            // GitHub API settings
            githubToken: document.getElementById('githubToken').value,
            resultsPerPage: document.getElementById('resultsPerPage').value,
            maxPages: document.getElementById('maxPages').value,
            
            // Scanner settings
            timeout: document.getElementById('timeout').value,
            maxPagesToScan: document.getElementById('maxPagesToScan').value,
            contentAnalysis: document.getElementById('contentAnalysis').checked,
            headerAnalysis: document.getElementById('headerAnalysis').checked,
            
            // Advanced settings
            saveHistory: document.getElementById('saveHistory').checked,
            
            // Theme
            theme: appSettings.theme
        };
        
        localStorage.setItem('bughunterSettings', JSON.stringify(settings));
        
        // Update current config
        CONFIG.github.token = settings.githubToken;
        CONFIG.github.resultsPerPage = parseInt(settings.resultsPerPage);
        CONFIG.github.maxPages = parseInt(settings.maxPages);
        CONFIG.scanner.timeout = parseInt(settings.timeout);
        CONFIG.scanner.maxPages = parseInt(settings.maxPagesToScan);
        CONFIG.scanner.contentAnalysis = settings.contentAnalysis;
        CONFIG.scanner.headerAnalysis = settings.headerAnalysis;
        appSettings.saveHistory = settings.saveHistory;
        
        // Show success message
        const successMessage = document.createElement('div');
        successMessage.className = 'bg-green-500/20 text-green-300 p-2 rounded-md text-sm text-center mt-2';
        successMessage.textContent = 'Settings saved successfully!';
        document.getElementById('saveSettings').insertAdjacentElement('afterend', successMessage);
        
        setTimeout(() => {
            successMessage.remove();
        }, 3000);
    }

    /**
     * Get CSS class for severity level
     */
    function getSeverityClass(severity) {
        const classes = {
            critical: 'bg-red-500/20 text-red-300',
            high: 'bg-orange-500/20 text-orange-300',
            medium: 'bg-yellow-500/20 text-yellow-300',
            low: 'bg-blue-500/20 text-blue-300',
            info: 'bg-gray-500/20 text-gray-300',
            error: 'bg-orange-500/20 text-orange-300',
            warning: 'bg-yellow-500/20 text-yellow-300'
        };
        return classes[severity] || classes.info;
    }

    /**
     * Display scan results in the UI
     */
    function displayResults(results) {
        // Display summary
        const summaryHTML = `
            <div class="mb-6 grid grid-cols-4 gap-4">
                <div class="bg-gray-800/50 p-4 rounded-lg">
                    <div class="text-2xl font-bold text-white">${results.summary.totalPages}</div>
                    <div class="text-sm text-gray-400">Pages Scanned</div>
                </div>
                <div class="bg-red-900/50 p-4 rounded-lg">
                    <div class="text-2xl font-bold text-red-300">${results.summary.vulnerabilities.critical}</div>
                    <div class="text-sm text-gray-400">Critical Issues</div>
                </div>
                <div class="bg-orange-900/50 p-4 rounded-lg">
                    <div class="text-2xl font-bold text-orange-300">${results.summary.vulnerabilities.high}</div>
                    <div class="text-sm text-gray-400">High Severity</div>
                </div>
                <div class="bg-yellow-900/50 p-4 rounded-lg">
                    <div class="text-2xl font-bold text-yellow-300">${results.summary.vulnerabilities.medium}</div>
                    <div class="text-sm text-gray-400">Medium Severity</div>
                </div>
            </div>
        `;

        // Display scan timestamp
        const scanTimeHTML = `
            <div class="mb-6 text-sm text-gray-400 flex justify-between items-center">
                <div>
                    <span class="font-medium">Target:</span> ${results.summary.targetUrl}
                </div>
                <div>
                    <span class="font-medium">Scan Time:</span> ${new Date(results.summary.scanTime).toLocaleString()}
                </div>
            </div>
        `;

        // Display exploits with enhanced information
        const exploitsHTML = results.exploits.length > 0 
            ? results.exploits.map(exploit => `
                <div class="bg-gray-800/50 p-4 rounded-lg mb-4">
                    <div class="flex items-center justify-between mb-2">
                        <h4 class="font-medium text-white flex items-center gap-2">
                            ${exploit.name}
                            ${exploit.language ? `<span class="text-xs ${getSeverityClass('info')} px-2 py-0.5 rounded">${exploit.language}</span>` : ''}
                        </h4>
                        <span class="text-xs ${getSeverityClass(exploit.category.toLowerCase())} px-2 py-1 rounded">
                            ${exploit.category}
                        </span>
                    </div>
                    <p class="text-sm text-gray-400 mb-3">${exploit.description || 'No description available'}</p>
                    <div class="flex items-center justify-between text-sm">
                        <div class="flex items-center gap-4">
                            <a href="${exploit.url}" target="_blank" class="text-blue-400 hover:text-blue-300 flex items-center gap-1">
                                <i class="fas fa-external-link-alt"></i>
                                View on GitHub
                            </a>
                            <span class="text-gray-400">
                                by ${exploit.owner}
                            </span>
                        </div>
                        <div class="flex items-center gap-3">
                            <span class="text-gray-400">
                                Updated: ${exploit.lastUpdated}
                            </span>
                            <span class="text-yellow-400">
                                <i class="fas fa-star"></i>
                                ${exploit.stars}
                            </span>
                            <span class="text-blue-400">
                                <i class="fas fa-code-branch"></i>
                                ${exploit.forks || 0}
                            </span>
                        </div>
                    </div>
                </div>
            `).join('')
            : '<p class="text-gray-400">No known exploits found.</p>';

        // Display scanned pages with enhanced information
        const pagesHTML = results.pages.map(page => `
            <div class="bg-gray-800/30 rounded-lg mb-3">
                <div class="flex items-center justify-between py-3 px-4">
                    <span class="text-sm text-gray-300 font-medium">${page.url}</span>
                    <span class="text-xs ${page.status === 'Error' ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'} px-2 py-1 rounded">
                        ${page.status}
                    </span>
                </div>
                ${page.findings.length > 0 ? `
                    <div class="border-t border-gray-700/50 px-4 py-3">
                        ${page.findings.map(finding => `
                            <div class="flex items-center gap-2 text-sm mb-2 last:mb-0">
                                <span class="${getSeverityClass(finding.type)}">
                                    <i class="fas fa-${finding.type === 'info' ? 'info-circle' : finding.type === 'warning' ? 'exclamation-triangle' : 'exclamation-circle'}"></i>
                                </span>
                                <span class="text-gray-400">${finding.message}</span>
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
            </div>
        `).join('');

        // Display scan history
        const historyHTML = scanHistory.length > 1 ? `
            <div class="mb-6">
                <h3 class="text-lg font-medium mb-4 text-gray-300">Scan History</h3>
                <div class="bg-gray-800/30 rounded-lg overflow-hidden">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="border-b border-gray-700/50">
                                <th class="py-2 px-4 text-left text-gray-400">URL</th>
                                <th class="py-2 px-4 text-left text-gray-400">Date</th>
                                <th class="py-2 px-4 text-left text-gray-400">Issues</th>
                                <th class="py-2 px-4 text-left text-gray-400">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${scanHistory.slice(1, 5).map((scan, index) => `
                                <tr class="${index % 2 === 0 ? 'bg-gray-800/20' : ''}">
                                    <td class="py-2 px-4 text-gray-300">${new URL(scan.url).hostname}</td>
                                    <td class="py-2 px-4 text-gray-400">${new Date(scan.timestamp).toLocaleDateString()}</td>
                                    <td class="py-2 px-4">
                                        <div class="flex items-center gap-2">
                                            <span class="text-red-300">${scan.summary.vulnerabilities.critical}</span>
                                            <span class="text-orange-300">${scan.summary.vulnerabilities.high}</span>
                                            <span class="text-yellow-300">${scan.summary.vulnerabilities.medium}</span>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4">
                                        <button class="text-blue-400 hover:text-blue-300 text-sm" data-url="${scan.url}">
                                            Rescan
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : '';

        // Update the DOM with all sections
        resultsContainer.innerHTML = `
            <div class="bg-[#40414f] rounded-lg p-6">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-xl font-semibold">Scan Results</h2>
                    <div class="flex gap-2">
                        <button id="exportButton" class="text-sm bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded flex items-center gap-1">
                            <i class="fas fa-download"></i> Export
                        </button>
                        <button id="rescanButton" class="text-sm bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded flex items-center gap-1">
                            <i class="fas fa-sync-alt"></i> Rescan
                        </button>
                    </div>
                </div>
                
                ${scanTimeHTML}
                ${summaryHTML}
                
                <div class="mb-6">
                    <h3 class="text-lg font-medium mb-4 text-gray-300">Known Exploits Found</h3>
                    <div id="exploitsList">${exploitsHTML}</div>
                </div>
                
                <div class="mb-6">
                    <h3 class="text-lg font-medium mb-4 text-gray-300">Scanned Pages</h3>
                    <div id="pagesList">${pagesHTML}</div>
                </div>
                
                ${historyHTML}
            </div>
        `;

        // Show results container
        resultsContainer.classList.remove('hidden');
        
        // Add event listeners for new buttons
        document.getElementById('exportButton')?.addEventListener('click', () => exportResults(results));
        document.getElementById('rescanButton')?.addEventListener('click', () => {
            urlInput.value = results.summary.targetUrl;
            scanButton.click();
        });
        
        // Add event listeners for history rescan buttons
        document.querySelectorAll('[data-url]').forEach(button => {
            button.addEventListener('click', () => {
                urlInput.value = button.getAttribute('data-url');
                scanButton.click();
            });
        });
    }

    /**
     * Export scan results as JSON file
     */
    function exportResults(results) {
        const dataStr = JSON.stringify(results, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        
        const exportFileDefaultName = `bughunter-scan-${new Date().toISOString().slice(0,10)}.json`;
        
        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();
    }

    // Event Listeners for UI components
    
    // Settings panel
    settingsButton.addEventListener('click', () => {
        initializeSettingsForm();
        settingsPanel.classList.add('open');
        settingsOverlay.classList.add('open');
    });
    
    closeSettings.addEventListener('click', () => {
        settingsPanel.classList.remove('open');
        settingsOverlay.classList.remove('open');
    });
    
    settingsOverlay.addEventListener('click', () => {
        settingsPanel.classList.remove('open');
        settingsOverlay.classList.remove('open');
    });
    
    saveSettings.addEventListener('click', saveUserSettings);
    
    // History panel
    historyButton.addEventListener('click', () => {
        displayHistory();
        historyContainer.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
    });
    
    closeHistory.addEventListener('click', () => {
        historyContainer.classList.add('hidden');
    });
    
    clearHistory.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all scan history?')) {
            scanHistory = [];
            localStorage.removeItem('scanHistory');
            displayHistory();
        }
    });
    
    // Theme toggle
    themeToggle.addEventListener('click', () => {
        if (document.body.classList.contains('light-mode')) {
            document.body.classList.remove('light-mode');
            themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
            appSettings.theme = 'dark';
        } else {
            document.body.classList.add('light-mode');
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
            appSettings.theme = 'light';
        }
        
        // Save theme preference
        const settings = JSON.parse(localStorage.getItem('bughunterSettings') || '{}');
        settings.theme = appSettings.theme;
        localStorage.setItem('bughunterSettings', JSON.stringify(settings));
    });
    
    // Handle scan button click
    scanButton.addEventListener('click', async () => {
        // Hide history container if it's open
        historyContainer.classList.add('hidden');
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }

        // Add http:// if protocol is missing
        let targetUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            targetUrl = 'http://' + url;
        }

        try {
            // Show scanning status
            const scanPhase = document.getElementById('scanPhase');
            scanningStatus.classList.remove('hidden');
            resultsContainer.classList.add('hidden');
            scanButton.disabled = true;
            scanButton.classList.add('opacity-50');

            const scanProgress = document.getElementById('scanProgress');
            const totalPhases = 4;
            let currentPhase = 0;

            async function updatePhase(phase, duration) {
                currentPhase++;
                scanPhase.textContent = phase;
                scanProgress.style.width = `${(currentPhase / totalPhases) * 100}%`;
                await new Promise(resolve => setTimeout(resolve, duration));
            }

            // Update scan phases with real scanning
            await updatePhase('Checking website availability', 1000);
            await updatePhase('Discovering endpoints', 1500);
            
            scanPhase.textContent = 'Searching for known exploits';
            scanProgress.style.width = `${(3 / totalPhases) * 100}%`;
            const results = await scanWebsite(targetUrl);

            await updatePhase('Analyzing vulnerabilities', 1000);

            // Hide scanning status
            scanningStatus.classList.add('hidden');
            
            // Display results
            displayResults(results);
        } catch (error) {
            alert(`Error scanning website: ${error.message}`);
            console.error(error);
            scanningStatus.classList.add('hidden');
        } finally {
            scanButton.disabled = false;
            scanButton.classList.remove('opacity-50');
        }
    });

    // Handle Enter key press
    urlInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !scanButton.disabled) {
            scanButton.click();
        }
    });
});
