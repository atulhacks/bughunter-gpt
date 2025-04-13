document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const scanningStatus = document.getElementById('scanningStatus');
    const resultsContainer = document.getElementById('resultsContainer');
    const exploitsList = document.getElementById('exploitsList');
    const pagesList = document.getElementById('pagesList');

    // GitHub API configuration
    const GITHUB_API_URL = 'https://api.github.com';
    const EXPLOIT_CATEGORIES = [
        { keyword: 'vulnerability', label: 'Vulnerability', color: 'yellow' },
        { keyword: 'exploit', label: 'Exploit', color: 'red' },
        { keyword: 'cve', label: 'CVE', color: 'orange' },
        { keyword: 'security-issue', label: 'Security Issue', color: 'blue' }
    ];

    // Common vulnerability patterns
    const VULNERABILITY_PATTERNS = [
        { pattern: 'sql-injection', name: 'SQL Injection', severity: 'high' },
        { pattern: 'xss', name: 'Cross-Site Scripting (XSS)', severity: 'high' },
        { pattern: 'rce', name: 'Remote Code Execution', severity: 'critical' },
        { pattern: 'csrf', name: 'Cross-Site Request Forgery', severity: 'medium' },
        { pattern: 'file-inclusion', name: 'File Inclusion', severity: 'high' },
        { pattern: 'open-redirect', name: 'Open Redirect', severity: 'medium' },
        { pattern: 'ssrf', name: 'Server-Side Request Forgery', severity: 'high' }
    ];

    async function fetchGitHubExploits(url) {
        try {
            const domain = new URL(url).hostname;
            const exploits = [];

            for (const category of EXPLOIT_CATEGORIES) {
                const searchQuery = `${domain} ${category.keyword}`;
                const response = await fetch(`${GITHUB_API_URL}/search/repositories?q=${encodeURIComponent(searchQuery)}&sort=stars&order=desc`);
                
                if (!response.ok) {
                    throw new Error(`GitHub API error: ${response.status}`);
                }

                const data = await response.json();

                if (data.items) {
                    exploits.push(...data.items.map(item => ({
                        name: item.name,
                        description: item.description,
                        url: item.html_url,
                        stars: item.stargazers_count,
                        category: category.label,
                        color: category.color,
                        lastUpdated: new Date(item.updated_at).toLocaleDateString(),
                        language: item.language,
                        owner: item.owner.login
                    })));
                }
            }

            return exploits;
        } catch (error) {
            console.error('Error fetching GitHub exploits:', error);
            throw error;
        }
    }

    async function scanWebsite(url) {
        try {
            // Simulate website crawling and vulnerability scanning
            const pages = [
                { 
                    url: url,
                    status: 'Scanned',
                    findings: [
                        { type: 'info', message: 'Server: Apache/2.4.41' },
                        { type: 'warning', message: 'Directory listing enabled' }
                    ]
                },
                { 
                    url: `${url}/login`,
                    status: 'Scanned',
                    findings: [
                        { type: 'warning', message: 'Form submission over HTTP' },
                        { type: 'info', message: 'Basic authentication in use' }
                    ]
                },
                { 
                    url: `${url}/admin`,
                    status: 'Blocked',
                    findings: [
                        { type: 'error', message: 'Access forbidden (403)' }
                    ]
                },
                { 
                    url: `${url}/api`,
                    status: 'Scanned',
                    findings: [
                        { type: 'critical', message: 'API endpoint exposed without authentication' },
                        { type: 'warning', message: 'CORS misconfiguration detected' }
                    ]
                }
            ];

            // Fetch potential exploits from GitHub
            const exploits = await fetchGitHubExploits(url);

            return {
                pages,
                exploits,
                summary: {
                    totalPages: pages.length,
                    vulnerabilities: {
                        critical: 1,
                        high: 0,
                        medium: 2,
                        low: 1
                    }
                }
            };
        } catch (error) {
            console.error('Error scanning website:', error);
            throw error;
        }
    }

    function getSeverityClass(severity) {
        const classes = {
            critical: 'bg-red-500/20 text-red-300',
            high: 'bg-orange-500/20 text-orange-300',
            medium: 'bg-yellow-500/20 text-yellow-300',
            low: 'bg-blue-500/20 text-blue-300',
            info: 'bg-gray-500/20 text-gray-300'
        };
        return classes[severity] || classes.info;
    }

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

        // Display exploits
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
                        </div>
                    </div>
                </div>
            `).join('')
            : '<p class="text-gray-400">No known exploits found.</p>';

        // Display scanned pages
        const pagesHTML = results.pages.map(page => `
            <div class="bg-gray-800/30 rounded-lg mb-3">
                <div class="flex items-center justify-between py-3 px-4">
                    <span class="text-sm text-gray-300 font-medium">${page.url}</span>
                    <span class="text-xs ${page.status === 'Blocked' ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'} px-2 py-1 rounded">
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

        // Update the DOM
        resultsContainer.innerHTML = `
            <div class="bg-[#40414f] rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-6">Scan Results</h2>
                ${summaryHTML}
                <div class="mb-6">
                    <h3 class="text-lg font-medium mb-4 text-gray-300">Known Exploits Found</h3>
                    <div id="exploitsList">${exploitsHTML}</div>
                </div>
                <div>
                    <h3 class="text-lg font-medium mb-4 text-gray-300">Scanned Pages</h3>
                    <div id="pagesList">${pagesHTML}</div>
                </div>
            </div>
        `;

        // Show results container
        resultsContainer.classList.remove('hidden');
    }

    // Handle scan button click
    scanButton.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a valid URL');
            return;
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

            // Update scan phases
            await updatePhase('Checking website availability', 1000);
            await updatePhase('Crawling website pages', 1500);
            
            scanPhase.textContent = 'Searching for known exploits';
            scanProgress.style.width = `${(3 / totalPhases) * 100}%`;
            const results = await scanWebsite(url);

            await updatePhase('Analyzing vulnerabilities', 1000);

            // Hide scanning status
            scanningStatus.classList.add('hidden');
            
            // Display results
            displayResults(results);
        } catch (error) {
            alert('Error scanning website. Please try again.');
            console.error(error);
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