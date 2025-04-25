// DOM Elements for File 1
const dropZone1 = document.getElementById('dropZone1');
const fileInput1 = document.getElementById('fileInput1');
const results1 = document.getElementById('results1');
const webhooksList1 = document.getElementById('webhooksList1');
const c2List1 = document.getElementById('c2List1');
const stringsList1 = document.getElementById('stringsList1');

// DOM Elements for File 2
const dropZone2 = document.getElementById('dropZone2');
const fileInput2 = document.getElementById('fileInput2');
const results2 = document.getElementById('results2');
const webhooksList2 = document.getElementById('webhooksList2');
const c2List2 = document.getElementById('c2List2');
const stringsList2 = document.getElementById('stringsList2');

// Event Listeners for File 1
dropZone1.addEventListener('click', () => fileInput1.click());
dropZone1.addEventListener('dragover', (e) => handleDragOver(e, dropZone1));
dropZone1.addEventListener('dragleave', () => handleDragLeave(dropZone1));
dropZone1.addEventListener('drop', (e) => handleDrop(e, dropZone1, 1));
fileInput1.addEventListener('change', (e) => handleFileSelect(e, 1));

// Event Listeners for File 2
dropZone2.addEventListener('click', () => fileInput2.click());
dropZone2.addEventListener('dragover', (e) => handleDragOver(e, dropZone2));
dropZone2.addEventListener('dragleave', () => handleDragLeave(dropZone2));
dropZone2.addEventListener('drop', (e) => handleDrop(e, dropZone2, 2));
fileInput2.addEventListener('change', (e) => handleFileSelect(e, 2));

// Drag and Drop Handlers
function handleDragOver(e, dropZone) {
    e.preventDefault();
    dropZone.style.borderColor = '#00ff88';
    dropZone.style.background = 'rgba(0, 255, 136, 0.1)';
}

function handleDragLeave(dropZone) {
    dropZone.style.borderColor = '#00ff88';
    dropZone.style.background = 'transparent';
}

function handleDrop(e, dropZone, fileNum) {
    e.preventDefault();
    dropZone.style.borderColor = '#00ff88';
    dropZone.style.background = 'transparent';
    
    const files = e.dataTransfer.files;
    handleFiles(files, fileNum);
}

function handleFileSelect(e, fileNum) {
    const files = e.target.files;
    handleFiles(files, fileNum);
}

// File Handling
function handleFiles(files, fileNum) {
    if (files.length > 0) {
        const file = files[0];
        if (file.name.endsWith('.exe')) {
            analyzeFile(file, fileNum);
        } else {
            alert('Please upload an .exe file');
        }
    }
}

// Analysis Patterns
const webhookPatterns = {
    discord: /(https?:\/\/)?((?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+)/gi,
    telegram: /https:\/\/api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+/g,
    generic: /https?:\/\/[A-Za-z0-9-]+\.[A-Za-z0-9-.]+(\/[A-Za-z0-9\/_.-]+)?\/webhook/gi
};

const c2Patterns = {
    ipPort: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\b/g,
    playit: /(?:playit\.gg|\.playit\.gg|tunnel\.playit\.gg)[\/\w-]*(?::[0-9]{1,5})?/gi
};

const suspiciousPatterns = {
    processInjection: [
        'CreateRemoteThread',
        'VirtualAllocEx',
        'WriteProcessMemory',
        'NtCreateThreadEx',
        'RtlCreateUserThread'
    ],
    codeExecution: [
        'WinExec',
        'ShellExecute',
        'CreateProcess',
        'system(',
        'exec('
    ],
    registry: [
        'RegCreateKey',
        'RegSetValue',
        'RegOpenKey',
        'RegDeleteKey'
    ],
    networking: [
        'WSAStartup',
        'socket(',
        'connect(',
        'InternetOpen',
        'HttpSendRequest'
    ]
};

// File Analysis
async function analyzeFile(file, fileNum) {
    const results = fileNum === 1 ? results1 : results2;
    const webhooksList = fileNum === 1 ? webhooksList1 : webhooksList2;
    const c2List = fileNum === 1 ? c2List1 : c2List2;
    const stringsList = fileNum === 1 ? stringsList1 : stringsList2;

    results.innerHTML = `
        <div class="result-item">
            <i class="fas fa-spinner fa-spin"></i>
            <span>Analyzing file: ${file.name}</span>
        </div>
    `;

    webhooksList.innerHTML = '';
    c2List.innerHTML = '';
    stringsList.innerHTML = '';

    try {
        const fileContent = await readFileAsBinary(file);
        
        const webhooks = findWebhooks(fileContent);
        const c2Servers = findC2Servers(fileContent);
        const suspiciousStrings = findSuspiciousStrings(fileContent);

        results.innerHTML = `
            <div class="result-item">
                <i class="fas fa-check-circle success"></i>
                <span>File analyzed successfully</span>
            </div>
            <div class="result-item">
                <i class="fas fa-exclamation-triangle warning"></i>
                <span>Found ${suspiciousStrings.length} suspicious strings</span>
            </div>
            <div class="result-item">
                <i class="fas fa-globe warning"></i>
                <span>Detected ${c2Servers.length} C2 connections</span>
            </div>
            <div class="result-item">
                <i class="fas fa-link warning"></i>
                <span>Found ${webhooks.length} webhooks</span>
            </div>
        `;

        updateWebhooksList(webhooks, webhooksList);
        updateC2List(c2Servers, c2List);
        updateStringsList(suspiciousStrings, stringsList);

        // Compare results if both files are analyzed
        if (fileNum === 2) {
            compareResults();
        }

    } catch (error) {
        results.innerHTML = `
            <div class="result-item">
                <i class="fas fa-times-circle" style="color: #ff4444;"></i>
                <span>Error analyzing file: ${error.message}</span>
            </div>
        `;
    }
}

// Helper Functions
function readFileAsBinary(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (event) => {
            const binary = event.target.result;
            const text = new TextDecoder('utf-8').decode(new Uint8Array(binary));
            resolve(text);
        };
        reader.onerror = (error) => reject(error);
        reader.readAsArrayBuffer(file);
    });
}

function updateWebhooksList(webhooks, list) {
    if (webhooks.length > 0) {
        webhooks.forEach(webhook => {
            list.innerHTML += `
                <div class="detail-item webhook-item">
                    <h3>${webhook.type} (Risk: ${webhook.risk})</h3>
                    <p>${webhook.url}</p>
                </div>
            `;
        });
    } else {
        list.innerHTML = '<p class="empty-message">No webhooks detected</p>';
    }
}

function updateC2List(servers, list) {
    if (servers.length > 0) {
        servers.forEach(server => {
            list.innerHTML += `
                <div class="detail-item c2-item">
                    <h3>${server.type} (Risk: ${server.risk})</h3>
                    <p>${server.address}</p>
                </div>
            `;
        });
    } else {
        list.innerHTML = '<p class="empty-message">No C2 connections detected</p>';
    }
}

function updateStringsList(strings, list) {
    if (strings.length > 0) {
        strings.forEach(string => {
            list.innerHTML += `
                <div class="detail-item string-item">
                    <h3>${string.category} (Risk: ${string.risk})</h3>
                    <p>${string.string}</p>
                </div>
            `;
        });
    } else {
        list.innerHTML = '<p class="empty-message">No suspicious strings detected</p>';
    }
}

function compareResults() {
    // Get all detail items
    const items1 = document.querySelectorAll('#webhooksList1 .detail-item, #c2List1 .detail-item, #stringsList1 .detail-item');
    const items2 = document.querySelectorAll('#webhooksList2 .detail-item, #c2List2 .detail-item, #stringsList2 .detail-item');

    // Create arrays of content for comparison
    const content1 = Array.from(items1).map(item => item.textContent);
    const content2 = Array.from(items2).map(item => item.textContent);

    // Highlight differences
    items1.forEach((item, index) => {
        if (!content2.includes(item.textContent)) {
            item.classList.add('difference-highlight');
        }
    });

    items2.forEach((item, index) => {
        if (!content1.includes(item.textContent)) {
            item.classList.add('difference-highlight');
        }
    });
}

// Analysis Functions
function findWebhooks(content) {
    const webhooks = [];
    
    const discordMatches = content.match(webhookPatterns.discord) || [];
    discordMatches.forEach(url => {
        if (isValidDiscordWebhook(url)) {
            const fullUrl = url.startsWith('http') ? url : 'https://' + url;
            if (!webhooks.some(w => w.url === fullUrl)) {
                webhooks.push({
                    url: fullUrl,
                    type: 'Discord Webhook',
                    risk: 'High'
                });
            }
        }
    });

    const telegramWebhooks = content.match(webhookPatterns.telegram) || [];
    telegramWebhooks.forEach(url => {
        if (!webhooks.some(w => w.url === url)) {
            webhooks.push({
                url: url,
                type: 'Telegram Webhook',
                risk: 'High'
            });
        }
    });

    const genericWebhooks = content.match(webhookPatterns.generic) || [];
    genericWebhooks.forEach(url => {
        if (!webhooks.some(w => w.url === url)) {
            webhooks.push({
                url: url,
                type: 'Generic Webhook',
                risk: 'Medium'
            });
        }
    });

    return webhooks;
}

function findC2Servers(content) {
    const servers = [];
    
    const ipPorts = content.match(c2Patterns.ipPort) || [];
    ipPorts.forEach(address => {
        const [ip, port] = address.split(':');
        const ipParts = ip.split('.');
        if (ipParts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255) && 
            parseInt(port) > 0 && parseInt(port) <= 65535) {
            servers.push({
                address: address,
                type: 'IP:Port',
                risk: 'Critical'
            });
        }
    });

    const playitTunnels = content.match(c2Patterns.playit) || [];
    playitTunnels.forEach(tunnel => {
        if (!servers.some(s => s.address === tunnel)) {
            servers.push({
                address: tunnel,
                type: 'Playit.gg Tunnel',
                risk: 'High'
            });
        }
    });

    return servers;
}

function findSuspiciousStrings(content) {
    const strings = [];
    
    suspiciousPatterns.processInjection.forEach(pattern => {
        if (content.includes(pattern)) {
            strings.push({
                string: pattern,
                category: 'Process Injection',
                risk: 'High'
            });
        }
    });

    suspiciousPatterns.codeExecution.forEach(pattern => {
        if (content.includes(pattern)) {
            strings.push({
                string: pattern,
                category: 'Code Execution',
                risk: 'High'
            });
        }
    });

    suspiciousPatterns.registry.forEach(pattern => {
        if (content.includes(pattern)) {
            strings.push({
                string: pattern,
                category: 'Registry Manipulation',
                risk: 'Medium'
            });
        }
    });

    suspiciousPatterns.networking.forEach(pattern => {
        if (content.includes(pattern)) {
            strings.push({
                string: pattern,
                category: 'Networking',
                risk: 'Medium'
            });
        }
    });

    return strings;
}

function isValidDiscordWebhook(url) {
    if (!url.startsWith('http')) {
        url = 'https://' + url;
    }
    
    try {
        const webhookUrl = new URL(url);
        const pathParts = webhookUrl.pathname.split('/');
        
        if (pathParts.length >= 5 && 
            pathParts[1] === 'api' && 
            pathParts[2] === 'webhooks' && 
            pathParts[3].length > 0 && 
            pathParts[4].length > 0) {
            return true;
        }
    } catch (e) {
        return false;
    }
    return false;
} 