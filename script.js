// DOM Elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const webhooksList = document.getElementById('webhooksList');
const c2List = document.getElementById('c2List');
const stringsList = document.getElementById('stringsList');

// Event Listeners
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = '#00ff88';
    dropZone.style.background = 'rgba(0, 255, 136, 0.1)';
});

dropZone.addEventListener('dragleave', () => {
    dropZone.style.borderColor = '#00ff88';
    dropZone.style.background = 'transparent';
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = '#00ff88';
    dropZone.style.background = 'transparent';
    
    const files = e.dataTransfer.files;
    handleFiles(files);
});

fileInput.addEventListener('change', (e) => {
    const files = e.target.files;
    handleFiles(files);
});

// File Handling
function handleFiles(files) {
    if (files.length > 0) {
        const file = files[0];
        if (file.name.endsWith('.exe')) {
            analyzeFile(file);
        } else {
            alert('Please upload an .exe file');
        }
    }
}

// Webhook patterns to search for
const webhookPatterns = {
    discord: /(https?:\/\/)?((?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+)/gi,
    telegram: /https:\/\/api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+/g,
    generic: /https?:\/\/[A-Za-z0-9-]+\.[A-Za-z0-9-.]+(\/[A-Za-z0-9\/_.-]+)?\/webhook/gi
};

// Helper function to validate Discord webhook
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

// C2 patterns to search for
const c2Patterns = {
    ipPort: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\b/g,
    playit: /(?:playit\.gg|\.playit\.gg|tunnel\.playit\.gg)[\/\w-]*(?::[0-9]{1,5})?/gi
};

// Suspicious strings to search for
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
async function analyzeFile(file) {
    const results = document.querySelector('.results');
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

        if (webhooks.length > 0) {
            webhooks.forEach(webhook => {
                webhooksList.innerHTML += `
                    <div class="detail-item webhook-item">
                        <h3>${webhook.type} (Risk: ${webhook.risk})</h3>
                        <p>${webhook.url}</p>
                    </div>
                `;
            });
        } else {
            webhooksList.innerHTML = '<p class="empty-message">No webhooks detected</p>';
        }

        if (c2Servers.length > 0) {
            c2Servers.forEach(server => {
                c2List.innerHTML += `
                    <div class="detail-item c2-item">
                        <h3>${server.type} (Risk: ${server.risk})</h3>
                        <p>${server.address}</p>
                    </div>
                `;
            });
        } else {
            c2List.innerHTML = '<p class="empty-message">No C2 connections detected</p>';
        }

        if (suspiciousStrings.length > 0) {
            suspiciousStrings.forEach(string => {
                stringsList.innerHTML += `
                    <div class="detail-item string-item">
                        <h3>${string.category} (Risk: ${string.risk})</h3>
                        <p>${string.string}</p>
                    </div>
                `;
            });
        } else {
            stringsList.innerHTML = '<p class="empty-message">No suspicious strings detected</p>';
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

// Helper function to read file as binary
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

// Find webhooks in content
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

// Find C2 servers in content
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

// Find suspicious strings in content
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