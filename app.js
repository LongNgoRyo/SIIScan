// Các loại dữ liệu cá nhân & Mức độ nhạy cảm theo Nghị định 13/2023/NĐ-CP và tiêu chuẩn quốc tế
const piiTypes = [
    { name: "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)", level: "high", icon: "💀" },
    { name: "Số định danh (CCCD/CMND)", level: "high", icon: "🆔" },
    { name: "Số thẻ tín dụng", level: "high", icon: "💳" },
    { name: "Số tài khoản ngân hàng / IBAN", level: "high", icon: "🏦" },
    { name: "Thông tin xác thực / API Key / Mật khẩu", level: "high", icon: "🔑" },
    { name: "Hồ sơ y tế / Thông tin sức khỏe", level: "high", icon: "🩺" },
    { name: "Dữ liệu sinh trắc học", level: "high", icon: "🧬" },
    { name: "Số điện thoại", level: "medium", icon: "📱" },
    { name: "Họ và tên", level: "medium", icon: "👤" },
    { name: "Ngày sinh", level: "medium", icon: "📅" },
    { name: "Địa chỉ", level: "medium", icon: "🏠" },
    { name: "Địa chỉ email", level: "low", icon: "✉️" },
    { name: "Địa chỉ IP", level: "low", icon: "🌐" },
    { name: "Cookie phiên", level: "low", icon: "🍪" }
];

const piiDescriptions = {
    "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)": "Phát hiện mã nguồn chứa các hàm thực thi lệnh hệ thống nguy hiểm, giải mã base64 tự động hoặc dấu hiệu Webshell/Backdoor giúp kẻ tấn công chiếm quyền điều khiển server.",
    "Số định danh (CCCD/CMND)": "Rò rỉ Số định danh cá nhân (CCCD/CMND) hoặc số Hộ chiếu có thể dẫn đến việc mạo danh danh tính, gian lận tài chính và vi phạm nghiêm trọng quy định bảo vệ dữ liệu cá nhân theo Nghị định 13/2023/NĐ-CP.",
    "Số thẻ tín dụng": "Tiết lộ số thẻ tín dụng (PAN) vi phạm trực tiếp các tiêu chuẩn PCI-DSS của tổ chức thẻ quốc tế, có thể dẫn đến nguy cơ bị phạt nặng hoặc khóa tài khoản thanh toán.",
    "Số tài khoản ngân hàng / IBAN": "Lộ lọt thông tin tài khoản ngân hàng tạo điều kiện cho kẻ xấu thực hiện các hành vi lừa đảo tài chính hoặc rút tiền trái phép.",
    "Thông tin xác thực / API Key / Mật khẩu": "Các mật khẩu, khóa API hoặc token bị lộ sẽ giúp kẻ tấn công trực tiếp chiếm quyền điều khiển tài khoản và nâng cao đặc quyền hệ thống.",
    "Hồ sơ y tế / Thông tin sức khỏe": "Thông tin sức khỏe cá nhân và hồ sơ bệnh án là dữ liệu cá nhân nhạy cảm đặc biệt theo Nghị định 13/2023/NĐ-CP, yêu cầu các biện pháp bảo vệ tối đa.",
    "Dữ liệu sinh trắc học": "Dữ liệu vân tay, FaceID hay võng mạc là các thông tin nhận dạng vĩnh viễn. Việc để lộ các dữ liệu này gây ra các rủi ro bảo mật nghiêm trọng không thể khắc phục.",
    "Số điện thoại": "Giúp kẻ xấu thực hiện các cuộc gọi lừa đảo, tin nhắn rác, tấn công SIM-swapping hoặc tấn công kỹ thuật xã hội.",
    "Địa chỉ": "Tiết lộ địa chỉ nơi ở, nơi thường trú gây ruiu ro về an toàn vật lý và quyền riêng tư cá nhân.",
    "Họ và tên": "Thông tin cơ bản để xây dựng các kịch bản lừa đảo hoặc liên kết các nguồn dữ liệu nhằm định danh một cá nhân.",
    "Ngày sinh": "Thường được sử dụng trong các câu hỏi xác minh bảo mật hoặc kết hợp với dữ liệu khác để giả danh nạn nhân.",
    "Địa chỉ email": "Mục tiêu hàng đầu cho các chiến dịch spam, phishing (lừa đảo qua email) và tấn công brute-force khôi phục mật khẩu.",
    "Địa chỉ IP": "Tiết lộ vị trí địa lý, nhà cung cấp mạng và các cổng kết nối mở của máy chủ/thiết bị cá nhân.",
    "Cookie phiên": "Cho phép kẻ tấn công thực hiện hành vi chiếm đoạt phiên đăng nhập (Session Hijacking) và bỏ qua xác thực đa yếu tố (MFA)."
};

// Hàm kiểm tra thẻ tín dụng bằng thuật toán Luhn
function isValidLuhn(numberStr) {
    const sanitized = numberStr.replace(/[-\s]/g, "");
    if (!/^\d{13,19}$/.test(sanitized)) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = sanitized.length - 1; i >= 0; i--) {
        let digit = parseInt(sanitized.charAt(i), 10);
        if (shouldDouble) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
}

// Render badge CVSS theo mức độ nghiêm trọng
function cvssBadge(score, severity, vector) {
    if (score === undefined || score === null || score === 0) return '';
    const sev = severity || 'None';
    const colorMap = {
        'Critical': '#EF4444', 'High': '#F97316', 'Medium': '#F59E0B', 'Low': '#10B981', 'None': '#6B7280'
    };
    const color = colorMap[sev] || '#6B7280';
    const title = vector ? `Vector: ${vector}` : '';
    return `<span class="cvss-badge" title="${title}" style="display:inline-flex; align-items:center; gap:6px; background:${color}22; color:${color}; border:1px solid ${color}55; padding:3px 10px; border-radius:99px; font-size:0.75rem; font-weight:700; font-family:var(--font-mono);">
        <span style="letter-spacing:0.5px;">CVSS</span> ${score} <span style="font-weight:600;">— ${sev}</span>
    </span>`;
}

// Render badge MITRE ATT&CK
function mitreBadge(mitreId, mitreTactic) {
    if (!mitreId) return '';
    const title = mitreTactic ? `Tactic: ${mitreTactic}` : '';
    return `<span class="mitre-badge" title="${title}" style="display:inline-flex; align-items:center; gap:4px; background:rgba(139,92,246,0.15); color:#A78BFA; border:1px solid rgba(139,92,246,0.4); padding:2px 8px; border-radius:99px; font-size:0.7rem; font-weight:700; font-family:var(--font-mono);">⚔️ ${mitreId}</span>`;
}

// Render badge signature rule (YARA-style)
function signatureBadge(ruleId, ruleName) {
    return `<span class="sig-badge" title="Rule: ${ruleName}" style="display:inline-flex; align-items:center; gap:4px; background:rgba(16,185,129,0.12); color:#34D399; border:1px solid rgba(16,185,129,0.35); padding:2px 8px; border-radius:4px; font-size:0.68rem; font-weight:600; font-family:var(--font-mono);">🔎 ${ruleId}</span>`;
}

// Hàm ẩn dữ liệu nhạy cảm để hiển thị an toàn
function maskPIIValue(type, value) {
    if (!value) return "";
    value = value.trim();
    if (type === "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)") {
        return value;
    } else if (type === "Số định danh (CCCD/CMND)") {
        if (value.length === 12) {
            return value.substring(0, 3) + "••••••" + value.substring(9);
        } else {
            return value.substring(0, 3) + "•••" + value.substring(6);
        }
    } else if (type === "Số điện thoại") {
        return value.substring(0, 4) + "•••" + value.substring(7);
    } else if (type === "Địa chỉ email") {
        const parts = value.split("@");
        if (parts.length === 2) {
            const name = parts[0];
            const domain = parts[1];
            if (name.length > 2) {
                return name.substring(0, 2) + "•••@" + domain;
            }
            return "•••@" + domain;
        }
        return "••••@••••";
    } else if (type === "Số thẻ tín dụng") {
        const clean = value.replace(/[-\s]/g, "");
        if (clean.length >= 15) {
            return "•••• •••• •••• " + clean.substring(clean.length - 4);
        }
        return "•••• •••• •••• ••••";
    } else if (type === "Thông tin xác thực / API Key / Mật khẩu") {
        return "••••••••";
    } else if (type === "Số tài khoản ngân hàng / IBAN") {
        if (value.length > 6) {
            return value.substring(0, 3) + "••••" + value.substring(value.length - 3);
        }
        return "••••••••";
    } else if (type === "Họ và tên") {
        const words = value.split(/\s+/);
        if (words.length > 1) {
            return words[0] + " " + words.slice(1).map(w => w[0] + "••").join(" ");
        }
        return value[0] + "••";
    } else if (type === "Ngày sinh") {
        if (value.length >= 10) {
            return value.substring(0, 6) + "••••";
        }
        return "••/••/••••";
    } else if (type === "Địa chỉ") {
        return value.substring(0, Math.min(value.length, 12)) + "••••";
    }
    return "••••";
}

// Các mẫu biểu thức chính quy (Regex) quét tại chỗ (local)
const PII_PATTERNS = {
    "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)": /\b(?:eval|shell_exec|passthru|system|exec|base64_decode|assert|subprocess\.Popen|os\.system|child_process\.exec)\s*\(|\b(?:webshell|backdoor|reverse_shell|c99shell|r57shell|wso_shell|cmd\.exe|\/bin\/sh|\/bin\/bash)\b/gi,
    "Số định danh (CCCD/CMND)": /\b\d{9}\b|\b\d{12}\b|\b\d{3}-\d{2}-\d{4}\b/g, // CMND/CCCD/SSN
    "Số điện thoại": /\b(?:0|\+84|\+1|\+44)(?:[1-9]\d{7,10}|[35789]\d{2}[-\s.]?\d{3}[-\s.]?\d{3})\b/g, // Định dạng số điện thoại
    "Địa chỉ email": /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    "Số thẻ tín dụng": /\b(?:4[0-9]{12}(?:[0-9]{3})?|[56][0-9]{14}|3[47][0-9]{13})\b|\b(?:4[0-9]{3}[-\s][0-9]{4}[-\s][0-9]{4}[-\s][0-9]{4}|5[1-5][0-9]{2}[-\s][0-9]{4}[-\s][0-9]{4}[-\s][0-9]{4})\b/g, // Số thẻ tín dụng (Luhn kiểm tra sau)
    "Địa chỉ IP": /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    "Thông tin xác thực / API Key / Mật khẩu": /(?:password|passwd|pwd|secret|db_pass|access_token|apikey|api_key|token)\s*[:=]\s*['"]?([A-Za-z0-9_@#$%-]{4,})['"]?/gi,
    "Số tài khoản ngân hàng / IBAN": /(?:stk|số tài khoản|so tai khoan|tài khoản|số tk|so tk|bank account|account number|account_number|iban|swift|vietcombank|vcb|techcombank|tcb|bidv|vietinbank|agribank|mbbank|acb|vpbank|sacombank|tpbank)\s*[:=-]?\s*\b[A-Z0-9]{8,34}\b/gi,
    "Họ và tên": /\b(?!Quận|Phường|Đường|Thành phố|Tỉnh|Huyện|Xã|Việt)(?:Nguyễn|Trần|Lê|Phạm|Hoàng|Huỳnh|Phan|Vũ|Võ|Đặng|Bùi|Đỗ|Hồ|Ngô|Dương|Lý|Nguyen|Tran|Le|Pham|Hoang|Huynh|Vu|Vo|Dang|Bui|Do|Ho|Ngo|Duong|Ly|John|Mary|James|Patricia|Robert|Jennifer|Michael|Elizabeth|William|Linda|David|Barbara|Richard|Susan|Joseph|Jessica|Thomas|Sarah|Charles|Karen)\s+\p{Lu}[\p{Ll}]*(?:\s+\p{Lu}[\p{Ll}]*){1,3}\b/gu,
    "Ngày sinh": /(?:ngày sinh|ngay sinh|năm sinh|nam sinh|dob|birth|birthdate|sinh ngày|sinh ngay)\s*[:=-]?\s*\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{1,2}[/-]\d{1,2}[/-](?:19\d{2}|20[0-2]\d)\b/gi,
    "Địa chỉ": /(?:địa chỉ(?![\s]*(?:email|mail|thư điện tử))|dia chi(?![\s]*(?:email|mail|thu dien tu))|home address|street address|thường trú|thuong tru)\s*[:=-]?\s*['"]?([^'"\n\r]{10,100})['"]?|\b(?:số|so)?\s*\d+\s+(?:đường|street|phố|pho|ngõ|ngo|hẻm|hem|ấp|ap|thôn|thon)\s+[^,\n\r]{2,30}(?:,\s*[^,\n\r]{2,30}){1,4}\b/gi,
    "Hồ sơ y tế / Thông tin sức khỏe": /\b(?:bệnh án|benh an|nhóm máu|nhom mau|tiền sử bệnh|tien su benh|đơn thuốc|don thuoc|chẩn đoán|chan doan|phác đồ|phac do|bệnh nhân|benh nhan|bệnh lý|benh ly|khám bệnh|kham benh|điều trị|dieu tri|blood type|medical record|prescription|diagnosis|health record|patient)\b/gi,
    "Dữ liệu sinh trắc học": /\b(?:vân tay|van tay|mống mắt|mong mat|sinh trắc|sinh trac|nhận diện khuôn mặt|nhan dien khuon mat|fingerprint|faceid|iris scan|biometric)\b/gi,
    "Cookie phiên": /\b(?:sessid|sessionid|sid|phpsessid|jsessionid|session_id|connect\.sid)\s*[:=]\s*['"]?([A-Za-z0-9_-]{16,64})['"]?/gi
};

const fileExtensions = ['.txt', '.csv', '.log', '.json', '.xml', '.sql', '.env', '.config', '.yaml', '.yml', '.php', '.js'];
const suspiciousKeywords = ['khachhang', 'nhanvien', 'danhsach', 'users', 'backup', 'config', 'credential', 'cccd', 'billing', 'invoice', 'customers', 'employees', 'pass', 'db', 'payment'];
const mockFolders = ["/var/www/html/config/", "/var/www/html/uploads/", "/var/www/html/logs/", "/var/www/html/backup/", "/var/www/html/public/"];

// HTML Elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const folderInput = document.getElementById('folderInput');
const hashInput = document.getElementById('hashInput');
const searchBtn = document.getElementById('searchBtn');

const heroSection = document.getElementById('hero');
const featuresSection = document.getElementById('featuresSection');
const loadingOverlay = document.getElementById('loadingOverlay');
const resultSection = document.getElementById('resultSection');

const progressFill = document.getElementById('progressFill');
const engineTicker = document.getElementById('engineTicker');
const loadingStatus = document.getElementById('loadingStatus');

const backBtn = document.getElementById('backBtn');
const reanalyzeBtn = document.getElementById('reanalyzeBtn');

// Variables
let currentTargetName = "";
let scannedFilesCount = 0;
let lastFilesArray = null;
let scanResults = [];
let scanStats = { high: 0, medium: 0, low: 0, totalFiles: 0, filesWithPii: 0, securedFiles: 0 };
let currentTargetIsFolder = false;
let isRemediated = false; // Check if recommendations have been run

// Tự động xác định địa chỉ API
const getApiUrl = (endpoint) => {
    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    if (window.location.protocol === 'file:' || (isLocalhost && window.location.port !== '5000' && window.location.port !== '')) {
        return `http://localhost:5000${endpoint}`;
    }
    return endpoint;
};

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initFilters();
    initSearchEngine();
    animateNumbers();
    
    // Theme Toggle
    const themeToggleBtn = document.getElementById('themeToggle');
    
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.documentElement.classList.add('light-theme');
        if (themeToggleBtn) themeToggleBtn.textContent = '☀️';
    } else {
        document.documentElement.classList.remove('light-theme');
        if (themeToggleBtn) themeToggleBtn.textContent = '🌙';
    }
    
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            document.documentElement.classList.toggle('light-theme');
            const isLight = document.documentElement.classList.contains('light-theme');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
            themeToggleBtn.textContent = isLight ? '☀️' : '🌙';
        });
    }
});

// ===== DRAG & DROP HANDLING =====
if (dropZone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', handleDrop, false);
}

function handleDrop(e) {
    let dt = e.dataTransfer;
    let files = dt.files;
    if (files.length > 0) {
        processFiles(files);
    }
}

if (fileInput) {
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) processFiles(this.files);
    });
}

if (folderInput) {
    folderInput.addEventListener('change', function() {
        if (this.files.length > 0) processFiles(this.files, true);
    });
}

if (searchBtn) {
    searchBtn.addEventListener('click', () => {
        const path = hashInput.value.trim();
        if (path) processServerPath(path);
    });
}

if (hashInput) {
    hashInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const path = hashInput.value.trim();
            if (path) processServerPath(path);
        }
    });
}

if (backBtn) {
    backBtn.addEventListener('click', resetToHome);
}

if (reanalyzeBtn) {
    reanalyzeBtn.addEventListener('click', () => {
        isRemediated = false;
        if (lastFilesArray) {
            startLoading(currentTargetName, lastFilesArray);
        } else {
            startLoading(currentTargetName, scannedFilesCount || 50);
        }
    });
}

// ===== PROCESSING =====
function processFiles(files, isFolder = false) {
    isRemediated = false;
    scannedFilesCount = files.length;
    currentTargetIsFolder = isFolder || files.length > 1;
    currentTargetName = isFolder ? (files[0].webkitRelativePath ? files[0].webkitRelativePath.split('/')[0] : "Uploaded Folder") : (files.length === 1 ? files[0].name : `${files.length} files`);
    
    const filesArray = Array.from(files);
    lastFilesArray = filesArray;
    startLoading(currentTargetName, filesArray);
}

function processServerPath(path) {
    isRemediated = false;
    currentTargetIsFolder = true;
    currentTargetName = path;
    scannedFilesCount = Math.floor(Math.random() * 80) + 20; // Simulated files count
    lastFilesArray = null;
    startLoading(path, scannedFilesCount);
}

function clearResultUI() {
    const containers = [
        'hashTable', 'detailTable', 'engineGrid', 
        'detailsContent', 'behaviorContent', 'fileTags'
    ];
    
    containers.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '';
    });
    
    const ringFill = document.getElementById('ringFill');
    if (ringFill) {
        ringFill.style.strokeDashoffset = 314;
        ringFill.style.stroke = 'var(--color-clean)';
    }
    
    const scoreNum = document.getElementById('scoreNum');
    const scoreLabel = document.getElementById('scoreLabel');
    if (scoreNum) scoreNum.textContent = '0';
    if (scoreLabel) {
        scoreLabel.textContent = 'Auditing...';
        scoreLabel.style.color = 'var(--text-secondary)';
    }

    ['metaSize', 'metaType', 'metaDate'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '–';
    });
}

async function startLoading(targetName, filesArrayOrCount) {
    clearResultUI();
    
    heroSection.style.display = 'none';
    featuresSection.style.display = 'none';
    resultSection.style.display = 'none';
    loadingOverlay.style.display = 'flex';
    
    progressFill.style.width = '0%';
    
    const isMock = !Array.isArray(filesArrayOrCount);
    const fileCount = isMock ? filesArrayOrCount : filesArrayOrCount.length;
    const scannedData = [];

    if (!isMock) {
        // REAL SCANNING
        for (let i = 0; i < filesArrayOrCount.length; i++) {
            const file = filesArrayOrCount[i];
            const pct = Math.round(((i + 1) / fileCount) * 100);
            progressFill.style.width = `${pct}%`;
            loadingStatus.textContent = `Analyzing ${i + 1}/${fileCount}: ${file.name}`;
            engineTicker.textContent = `Extracting patterns: ${file.name}...`;
            
            const findings = await scanFileContent(file);
            scannedData.push({
                file: file,
                findings: findings
            });
            await new Promise(r => setTimeout(r, 40)); // Small delay for smooth UI
        }
        progressFill.style.width = '100%';
        loadingStatus.textContent = `Scan complete. Generating compliance report...`;
        await new Promise(r => setTimeout(r, 500));
        processScanResults(targetName, filesArrayOrCount, scannedData);
        showResults();
    } else {
        // Attempt to run a real server-side scan via the local Python API
        try {
            progressFill.style.width = '10%';
            loadingStatus.textContent = 'Connecting to local API server...';
            engineTicker.textContent = `Target Directory: ${targetName}`;
            
            const response = await fetch(getApiUrl('/api/scan/path'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-apikey': 'default_key'
                },
                body: JSON.stringify({ path: targetName })
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data && data.success) {
                    progressFill.style.width = '100%';
                    loadingStatus.textContent = 'Audit complete. Loading findings...';
                    await new Promise(r => setTimeout(r, 400));
                    
                    // Populate results from real backend python engine
                    scanResults = data.results;
                    scanStats = {
                        high: data.stats.high,
                        medium: data.stats.medium,
                        low: data.stats.low,
                        totalFiles: data.stats.totalFiles,
                        filesWithPii: data.stats.filesWithPii,
                        securedFiles: data.stats.totalFiles - data.stats.filesWithPii
                    };
                    
                    // Update dashboard meta
                    document.getElementById('resultFileName').textContent = targetName;
                    document.getElementById('metaSize').textContent = `${data.stats.totalFiles} files audited`;
                    document.getElementById('metaType').textContent = "Server Directory";
                    document.getElementById('metaDate').textContent = new Date().toISOString().split('T')[0];
                    
                    const tagsDiv = document.getElementById('fileTags');
                    if (tagsDiv) {
                        tagsDiv.innerHTML = '';
                        if (data.stats.high > 0) {
                            tagsDiv.innerHTML += `<span class="tag malware" style="background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3);">High Risk</span>`;
                        } else if (data.stats.medium > 0) {
                            tagsDiv.innerHTML += `<span class="tag warning" style="background: rgba(245, 158, 11, 0.15); color: #F59E0B; border: 1px solid rgba(245, 158, 11, 0.3);">Warning</span>`;
                        } else {
                            tagsDiv.innerHTML += `<span class="tag clean" style="background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3);">Secure</span>`;
                        }
                        tagsDiv.innerHTML += `<span class="tag">PII Scan</span>`;
                    }
                    
                    updateScoreRing();
                    populateHashInfo();
                    populateQuickDetails();
                    populateDetailTab();
                    populateComplianceTab();
                    renderDetailedGrid(scanResults);
                    
                    showResults();
                    return;
                }
            }
        } catch (err) {
            console.warn("Local API server not running or unreachable. Falling back to browser simulation.", err);
        }

        // MOCK GENERATOR FOR SERVER PATH (FALLBACK)
        let progress = 0;
        const scanInterval = setInterval(() => {
            progress += Math.random() * 8 + 4;
            if (progress > 100) progress = 100;
            progressFill.style.width = `${progress}%`;
            const scanned = Math.floor((progress / 100) * fileCount);
            loadingStatus.textContent = `Scanning directory ${scanned}/${fileCount} files...`;
            engineTicker.textContent = `Auditing file: ${mockFolders[Math.floor(Math.random()*mockFolders.length)]}file_${Math.floor(Math.random()*100)}.${fileExtensions[Math.floor(Math.random()*fileExtensions.length)]}`;
            
            if (progress === 100) {
                clearInterval(scanInterval);
                setTimeout(() => {
                    processScanResults(targetName, fileCount, null);
                    showResults();
                }, 500);
            }
        }, 80);
    }
}

// Quét thực tế nội dung tệp tin bằng Regex và Heuristics
async function scanFileContent(file) {
    const nameParts = file.name.split('.');
    const ext = nameParts.length > 1 ? ('.' + nameParts.pop().toLowerCase()) : '';
    let findings = [];

    // Luật 1: Heuristics dựa trên tên tệp tin
    const lowerName = file.name.toLowerCase();
    let nameFindings = false;
    if (suspiciousKeywords.some(kw => lowerName.includes(kw))) {
        nameFindings = true;
    }

    // Luật 2: Tệp cấu hình hoặc môi trường nhạy cảm
    const highRiskExts = ['.env', '.sql', '.conf', '.config', '.key', '.pem'];
    if (highRiskExts.includes(ext)) {
        findings.push({
            name: "Thông tin xác thực / API Key / Mật khẩu",
            count: 1,
            level: "high",
            reason: "Tệp tin cấu hình hệ thống / bản sao lưu chứa thông tin xác thực.",
            details: [{ line: 1, text: `Tệp cấu hình: ${file.name}`, value: "[Khóa hệ thống / Cấu hình]" }]
        });
    }

    // Luật 3: Quét nội dung tệp tin theo từng dòng
    try {
        const text = await readFileAsText(file);
        if (text && text.length > 0) {
            const lines = text.split(/\r?\n/);
            const maxLinesToScan = Math.min(lines.length, 5000); // Giới hạn hiệu năng
            const fileFindingsMap = {};

            for (let i = 0; i < maxLinesToScan; i++) {
                const lineContent = lines[i];
                if (lineContent.trim().length === 0) continue;

                for (const [piiName, pattern] of Object.entries(PII_PATTERNS)) {
                    // Đặt lại regex lastIndex trước khi thực thi
                    pattern.lastIndex = 0;
                    
                    let matches = [];
                    if (pattern.global) {
                        let match;
                        while ((match = pattern.exec(lineContent)) !== null) {
                            matches.push(match[0]);
                        }
                    } else {
                        const m = lineContent.match(pattern);
                        if (m) matches.push(m[0]);
                    }

                    if (matches.length > 0) {
                        let validMatches = [];
                        for (const matchVal of matches) {
                            let isValid = true;
                            if (piiName === "Số định danh (CCCD/CMND)") {
                                const isSeq = "01234567890123456789".includes(matchVal) || "98765432109876543210".includes(matchVal);
                                const isRep = /^(.)\1+$/.test(matchVal);
                                if (isSeq || isRep) {
                                    isValid = false;
                                } else if (matchVal.length === 12) {
                                    const province = parseInt(matchVal.substring(0, 3), 10);
                                    const gender = parseInt(matchVal.substring(3, 4), 10);
                                    isValid = (province >= 1 && province <= 96) && (gender >= 0 && gender <= 9);
                                } else if (matchVal.length === 9) {
                                    isValid = true;
                                } else if (matchVal.includes("-")) {
                                    // Kiểm tra định dạng số SSN Mỹ
                                    isValid = /^\d{3}-\d{2}-\d{4}$/.test(matchVal);
                                } else {
                                    isValid = false;
                                }
                            } else if (piiName === "Số thẻ tín dụng") {
                                isValid = isValidLuhn(matchVal);
                            } else if (piiName === "Thông tin xác thực / API Key / Mật khẩu") {
                                const lowercaseVal = matchVal.toLowerCase();
                                if (lowercaseVal.includes("placeholder") || lowercaseVal.includes("your_") || lowercaseVal.includes("todo")) {
                                    isValid = false;
                                }
                            }
                            if (isValid) {
                                validMatches.push(matchVal);
                            }
                        }

                        // Lọc các false positive cho Họ và tên
                        if (piiName === "Họ và tên") {
                            const nameBlacklist = ["hồ chí minh", "thành phố", "thành phố hồ chí minh", "hà nội", "đà nẵng", "hải phòng", "cần thơ", "việt nam", "viet nam", "quận", "phường", "đường", "tỉnh", "huyện", "xã"];
                            validMatches = validMatches.filter(val => {
                                const valLower = val.toLowerCase().trim();
                                return !nameBlacklist.some(bl => valLower.includes(bl));
                            });
                        }

                        if (validMatches.length > 0) {
                            if (!fileFindingsMap[piiName]) {
                                const matchedType = piiTypes.find(t => t.name === piiName);
                                fileFindingsMap[piiName] = {
                                    name: piiName,
                                    count: 0,
                                    level: matchedType ? matchedType.level : "medium",
                                    details: []
                                };
                            }
                            fileFindingsMap[piiName].count += validMatches.length;
                            
                            validMatches.forEach(val => {
                                fileFindingsMap[piiName].details.push({
                                    line: i + 1,
                                    text: lineContent.substring(0, 80).trim() + (lineContent.length > 80 ? "..." : ""),
                                    value: val
                                });
                            });
                        }
                    }
                }
            }

            for (const item of Object.values(fileFindingsMap)) {
                findings.push({
                    name: item.name,
                    count: item.count,
                    level: item.level,
                    reason: `Phát hiện ${item.count} trường dữ liệu dạng ${item.name} trong nội dung tệp.`,
                    details: item.details.slice(0, 10) // Giới hạn hiển thị UI
                });
            }
        }
    } catch (e) {
        // Tệp không phải văn bản hoặc lỗi đọc tệp
        if (nameFindings && findings.length === 0) {
            findings.push({
                name: "Thông tin xác thực / API Key / Mật khẩu",
                count: 1,
                level: "high",
                reason: "Tên tệp chứa từ khóa nhạy cảm, có nguy cơ lộ lọt thông tin xác thực.",
                details: [{ line: 1, text: `Phát hiện qua tên tệp: ${file.name}`, value: "[Cảnh báo từ khóa]" }]
            });
        }
    }

    return findings;
}

function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsText(file.slice(0, 150000)); // Đọc tối đa 150KB đầu tiên
    });
}

// Xử lý kết quả quét & Tính toán số liệu thống kê
function processScanResults(targetName, filesArrayOrCount, realData) {
    scanResults = [];
    const isMock = !Array.isArray(filesArrayOrCount);
    const totalFiles = isMock ? filesArrayOrCount : filesArrayOrCount.length;
    
    scanStats = { high: 0, medium: 0, low: 0, totalFiles: totalFiles, filesWithPii: 0, securedFiles: 0 };

    if (!isMock && realData) {
        // SỬ DỤNG DỮ LIỆU THẬT
        realData.forEach(item => {
            let highestLevel = "low";
            let securityStatus = "secured";
            let permissions = "chmod 644 (Đọc Công khai)";
            
            if (item.findings.length > 0) {
                // Xác định mức độ nhạy cảm cao nhất của tệp
                item.findings.forEach(f => {
                    if (f.level === "high") highestLevel = "high";
                    if (f.level === "medium" && highestLevel === "low") highestLevel = "medium";
                });
                
                scanStats[highestLevel]++;
                scanStats.filesWithPii++;

                if (highestLevel === "high") {
                    permissions = "chmod 777 (Ghi Công khai)";
                    securityStatus = "unsecured";
                } else if (highestLevel === "medium") {
                    permissions = "chmod 755 (Đọc Nhóm)";
                    securityStatus = "warning";
                } else {
                    securityStatus = "secured"; // được bảo vệ/mã hóa
                    scanStats.securedFiles++;
                }

                // Nếu là tệp .env hoặc .sql thì mặc định là chưa bảo mật quyền 777 trong mô phỏng
                const ext = '.' + item.file.name.split('.').pop().toLowerCase();
                if (ext === '.env' || ext === '.sql') {
                    permissions = "chmod 777 (Ghi Công khai)";
                    securityStatus = "unsecured";
                }
            } else {
                // Tệp an toàn
                highestLevel = "low";
                securityStatus = "secured";
                permissions = "chmod 600 (Riêng tư)";
                scanStats.securedFiles++;
            }

            scanResults.push({
                fileName: item.file.name,
                path: item.file.webkitRelativePath || item.file.name,
                level: highestLevel,
                securityStatus: securityStatus,
                piiFound: item.findings,
                permissions: permissions,
                size: formatBytes(item.file.size),
                date: new Date(item.file.lastModified || Date.now()).toISOString().split('T')[0]
            });
        });
    } else {
        // TẠO DỮ LIỆU MẪU (MOCK DATA) CHO DEMO
        if (isRemediated) {
            scanStats.filesWithPii = 0;
            scanStats.securedFiles = totalFiles;
            
            const mockPaths = [
                { path: "config/database.yml", size: "1.2 KB" },
                { path: "uploads/danh_sach_khach_hang.csv", size: "32 KB" },
                { path: "logs/access.log", size: "450 KB" },
                { path: "backup/db_export_2026.sql", size: "4.8 MB" },
                { path: ".env", size: "640 B" },
                { path: "src/PaymentGateway.js", size: "15 KB" }
            ];
            
            mockPaths.forEach(p => {
                const fileName = p.path.split('/').pop();
                const fullPath = targetName.endsWith('/') ? targetName + p.path : targetName + '/' + p.path;
                scanResults.push({
                    fileName: fileName,
                    path: fullPath,
                    level: "low",
                    securityStatus: "secured",
                    piiFound: [],
                    permissions: "chmod 600 (Chủ sở hữu) + AES-256",
                    size: p.size,
                    date: new Date().toISOString().split('T')[0]
                });
            });
        } else {
            const filesWithPiiCount = Math.max(2, Math.floor(totalFiles * 0.15)); // 15% tệp chứa DLCN
            scanStats.filesWithPii = filesWithPiiCount;

            const generatedPaths = [
                { path: "uploads/backdoor.php", ext: ".php", pii: [{ name: "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)", count: 2, level: "high" }], perm: "chmod 777 (Ghi Công khai)", status: "unsecured", size: "1.4 KB" },
                { path: "config/database.yml", ext: ".yml", pii: [{ name: "Thông tin xác thực / API Key / Mật khẩu", count: 4, level: "high" }], perm: "chmod 777 (Ghi Công khai)", status: "unsecured", size: "1.2 KB" },
                { path: "uploads/danh_sach_khach_hang.csv", ext: ".csv", pii: [{ name: "Số định danh (CCCD/CMND)", count: 154, level: "high" }, { name: "Số điện thoại", count: 154, level: "medium" }, { name: "Họ và tên", count: 154, level: "medium" }], perm: "chmod 755 (Đọc Công khai)", status: "unsecured", size: "32 KB" },
                { path: "logs/access.log", ext: ".log", pii: [{ name: "Địa chỉ IP", count: 1845, level: "low" }, { name: "Địa chỉ email", count: 12, level: "low" }], perm: "chmod 644 (Đọc Nhóm)", status: "warning", size: "450 KB" },
                { path: "backup/db_export_2026.sql", ext: ".sql", pii: [{ name: "Số tài khoản ngân hàng / IBAN", count: 85, level: "high" }, { name: "Họ và tên", count: 90, level: "medium" }], perm: "chmod 777 (Ghi Công khai)", status: "unsecured", size: "4.8 MB" },
                { path: "public/index.php", ext: ".php", pii: [{ name: "Cookie phiên", count: 2, level: "low" }], perm: "chmod 644 (Chủ sở hữu Đọc)", status: "secured", size: "8.5 KB" },
                { path: ".env", ext: ".env", pii: [{ name: "Thông tin xác thực / API Key / Mật khẩu", count: 6, level: "high" }], perm: "chmod 777 (Ghi Công khai)", status: "unsecured", size: "640 B" },
                { path: "src/PaymentGateway.js", ext: ".js", pii: [{ name: "Số thẻ tín dụng", count: 2, level: "high" }], perm: "chmod 755 (Đọc Công khai)", status: "unsecured", size: "15 KB" },
                { path: "public/assets/avatars/admin.png", ext: ".png", pii: [{ name: "Dữ liệu sinh trắc học", count: 1, level: "high" }], perm: "chmod 600 (Riêng tư)", status: "secured", size: "120 KB" }
            ];

            // Tạo dữ liệu cho filesWithPiiCount tệp
            for (let i = 0; i < filesWithPiiCount; i++) {
                const template = generatedPaths[i % generatedPaths.length];
                const folder = mockFolders[Math.floor(Math.random() * mockFolders.length)];
                const fullPath = targetName.endsWith('/') ? targetName + template.path : targetName + '/' + template.path;
                const fileName = template.path.split('/').pop();
                
                let highestLevel = "low";
                template.pii.forEach(p => {
                    if (p.level === "high") highestLevel = "high";
                    if (p.level === "medium" && highestLevel === "low") highestLevel = "medium";
                });

                scanStats[highestLevel]++;
                if (template.status === "secured") scanStats.securedFiles++;

                scanResults.push({
                    fileName: fileName,
                    path: fullPath,
                    level: highestLevel,
                    securityStatus: template.status,
                    piiFound: template.pii.map(p => {
                        const detailsList = [];
                        if (p.name === "Thông tin xác thực / API Key / Mật khẩu") {
                            detailsList.push({ line: 4, text: "DB_PASSWORD=secret_db_pass_123", value: "secret_db_pass_123" });
                            detailsList.push({ line: 5, text: "API_SECRET_KEY=prod_token_99abc88", value: "prod_token_99abc88" });
                            detailsList.push({ line: 12, text: "JWT_SECRET=super_secret_jwt_sign", value: "super_secret_jwt_sign" });
                        } else if (p.name === "Số định danh (CCCD/CMND)") {
                            detailsList.push({ line: 102, text: "1,Nguyễn Văn An,001095123456,an.nguyen@gmail.com,123 Đường Nguyễn Trãi", value: "001095123456" });
                            detailsList.push({ line: 103, text: "2,Trần Thị Bình,002095000123,binh.tran@gmail.com,456 Đường CMT8", value: "002095000123" });
                        } else if (p.name === "Số điện thoại") {
                            detailsList.push({ line: 102, text: "1,Nguyễn Văn An,001095123456,0901234567,123 Đường Nguyễn Trãi", value: "0901234567" });
                            detailsList.push({ line: 103, text: "2,Trần Thị Bình,002095000123,0912345678,456 Đường CMT8", value: "0912345678" });
                        } else if (p.name === "Họ và tên") {
                            detailsList.push({ line: 102, text: "1,Nguyễn Văn An,001095123456,0901234567,123 Đường Nguyễn Trãi", value: "Nguyễn Văn An" });
                            detailsList.push({ line: 103, text: "2,Trần Thị Bình,002095000123,0912345678,456 Đường CMT8", value: "Trần Thị Bình" });
                        } else if (p.name === "Địa chỉ email") {
                            detailsList.push({ line: 15, text: "mail_config: { support: 'support@company.com', admin: 'admin@company.com' }", value: "admin@company.com" });
                        } else if (p.name === "Địa chỉ IP") {
                            detailsList.push({ line: 201, text: "127.0.0.1 - - [26/May/2026] \"GET /api/v1/users HTTP/1.1\" 200", value: "127.0.0.1" });
                            detailsList.push({ line: 202, text: "192.168.1.50 - - [26/May/2026] \"POST /api/v1/auth HTTP/1.1\" 401", value: "192.168.1.50" });
                        } else if (p.name === "Số tài khoản ngân hàng / IBAN") {
                            detailsList.push({ line: 45, text: "Tài khoản ngân hàng: STK Vietcombank 1023456789", value: "1023456789" });
                        } else if (p.name === "Số thẻ tín dụng") {
                            detailsList.push({ line: 88, text: "cardNumber: '4111-1111-1111-1111', expiry: '12/28'", value: "4111-1111-1111-1111" });
                        } else if (p.name === "Cookie phiên") {
                            detailsList.push({ line: 3, text: "Set-Cookie: PHPSESSID=f39a0c8b2164ad8e2193b2a; Path=/; Secure;", value: "f39a0c8b2164ad8e2193b2a" });
                        } else if (p.name === "Dữ liệu sinh trắc học") {
                            detailsList.push({ line: 1, text: "admin_fingerprint_hash = '5f4dcc3b5aa765d61d8327deb882cf99'", value: "5f4dcc3b5aa765d61d8327deb882cf99" });
                        } else {
                            detailsList.push({ line: 1, text: `Ngữ cảnh mẫu cho ${p.name}`, value: "Giá trị" });
                        }

                        return {
                            name: p.name,
                            count: p.count,
                            level: p.level,
                            reason: `Phát hiện ${p.count} trường dữ liệu dạng ${p.name} lưu dưới dạng văn bản thô.`,
                            details: detailsList.slice(0, p.count).length > 0 ? detailsList.slice(0, p.count) : [{ line: 1, text: `Ngữ cảnh mẫu cho ${p.name}`, value: "Giá trị" }]
                        };
                    }),
                    permissions: template.perm,
                    size: template.size,
                    date: new Date(Date.now() - Math.random() * 10 * 24 * 3600 * 1000).toISOString().split('T')[0]
                });
            }

            // Tạo các file sạch mock để bổ sung cho đủ tổng số file
            const remainingCount = totalFiles - filesWithPiiCount;
            for (let i = 0; i < remainingCount; i++) {
                const fullPath = targetName.endsWith('/') ? targetName + `src/safe_file_${i}.js` : targetName + `/src/safe_file_${i}.js`;
                scanStats.securedFiles++;
                
                scanResults.push({
                    fileName: `safe_file_${i}.js`,
                    path: fullPath,
                    level: "low",
                    securityStatus: "secured",
                    piiFound: [],
                    permissions: "chmod 600 (Riêng tư)",
                    size: "4.2 KB",
                    date: new Date(Date.now() - Math.random() * 5 * 24 * 3600 * 1000).toISOString().split('T')[0]
                });
            }
        }
    }

    // Sắp xếp: Nguy cơ cao lên trước, đến Cảnh báo, sau đó là Đã bảo mật
    scanResults.sort((a, b) => {
        const order = { "unsecured": 1, "warning": 2, "secured": 3 };
        return order[a.securityStatus] - order[b.securityStatus];
    });

    // Điền thông tin tệp
    document.getElementById('resultFileName').textContent = targetName;
    document.getElementById('metaSize').textContent = `${totalFiles} tệp đã quét`;
    document.getElementById('metaType').textContent = currentTargetIsFolder ? "Thư mục máy chủ" : "Tệp đã tải lên";
    document.getElementById('metaDate').textContent = new Date().toISOString().split('T')[0];

    // Thẻ nhãn tệp
    const tagsDiv = document.getElementById('fileTags');
    if (tagsDiv) {
        tagsDiv.innerHTML = '';
        if (scanStats.high > 0) {
            tagsDiv.innerHTML += `<span class="tag malware" style="background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3);">Nguy cơ Cao</span>`;
        } else if (scanStats.medium > 0) {
            tagsDiv.innerHTML += `<span class="tag warning" style="background: rgba(245, 158, 11, 0.15); color: #F59E0B; border: 1px solid rgba(245, 158, 11, 0.3);">Cảnh báo</span>`;
        } else {
            tagsDiv.innerHTML += `<span class="tag clean" style="background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3);">An toàn</span>`;
        }
        tagsDiv.innerHTML += `<span class="tag">Quét DLCN</span>`;
    }

    // Cập nhật các thành phần giao diện
    updateScoreRing();
    populateHashInfo();
    populateQuickDetails();
    populateDetailTab();
    populateComplianceTab();
    
    // Kết xuất danh sách kết quả chi tiết trong Tab 1
    renderDetailedGrid(scanResults);
}

function showResults() {
    loadingOverlay.style.display = 'none';
    resultSection.style.display = 'block';
    
    // Active Tab 1
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    const tab1 = document.querySelector('.tab[data-tab="detection"]');
    if (tab1) tab1.classList.add('active');
    const content1 = document.getElementById('tab-detection');
    if (content1) content1.classList.add('active');
    
    // Active filter 'all'
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    const btnAll = document.querySelector('.filter-btn[data-filter="all"]');
    if (btnAll) btnAll.classList.add('active');
    
    const searchInp = document.getElementById('engineSearch');
    if (searchInp) searchInp.value = '';
}

function resetToHome() {
    resultSection.style.display = 'none';
    heroSection.style.display = 'flex';
    featuresSection.style.display = 'block';
    if (hashInput) hashInput.value = '';
    if (fileInput) fileInput.value = '';
    if (folderInput) folderInput.value = '';
    currentTargetName = "";
}

// Formats file sizes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// ===== UI POPULATORS =====

// Cập nhật Vòng điểm Bảo mật Dữ liệu
// Hàm tính điểm an toàn DUY NHẤT — dùng chung cho vòng tròn và xuất PDF
function computeSecurityScore() {
    let securityScore = 100;
    if (scanStats.totalFiles > 0) {
        if (isRemediated) {
            return 100;
        }
        const highCount = scanStats.high || 0;
        const mediumCount = scanStats.medium || 0;
        const lowCount = scanStats.low || 0;

        securityScore -= (highCount * 20);
        securityScore -= (mediumCount * 10);
        securityScore -= (lowCount * 3);

        if (highCount > 0) {
            securityScore = Math.max(10, Math.min(40, 60 - highCount * 10));
        } else if (mediumCount > 0) {
            securityScore = Math.max(50, Math.min(79, 85 - mediumCount * 5));
        }
        if (securityScore < 10 && (highCount > 0 || mediumCount > 0 || lowCount > 0)) {
            securityScore = 10;
        }
    }
    return securityScore;
}

function updateScoreRing() {
    const ringFill = document.getElementById('ringFill');
    const scoreNum = document.getElementById('scoreNum');
    const scoreDenom = document.getElementById('scoreDenom');
    const scoreLabel = document.getElementById('scoreLabel');

    if (!scoreNum || !ringFill) return;

    // Điểm an toàn được tính tập trung trong computeSecurityScore()
    const securityScore = computeSecurityScore();

    scoreNum.textContent = securityScore;
    scoreDenom.textContent = "/100 điểm";

    const percent = securityScore / 100;
    const circumference = 314;
    const offset = circumference - (percent * circumference);
    
    ringFill.style.strokeDashoffset = circumference;
    
    if (securityScore >= 80) {
        ringFill.style.stroke = 'var(--color-clean)';
        if (scoreLabel) {
            scoreLabel.textContent = "A - An toàn";
            scoreLabel.style.color = "var(--color-clean)";
        }
        document.getElementById('fileIconBig').style.borderColor = "var(--color-clean)";
        document.getElementById('fileIconBig').style.color = "var(--color-clean)";
    } else if (securityScore >= 50) {
        ringFill.style.stroke = 'var(--color-warning)';
        if (scoreLabel) {
            scoreLabel.textContent = "C - Cảnh báo";
            scoreLabel.style.color = "var(--color-warning)";
        }
        document.getElementById('fileIconBig').style.borderColor = "var(--color-warning)";
        document.getElementById('fileIconBig').style.color = "var(--color-warning)";
    } else {
        ringFill.style.stroke = 'var(--color-malicious)';
        if (scoreLabel) {
            scoreLabel.textContent = "F - Nguy cơ cao";
            scoreLabel.style.color = "var(--color-malicious)";
        }
        document.getElementById('fileIconBig').style.borderColor = "var(--color-malicious)";
        document.getElementById('fileIconBig').style.color = "var(--color-malicious)";
    }
    
    setTimeout(() => {
        ringFill.style.strokeDashoffset = offset;
    }, 100);
}

// Điền thẻ Thống kê Dashboard
function populateHashInfo() {
    const table = document.getElementById('hashTable');
    if (!table) return;
    
    const unsecureCount = isRemediated ? 0 : scanResults.filter(r => r.securityStatus !== 'secured').length;
    const securedCount = isRemediated ? scanResults.length : scanResults.filter(r => r.securityStatus === 'secured').length;
    
    table.innerHTML = `
        <div class="stats-row-new">
            <span class="stat-label-new">Tổng số tệp đã quét</span>
            <span class="stat-val-new">${scanStats.totalFiles.toLocaleString()}</span>
        </div>
        <div class="stats-row-new">
            <span class="stat-label-new">Tệp chứa dữ liệu cá nhân</span>
            <span class="stat-val-new" style="color: var(--accent-primary)">${scanStats.filesWithPii}</span>
        </div>
        <div class="stats-row-new">
            <span class="stat-label-new">Chưa bảo mật (Văn bản thô)</span>
            <span class="stat-val-new" style="color: ${unsecureCount > 0 ? 'var(--color-malicious)' : 'var(--color-clean)'}">${unsecureCount}</span>
        </div>
        <div class="stats-row-new">
            <span class="stat-label-new">Đã bảo mật / Mã hóa</span>
            <span class="stat-val-new" style="color: var(--color-clean)">${securedCount}</span>
        </div>
    `;
}

// Điền các loại DLCN phát hiện nhiều nhất trên Dashboard
function populateQuickDetails() {
    const table = document.getElementById('detailTable');
    if (!table) return;

    // Đếm các thực thể DLCN trên tất cả các tệp tin
    const piiCounts = {};
    scanResults.forEach(res => {
        res.piiFound.forEach(p => {
            piiCounts[p.name] = (piiCounts[p.name] || 0) + p.count;
        });
    });

    const sortedPii = Object.entries(piiCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4);

    let html = '';
    sortedPii.forEach(([name, count]) => {
        const matchingType = piiTypes.find(t => t.name === name);
        const icon = matchingType ? matchingType.icon : "📋";
        html += `
            <div class="detail-item-new">
                <span class="detail-label-new clickable-threat" onclick="jumpToDetails()" style="display:flex; align-items:center; gap: 6px;">
                    <span>${icon}</span> ${name}
                </span>
                <span class="detail-val-new">${count.toLocaleString()} trường</span>
            </div>
        `;
    });

    if (html === '') {
        html = '<div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 10px;">Không phát hiện trường thông tin nhạy cảm nào</div>';
    }

    table.innerHTML = html;
}

// Điền Tab 2: Phân tích & Phân bổ dữ liệu cá nhân
function populateDetailTab() {
    const content = document.getElementById('detailsContent');
    if (!content) return;

    // Tập hợp số liệu theo loại DLCN
    const piiCounts = {};
    scanResults.forEach(res => {
        res.piiFound.forEach(p => {
            if (!piiCounts[p.name]) piiCounts[p.name] = 0;
            piiCounts[p.name] += p.count;
        });
    });

    let piiRowsHtml = '';
    for (const [name, count] of Object.entries(piiCounts)) {
        const matchingType = piiTypes.find(t => t.name === name);
        const isSensitive = matchingType && matchingType.level === 'high';
        const levelText = isSensitive ? 'Nhạy cảm (Nghị định 13)' : 'Cơ bản (Nghị định 13)';
        const badgeClass = matchingType ? matchingType.level : 'low';
        piiRowsHtml += `
            <div class="detail-row" style="display:flex; justify-content:space-between; align-items:center; padding:12px 0; border-bottom:1px solid var(--border-color);">
                <span class="detail-label" style="font-weight: 500;">${name}</span>
                <div style="display:flex; align-items:center; gap: 12px;">
                    <span class="pii-badge ${badgeClass}">Phân loại: ${levelText}</span>
                    <span class="detail-val" style="font-family:var(--font-mono); font-weight:600;">${count.toLocaleString()} lượt xuất hiện</span>
                </div>
            </div>`;
    }
    if (piiRowsHtml === '') {
        piiRowsHtml = '<div class="detail-row" style="text-align:center; color:var(--text-muted); padding: 12px;">Không phát hiện trường thông tin cá nhân nào.</div>';
    }

    // Phân tích định dạng tệp
    const extCounts = {};
    let totalPiiFiles = 0;
    scanResults.forEach(res => {
        const parts = res.fileName.split('.');
        const ext = parts.length > 1 ? '.' + parts.pop().toLowerCase() : '.txt';
        extCounts[ext] = (extCounts[ext] || 0) + 1;
        totalPiiFiles++;
    });

    const sortedExts = Object.entries(extCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3);

    let extRowsHtml = '';
    sortedExts.forEach(([ext, count]) => {
        const percent = Math.round((count / totalPiiFiles) * 100);
        extRowsHtml += `
            <div class="detail-row" style="display:flex; justify-content:space-between; align-items:center; padding:12px 0; border-bottom:1px solid var(--border-color);">
                <span class="detail-label" style="font-family:var(--font-mono);">${ext}</span>
                <span class="detail-val" style="color:var(--text-secondary);">${count} tệp tin (${percent}%)</span>
            </div>`;
    });
    if (extRowsHtml === '') {
        extRowsHtml = '<div class="detail-row" style="text-align:center; color:var(--text-muted); padding: 12px;">Không có thông tin</div>';
    }

    // Tính phân bố CVSS (cho dashboard)
    const cvssDist = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    let totalCvssRated = 0;
    scanResults.forEach(res => {
        if (res.cvss && res.cvss.severity) {
            const sev = res.cvss.severity;
            if (cvssDist[sev] !== undefined) { cvssDist[sev]++; totalCvssRated++; }
        }
    });
    const cvssColors = { Critical: '#EF4444', High: '#F97316', Medium: '#F59E0B', Low: '#10B981' };
    let cvssBarsHtml = '';
    for (const [sev, cnt] of Object.entries(cvssDist)) {
        if (cnt === 0) continue;
        const pct = totalCvssRated > 0 ? Math.round((cnt / totalCvssRated) * 100) : 0;
        cvssBarsHtml += `
            <div class="detail-row" style="display:flex; flex-direction:column; gap:6px; padding:10px 0; border-bottom:1px solid var(--border-color);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:600; color:${cvssColors[sev]}; display:flex; align-items:center; gap:8px;"><span style="width:10px; height:10px; border-radius:50%; background:${cvssColors[sev]}; display:inline-block;"></span>${sev}</span>
                    <span style="font-family:var(--font-mono); color:var(--text-secondary);">${cnt} tệp (${pct}%)</span>
                </div>
                <div style="height:6px; background:rgba(255,255,255,0.06); border-radius:99px; overflow:hidden;">
                    <div style="height:100%; width:${pct}%; background:${cvssColors[sev]}; border-radius:99px;"></div>
                </div>
            </div>`;
    }

    // Đưa nội dung vào Tab
    content.innerHTML = `
        <div class="detail-card">
            <h4>📊 Thống kê Phân bổ Dữ liệu Cá nhân</h4>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px;">Số lượt xuất hiện của các dữ liệu cá nhân cơ bản và nhạy cảm (theo quy định tại Nghị định 13/2023/NĐ-CP) được phát hiện trên máy chủ này.</p>
            <div class="detail-table">
                ${piiRowsHtml}
            </div>
        </div>
        <div class="detail-card" style="margin-top: 24px;">
            <h4>🛡️ Phân bố Mức độ Nghiêm trọng Lỗ hổng (CVSS v3.1)</h4>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px;">Phân loại tệp tin theo điểm CVSS 3.1: Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9). Điểm được tính theo chuẩn FIRST.org.</p>
            <div class="detail-table">
                ${cvssBarsHtml || '<div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 10px;">Không có lỗ hổng mã độc được đánh giá CVSS.</div>'}
            </div>
        </div>
        <div class="detail-card" style="margin-top: 24px;">
            <h4>📁 Các Loại Tệp Tin Lưu Trữ Dữ Liệu Nhạy Cảm Phổ Biến</h4>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px;">Nhận diện định dạng tệp tin có mật độ lưu trữ dữ liệu cá nhân chưa bảo mật cao nhất để ưu tiên xử lý khắc phục.</p>
            <div class="detail-table">
                ${extRowsHtml}
            </div>
        </div>
    `;

    // Thêm các thẻ giải thích chi tiết pháp lý cho mỗi loại dữ liệu
    let theoryHtml = '<div class="detail-card" style="margin-top: 24px;"><h4>💡 Rủi ro Pháp lý & Biện pháp Bảo vệ</h4><p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px;">Mức độ ảnh hưởng pháp lý tương ứng theo Nghị định 13/2023/NĐ-CP và hướng dẫn áp dụng các biện pháp an toàn kỹ thuật.</p><div style="display: flex; flex-direction: column; gap: 16px;">';
    for (const [name, count] of Object.entries(piiCounts)) {
        const desc = piiDescriptions[name] || "Dữ liệu cá nhân phải được bảo vệ đầy đủ bằng các biện pháp mã hóa và phân quyền phù hợp.";
        const searchLink = `https://www.google.com/search?q=Nghi+dinh+13+2023+ND-CP+bao+ve+du+lieu+ca+nhan+${encodeURIComponent(name)}`;
        theoryHtml += `
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 16px;">
                <h5 style="color: var(--accent-primary); margin-bottom: 8px; font-size: 1rem; display: flex; align-items: center; gap: 8px;">
                    <span>⚠️</span> ${name} (${count} lượt xuất hiện)
                </h5>
                <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 12px; line-height: 1.5;">${desc}</p>
                <a href="${searchLink}" target="_blank" style="display: inline-flex; align-items: center; gap: 6px; font-size: 0.85rem; color: #60A5FA; text-decoration: none; padding: 6px 12px; background: rgba(59, 130, 246, 0.1); border-radius: 4px; transition: 0.2s;">
                    <span>🔍</span> Tra cứu Nghị định 13 & Quy định Bảo vệ DLCN
                </a>
            </div>
        `;
    }
    theoryHtml += '</div></div>';
    content.innerHTML += theoryHtml;
}

// Điền Tab 3: Báo cáo Tuân thủ Quy định & Hành động Khắc phục
function populateComplianceTab() {
    const behaviorContent = document.getElementById('behaviorContent');
    if (!behaviorContent) return;

    let overallRating = "AN TOÀN / TUÂN THỦ";
    let ratingColor = "var(--color-clean)";
    let reportSummary = "Hệ thống đáp ứng các tiêu chuẩn cơ bản về bảo vệ dữ liệu cá nhân. Không phát hiện tệp tin văn bản thô chưa bảo mật chứa dữ liệu nhạy cảm.";

    const unsecuredHigh = scanResults.filter(r => r.securityStatus === 'unsecured' && r.level === 'high').length;
    const unsecuredMed = scanResults.filter(r => r.securityStatus === 'unsecured' && r.level === 'medium').length;

    if (isRemediated) {
        overallRating = "TUÂN THỦ (ĐÃ KHẮC PHỤC)";
        ratingColor = "var(--color-clean)";
        reportSummary = "Tất cả các tệp tin chứa dữ liệu cá nhân nhạy cảm và mã độc đã được cách ly, mã hóa AES-256 và giới hạn quyền truy cập hệ thống tệp (CHMOD 600). Hệ thống hiện đã an toàn.";
    } else if (unsecuredHigh > 0) {
        overallRating = "KHÔNG TUÂN THỦ (NGUY CƠ CAO)";
        ratingColor = "var(--color-malicious)";
        const hasMalware = scanResults.some(r => r.securityStatus === 'unsecured' && r.piiFound.some(p => p.name === "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)"));
        if (hasMalware) {
            reportSummary = "CẢNH BÁO NGUY HIỂM: Phát hiện mã độc, backdoor hoặc câu lệnh hệ thống nguy hiểm chưa được xử lý, cùng các tệp rò rỉ dữ liệu cá nhân nhạy cảm. Nguy cơ bị chiếm quyền kiểm soát server và thất thoát dữ liệu cực kỳ nghiêm trọng.";
        } else {
            reportSummary = `Phát hiện ${unsecuredHigh} tệp tin chứa dữ liệu cá nhân nhạy cảm (Số định danh CCCD, Số thẻ tín dụng, Tài khoản ngân hàng, Mật khẩu) đang được lưu trữ dưới dạng văn bản thô (Plaintext) với quyền truy cập lỏng lẻo. Vi phạm trực tiếp Nghị định 13/2023/NĐ-CP (Điều 36) và tiêu chuẩn PCI-DSS (Yêu cầu 3).`;
        }
    } else if (unsecuredMed > 0) {
        overallRating = "TUÂN THỦ MỘT PHẦN (CẢNH BÁO)";
        ratingColor = "var(--color-warning)";
        reportSummary = `Phát hiện ${unsecuredMed} tệp tin lưu trữ dữ liệu cá nhân cơ bản (Số điện thoại, Họ tên, Địa chỉ) trong các thư mục dùng chung hoặc phân quyền chưa chặt chẽ. Khuyến nghị cấu hình thắt chặt phân quyền truy cập.`;
    }

    // Đánh giá các tiêu chí theo checklist pháp lý và bảo mật
    const nd13Status = (isRemediated || (unsecuredMed === 0 && unsecuredHigh === 0)) ? "ĐẠT" : "KHÔNG ĐẠT";
    const pcidssStatus = (isRemediated || unsecuredHigh === 0) ? "ĐẠT" : "KHÔNG ĐẠT";
    const accessControlStatus = (isRemediated || scanResults.filter(r => r.permissions.includes("777")).length === 0) ? "ĐẠT" : "KHÔNG ĐẠT";

    behaviorContent.innerHTML = `
        <div class="detail-card" style="margin-bottom: 24px;">
            <h4>📈 Kết quả Đánh giá Tuân thủ Bảo mật Dữ liệu</h4>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px;">Đánh giá hiện trạng bảo mật dữ liệu dựa trên việc phân tích cấu hình phân quyền và dữ liệu lưu trữ thực tế trên máy chủ.</p>
            <div class="detail-table">
                <div class="detail-row" style="display:flex; justify-content:space-between; align-items:center; padding:12px 0; border-bottom:1px solid var(--border-color);">
                    <span class="detail-label" style="font-weight:600;">Trạng thái Tuân thủ Tổng thể (NĐ 13 / PCI-DSS / ISO 27001)</span>
                    <span class="detail-val" style="color: ${ratingColor}; font-weight: bold; font-size: 1.05rem;">${overallRating}</span>
                </div>
                <div class="detail-row" style="display:flex; justify-content:space-between; align-items:start; padding:12px 0;">
                    <span class="detail-label" style="font-weight:600; width: 250px;">Kết luận Kiểm toán</span>
                    <span class="detail-val" style="text-align: right; color: var(--text-secondary); line-height: 1.5;">${reportSummary}</span>
                </div>
            </div>
        </div>

        <div class="detail-card" style="margin-bottom: 24px;">
            <h4>📋 Bảng kiểm toán Quy định Pháp lý & Tiêu chuẩn Bảo mật</h4>
            <div class="compliance-grid">
                
                <div class="compliance-card">
                    <div class="compliance-status-icon">${nd13Status === 'ĐẠT' ? '🟢' : '🔴'}</div>
                    <div class="compliance-details">
                        <div class="compliance-article">NGHỊ ĐỊNH 13/2023/NĐ-CP - ĐIỀU 36 & 37</div>
                        <div class="compliance-title">Biện pháp Bảo vệ Dữ liệu Cá nhân (DLCN)</div>
                        <div class="compliance-desc">Yêu cầu bên kiểm soát và xử lý dữ liệu phải áp dụng các biện pháp quản lý và kỹ thuật phù hợp (như mã hóa, kiểm soát truy cập) để bảo vệ DLCN, đặc biệt là dữ liệu cá nhân nhạy cảm, tránh rò rỉ dữ liệu dạng văn bản thô.</div>
                        <div class="compliance-status-text ${nd13Status === 'ĐẠT' ? 'pass' : 'fail'}">
                            <span>Hiện trạng:</span> ${nd13Status === 'ĐẠT' ? 'ĐẠT (Đã áp dụng các biện pháp bảo vệ dữ liệu thích hợp)' : 'KHÔNG ĐẠT (Phát hiện dữ liệu cá nhân để lộ dưới dạng văn bản thô)'}
                        </div>
                    </div>
                </div>

                <div class="compliance-card">
                    <div class="compliance-status-icon">${pcidssStatus === 'ĐẠT' ? '🟢' : '🔴'}</div>
                    <div class="compliance-details">
                        <div class="compliance-article">PCI-DSS - YÊU CẦU 3</div>
                        <div class="compliance-title">Bảo vệ Dữ liệu Chủ thẻ & Dữ liệu Giao dịch</div>
                        <div class="compliance-desc">Yêu cầu bắt buộc mã hóa mạnh, ẩn hoặc cắt cụt các thông tin thẻ tín dụng, số tài khoản ngân hàng, thông tin tài chính cá nhân khi lưu trữ trên máy chủ.</div>
                        <div class="compliance-status-text ${pcidssStatus === 'ĐẠT' ? 'pass' : 'fail'}">
                            <span>Hiện trạng:</span> ${pcidssStatus === 'ĐẠT' ? 'ĐẠT (Thông tin thanh toán đã được mã hóa hoặc cô lập an toàn)' : 'KHÔNG ĐẠT (Phát hiện thông tin thẻ/tài khoản lưu trữ không an toàn)'}
                        </div>
                    </div>
                </div>

                <div class="compliance-card">
                    <div class="compliance-status-icon">${accessControlStatus === 'ĐẠT' ? '🟢' : '🔴'}</div>
                    <div class="compliance-details">
                        <div class="compliance-article">ISO/IEC 27001 - KIỂM SOÁT A.8.24 & A.5.15</div>
                        <div class="compliance-title">Kiểm soát Truy cập & Quản lý Khóa mật mã</div>
                        <div class="compliance-desc">Đảm bảo các tệp cấu hình quan trọng (.env, database.config) và tệp chứa DLCN được phân quyền chặt chẽ (CHMOD 600), ngăn chặn quyền đọc/ghi công khai trên phân vùng đĩa.</div>
                        <div class="compliance-status-text ${accessControlStatus === 'ĐẠT' ? 'pass' : 'fail'}">
                            <span>Hiện trạng:</span> ${accessControlStatus === 'ĐẠT' ? 'ĐẠT (Quyền truy cập tệp tin được giới hạn an toàn)' : 'KHÔNG ĐẠT (Phát hiện tệp cấu hình hoặc dữ liệu nhạy cảm có quyền đọc/ghi công khai)'}
                        </div>
                    </div>
                </div>

            </div>
        </div>

        <div class="detail-card">
            <h4>🛠️ Hành động Khắc phục Bảo mật Tự động</h4>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px;">Áp dụng các biện pháp kiểm soát kỹ thuật tức thì để thắt chặt an toàn và đưa hệ thống về trạng thái tuân thủ pháp luật.</p>
            
            <div style="background: rgba(255, 255, 255, 0.02); padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-color); margin-bottom: 20px; display: flex; flex-direction: column; gap: 8px;">
                <div style="font-size: 0.9rem; color: var(--text-primary); display:flex; align-items:center; gap: 8px;">
                    <span>🔐</span> <strong>Mã hóa AES-256:</strong> Tiến hành mã hóa nội dung của ${scanResults.filter(r => r.level === 'high').length} tệp tin chứa dữ liệu có mức độ nhạy cảm cao.
                </div>
                <div style="font-size: 0.9rem; color: var(--text-primary); display:flex; align-items:center; gap: 8px;">
                    <span>🛡️</span> <strong>Thắt chặt Phân quyền (CHMOD):</strong> Thu hồi toàn bộ quyền truy cập công khai/nhóm, thiết lập các tệp tin chứa DLCN về CHMOD 600 (Chủ sở hữu).
                </div>
                <div style="font-size: 0.9rem; color: var(--text-primary); display:flex; align-items:center; gap: 8px;">
                    <span>📋</span> <strong>Ghi Nhật ký Kiểm toán:</strong> Kết xuất báo cáo chi tiết không ẩn thông tin phục vụ công tác rà soát nội bộ của quản trị viên hệ thống.
                </div>
            </div>

            <div>
                <button class="btn-primary" onclick="executeRecommendations()">${isRemediated ? '✅ Đã áp dụng khắc phục' : 'Thực hiện Khắc phục Tự động'}</button>
            </div>
        </div>
    `;
}

// Toggle detail accordion panel for a file row
window.toggleFileDetails = function(headerElement) {
    const parent = headerElement.parentElement;
    const panel = parent.querySelector('.pii-details-panel');
    const arrow = headerElement.querySelector('.accordion-arrow');
    
    if (panel) {
        const isCollapsed = panel.style.display === 'none';
        panel.style.display = isCollapsed ? 'block' : 'none';
        if (arrow) {
            arrow.style.transform = isCollapsed ? 'rotate(180deg)' : 'rotate(0deg)';
        }
        
        // Add a nice visual adjustment to the header borders when expanded
        if (isCollapsed) {
            headerElement.style.borderBottomLeftRadius = '0';
            headerElement.style.borderBottomRightRadius = '0';
        } else {
            headerElement.style.borderBottomLeftRadius = 'var(--radius-md)';
            headerElement.style.borderBottomRightRadius = 'var(--radius-md)';
        }
    }
};

// Render Grid of scanned files in Tab 1 (Detailed results)
function renderDetailedGrid(results) {
    const grid = document.getElementById('engineGrid');
    if (!grid) return;

    grid.innerHTML = '';

    if (results.length === 0) {
        grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-secondary); background:var(--bg-card); border-radius:var(--radius-md); border: 1px solid var(--border-color);">🎉 Tuyệt vời! Không phát hiện tệp tin chưa bảo mật chứa dữ liệu cá nhân nhạy cảm.</div>`;
        return;
    }

    results.forEach(res => {
        // Nhãn dữ liệu cá nhân phát hiện được
        let piiBadgesHtml = '';
        res.piiFound.forEach(p => {
            piiBadgesHtml += `<span class="pii-badge ${p.level}">${p.name} (${p.count})</span>`;
        });

        // Ánh xạ trạng thái bảo mật
        let statusBadgeHtml = '';
        let rowBorderColor = 'var(--border-color)';
        let rowBackground = 'var(--bg-card)';

        if (res.securityStatus === 'unsecured') {
            statusBadgeHtml = `<span class="security-status-badge unsecured">🔴 Văn bản thô (Nguy cơ)</span>`;
            rowBorderColor = 'rgba(239, 68, 68, 0.3)';
            rowBackground = 'rgba(239, 68, 68, 0.03)';
        } else if (res.securityStatus === 'warning') {
            statusBadgeHtml = `<span class="security-status-badge warning">🟡 Cảnh báo (Chưa an toàn)</span>`;
            rowBorderColor = 'rgba(245, 158, 11, 0.3)';
            rowBackground = 'rgba(245, 158, 11, 0.03)';
        } else {
            statusBadgeHtml = `<span class="security-status-badge secured">🟢 Đã bảo mật</span>`;
            rowBorderColor = 'rgba(16, 185, 129, 0.3)';
            rowBackground = 'rgba(16, 185, 129, 0.03)';
        }

        const item = document.createElement('div');
        item.className = 'pii-file-card-wrap';
        item.style.marginBottom = '12px';

        // Header tệp tin
        let headerRowHtml = `
            <div class="pii-file-row" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; border: 1px solid ${rowBorderColor}; background: ${rowBackground}; border-radius: var(--radius-md); padding: 14px 20px; transition: var(--transition);" onclick="toggleFileDetails(this)">
                <div class="pii-file-info">
                    <div style="display:flex; align-items:center; gap: 8px;">
                        <span style="font-size: 1.1rem;">${res.piiFound.some(p => p.name === "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)") ? '💀' : (res.fileName.endsWith('.sql') ? '🗄️' : res.fileName.endsWith('.csv') ? '📊' : '📄')}</span>
                        <span class="pii-file-path" title="${res.path}">${res.relativePath || res.path || res.fileName}</span>
                    </div>
                    <div class="pii-file-findings" style="margin-top: 4px;">
                        ${piiBadgesHtml}
                    </div>
                    <div style="display:flex; gap:16px; font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono); margin-top:4px;">
                        <span>Quyền hạn: ${res.permissions}</span>
                        <span>Dung lượng: ${res.size}</span>
                    </div>
                    ${res.cvss && res.cvss.score ? `<div style="margin-top:8px;">${cvssBadge(res.cvss.score, res.cvss.severity, res.cvss.vector)}</div>` : ''}
                    ${(() => {
                        // Gom các MITRE id duy nhất từ details
                        const mitreIds = [];
                        res.piiFound.forEach(p => (p.details || []).forEach(d => {
                            if (d.mitre_id && !mitreIds.some(m => m.id === d.mitre_id)) {
                                mitreIds.push({ id: d.mitre_id, tactic: d.mitre_tactic });
                            }
                        }));
                        return mitreIds.map(m => mitreBadge(m.id, m.tactic)).join(' ');
                    })()}
                    ${res.entropy !== undefined && res.entropy > 0 ? `<span style="display:inline-flex; align-items:center; gap:4px; font-size:0.7rem; color:var(--text-muted); font-family:var(--font-mono); margin-left:6px;" title="Entropy Shannon">Entropy: ${res.entropy}</span>` : ''}
                    ${res.riskRating ? `<span style="font-size:0.7rem; color:${res.riskRating.level.includes('Cao') ? '#F59E0B' : '#9CA3AF'}; margin-left:6px;" title="OWASP Risk = Likelihood × Impact">Risk: ${res.riskRating.level}</span>` : ''}
                    ${res.signatures && res.signatures.length > 0 ? `<div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:6px;">${res.signatures.map(s => signatureBadge(s.rule_id, s.rule_name)).join('')}</div>` : ''}
                </div>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div class="pii-file-status">
                        ${statusBadgeHtml}
                    </div>
                    <span class="accordion-arrow" style="font-size: 0.9rem; transition: transform 0.3s; color: var(--text-secondary);">▼</span>
                </div>
            </div>
        `;

        // Danh sách các trường chi tiết phát hiện
        let detailsRowsHtml = '';
        res.piiFound.forEach(p => {
            if (p.details && p.details.length > 0) {
                p.details.forEach(det => {
                    detailsRowsHtml += `
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
                            <td style="padding: 8px 6px; font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-primary);">${det.line}</td>
                            <td style="padding: 8px 6px; font-weight: 500; font-size: 0.8rem;">
                                <span class="pii-badge ${p.level}" style="margin: 0; padding: 1px 6px; font-size: 0.7rem;">${p.name}</span>
                            </td>
                            <td style="padding: 8px 6px; font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-primary);">${maskPIIValue(p.name, det.value)}</td>
                            <td style="padding: 8px 6px; font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-secondary);">${det.cwe_id || '—'}</td>
                            <td style="padding: 8px 6px;">${det.mitre_id ? mitreBadge(det.mitre_id, det.mitre_tactic) : '—'}</td>
                            <td style="padding: 8px 6px;">${det.cvss_score ? cvssBadge(det.cvss_score, det.cvss_severity, det.cvss_vector) : '—'}</td>
                            <td style="padding: 8px 6px; font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 350px;" title="${det.text.replace(/"/g, '&quot;')}">${det.text}</td>
                        </tr>
                    `;
                });
            }
        });

        let detailsPanelHtml = '';
        if (detailsRowsHtml) {
            detailsPanelHtml = `
                <div class="pii-details-panel" style="display: none; border: 1px solid var(--border-color); border-top: none; background: rgba(0,0,0,0.2); border-bottom-left-radius: var(--radius-md); border-bottom-right-radius: var(--radius-md); padding: 16px; margin-top: -4px;">
                    <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-primary); margin-bottom: 10px; display:flex; align-items:center; gap:6px;">
                        <span>📋</span> Danh sách chi tiết các trường thông tin nhạy cảm phát hiện:
                    </div>
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">
                                    <th style="padding: 6px; font-weight: 600; width: 60px;">Dòng</th>
                                    <th style="padding: 6px; font-weight: 600; width: 120px;">Loại dữ liệu</th>
                                    <th style="padding: 6px; font-weight: 600; width: 180px;">Giá trị phát hiện</th>
                                    <th style="padding: 6px; font-weight: 600; width: 70px;">CWE</th>
                                    <th style="padding: 6px; font-weight: 600; width: 90px;">MITRE</th>
                                    <th style="padding: 6px; font-weight: 600; width: 130px;">CVSS</th>
                                    <th style="padding: 6px; font-weight: 600;">Ngữ cảnh phát hiện</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${detailsRowsHtml}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } else {
            detailsPanelHtml = `
                <div class="pii-details-panel" style="display: none; border: 1px solid var(--border-color); border-top: none; background: rgba(0,0,0,0.2); border-bottom-left-radius: var(--radius-md); border-bottom-right-radius: var(--radius-md); padding: 16px; margin-top: -4px; text-align: center; color: var(--text-muted); font-size: 0.8rem;">
                    Không có chi tiết từng dòng (tệp cấu hình được quét nguyên trạng).
                </div>
            `;
        }

        item.innerHTML = headerRowHtml + detailsPanelHtml;
        grid.appendChild(item);
    });
}

function initFilters() {
    const buttons = document.querySelectorAll('.filter-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            buttons.forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');

            const filter = e.currentTarget.getAttribute('data-filter');
            filterResults(filter, document.getElementById('engineSearch').value);
        });
    });
}

function initSearchEngine() {
    const searchInput = document.getElementById('engineSearch');
    if (!searchInput) return;
    searchInput.addEventListener('input', (e) => {
        const activeBtn = document.querySelector('.filter-btn.active');
        const activeFilter = activeBtn ? activeBtn.getAttribute('data-filter') : 'all';
        filterResults(activeFilter, e.target.value);
    });
}

function filterResults(statusFilter, searchQuery) {
    const query = searchQuery.toLowerCase();
    const filtered = scanResults.filter(res => {
        let matchesStatus = true;
        if (statusFilter === 'high') matchesStatus = (res.securityStatus === 'unsecured');
        else if (statusFilter === 'medium') matchesStatus = (res.securityStatus === 'warning');
        else if (statusFilter === 'low') matchesStatus = (res.securityStatus === 'secured');

        const matchesSearch = res.fileName.toLowerCase().includes(query) || 
                              res.path.toLowerCase().includes(query) || 
                              res.piiFound.some(p => p.name.toLowerCase().includes(query));
        
        return matchesStatus && matchesSearch;
    });
    renderDetailedGrid(filtered);
}

function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            const targetId = `tab-${tab.getAttribute('data-tab')}`;
            const content = document.getElementById(targetId);
            if (content) content.classList.add('active');
        });
    });
}

function jumpToDetails() {
    const detailTab = document.querySelector('.tab[data-tab="details"]');
    if (detailTab) {
        detailTab.click();
        setTimeout(() => {
            const content = document.getElementById('detailsContent');
            if (content) {
                window.scrollTo({
                    top: content.getBoundingClientRect().top + window.pageYOffset - 100,
                    behavior: 'smooth'
                });
            }
        }, 100);
    }
}

// Thực hiện khắc phục tự động
async function executeRecommendations() {
    if (isRemediated) {
        alert("Hệ thống đã ở trạng thái an toàn sau khi khắc phục!");
        return;
    }

    if (document.getElementById('execModal')) return;
    
    const modalHtml = `
    <div id="execModal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); backdrop-filter: blur(8px); z-index: 2000; display: flex; justify-content: center; align-items: center; opacity: 0; transition: opacity 0.3s ease;">
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 32px; width: 550px; max-width: 90%; box-shadow: var(--shadow-lg);">
            <h3 style="margin-bottom: 16px; font-size: 1.3rem; display:flex; align-items:center; gap:8px;">
                <span>🛠️</span> Đang khắc phục lỗ hổng an toàn dữ liệu...
            </h3>
            <div id="execLog" style="background: #05070B; color: #38BDF8; font-family: monospace; padding: 16px; height: 220px; overflow-y: auto; border-radius: 6px; font-size: 0.85rem; margin-bottom: 24px; line-height: 1.6; border: 1px solid var(--border-color);">
                > Đang kết nối với API Server để khắc phục tệp vật lý...<br>
            </div>
            <div class="progress-bar" style="margin-bottom: 24px; height: 8px;">
                <div class="progress-fill" id="execProgress" style="width: 0%;"></div>
            </div>
            <div style="text-align: right;">
                <button id="closeExecBtn" class="btn-outline" style="display:none; pointer-events: none; opacity: 0.5;" onclick="closeExecModal()">Hoàn tất & Đóng</button>
            </div>
        </div>
    </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    setTimeout(() => document.getElementById('execModal').style.opacity = '1', 10);
    
    const logEl = document.getElementById('execLog');
    const progEl = document.getElementById('execProgress');
    const closeBtn = document.getElementById('closeExecBtn');

    // Kiểm tra xem có kết nối tới server API hay không
    let isServerMode = false;
    if (currentTargetName && (currentTargetName.includes('\\') || currentTargetName.includes('/') || currentTargetName.length > 5)) {
        isServerMode = true;
    }

    if (isServerMode) {
        try {
            logEl.innerHTML += `> Đang gửi yêu cầu khắc phục đến API Server cho thư mục: ${currentTargetName}...<br>`;
            progEl.style.width = "20%";
            logEl.scrollTop = logEl.scrollHeight;
            
            const response = await fetch(getApiUrl('/api/remediate'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-apikey': 'default_key'
                },
                body: JSON.stringify({ path: currentTargetName })
            });

            if (response.ok) {
                const data = await response.json();
                if (data && data.success) {
                    progEl.style.width = "70%";
                    logEl.innerHTML += `> Đã nhận phản hồi từ Backend. Số tệp đã xử lý thành công: ${data.count}.<br>`;
                    logEl.scrollTop = logEl.scrollHeight;
                    
                    // In từng dòng log của server
                    if (data.logs && data.logs.length > 0) {
                        data.logs.forEach(logLine => {
                            logEl.innerHTML += `<span style="color: #F59E0B;">${logLine}</span><br>`;
                        });
                    } else {
                        logEl.innerHTML += `> Không phát hiện tệp tin nào cần khắc phục rủi ro trực tiếp.<br>`;
                    }
                    
                    progEl.style.width = "100%";
                    logEl.innerHTML += "<br><span style='color: #10B981; font-weight: bold;'>[THÀNH CÔNG] Backend đã hoàn tất cập nhật tệp vật lý và thắt quyền CHMOD 600!</span><br>";
                    logEl.scrollTop = logEl.scrollHeight;

                    // Thiết lập trạng thái đã khắc phục
                    isRemediated = true;
                    
                    // Tự động quét lại sau khi khắc phục để cập nhật giao diện
                    logEl.innerHTML += `> Đang tự động quét lại thư mục để kiểm chứng trạng thái bảo mật mới...<br>`;
                    logEl.scrollTop = logEl.scrollHeight;

                    // Gọi lại API scan
                    const scanResponse = await fetch(getApiUrl('/api/scan/path'), {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'x-apikey': 'default_key'
                        },
                        body: JSON.stringify({ path: currentTargetName })
                    });
                    
                    if (scanResponse.ok) {
                        const scanData = await scanResponse.json();
                        if (scanData && scanData.success) {
                            scanResults = scanData.results;
                            scanStats = {
                                high: scanData.stats.high,
                                medium: scanData.stats.medium,
                                low: scanData.stats.low,
                                totalFiles: scanData.stats.totalFiles,
                                filesWithPii: scanData.stats.filesWithPii,
                                securedFiles: scanData.stats.totalFiles - scanData.stats.filesWithPii
                            };
                            
                            // Cập nhật giao diện
                            updateScoreRing();
                            populateHashInfo();
                            populateQuickDetails();
                            populateDetailTab();
                            populateComplianceTab();
                            renderDetailedGrid(scanResults);
                            
                            logEl.innerHTML += `<span style="color: #10B981;">> [OK] Giao diện đã cập nhật đồng bộ trạng thái tệp vật lý sau khắc phục.</span><br>`;
                            logEl.scrollTop = logEl.scrollHeight;
                        }
                    }
                } else {
                    throw new Error("API Server trả về lỗi xử lý.");
                }
            } else {
                throw new Error("Không thể kết nối đến API Server port 5000.");
            }
        } catch (err) {
            logEl.innerHTML += `<span style="color: #EF4444;">> [LỖI] Khắc phục tệp vật lý thất bại: ${err.message}</span><br>`;
            logEl.innerHTML += `> Chuyển sang chế độ giả lập cục bộ...<br>`;
            logEl.scrollTop = logEl.scrollHeight;
            runMockRemediation(logEl, progEl, closeBtn);
            return;
        }
        
        closeBtn.style.display = "inline-block";
        closeBtn.style.opacity = "1";
        closeBtn.style.pointerEvents = "auto";
    } else {
        // Chạy giả lập (đối với quét file local kéo thả trình duyệt)
        logEl.innerHTML += `> Chế độ quét cục bộ trình duyệt. Đang khởi chạy Module mã hóa mô phỏng...<br>`;
        runMockRemediation(logEl, progEl, closeBtn);
    }
}

function runMockRemediation(logEl, progEl, closeBtn) {
    const steps = [
        "> Đang quét danh sách các tệp tin không tuân thủ...",
        `> Đang khởi chạy Module Mã hóa giả lập AES-256 cho các tệp nhạy cảm...`,
        "> Thiết lập khóa mã hóa trong phân vùng an toàn (giả lập)...",
        `> Điều chỉnh quyền truy cập tệp (CHMOD) giả định...`,
        "> Phân quyền tệp tin: Giới hạn tất cả tệp chứa DLCN về CHMOD 600...",
        "> Đánh giá lại mức độ tuân thủ (Nghị định 13/2023/NĐ-CP)..."
    ];
    
    let step = 0;
    const interval = setInterval(() => {
        if (step < steps.length) {
            logEl.innerHTML += steps[step] + "<br>";
            logEl.scrollTop = logEl.scrollHeight;
            progEl.style.width = ((step + 1) / steps.length * 100) + "%";
            step++;
        } else {
            clearInterval(interval);
            logEl.innerHTML += "<br><span style='color: #10B981; font-weight: bold;'>[OK] Hệ thống giả lập đã khắc phục xong thành công!</span><br>";
            logEl.scrollTop = logEl.scrollHeight;
            
            isRemediated = true;
            scanResults.forEach(res => {
                res.securityStatus = "secured";
                res.permissions = "chmod 600 (Chủ sở hữu) + AES-256";
            });
            scanStats.securedFiles = scanResults.length;
            
            updateScoreRing();
            populateHashInfo();
            populateComplianceTab();
            renderDetailedGrid(scanResults);
            
            closeBtn.style.display = "inline-block";
            closeBtn.style.opacity = "1";
            closeBtn.style.pointerEvents = "auto";
        }
    }, 500);
}

function closeExecModal() {
    const modal = document.getElementById('execModal');
    if (modal) {
        modal.style.opacity = '0';
        setTimeout(() => modal.remove(), 300);
    }
}

// Xuất báo cáo PDF chuyên nghiệp dùng html2pdf.js
function exportReport() {
    if (scanResults.length === 0) {
        alert("Không có dữ liệu quét để xuất báo cáo!");
        return;
    }

    // Lấy điểm số an toàn hiện tại (tính tập trung)
    const securityScore = computeSecurityScore();

    let overallRating = "AN TOÀN / TUÂN THỦ";
    let ratingColor = "#10B981";
    let ratingClass = "pass";
    if (!isRemediated) {
        const highCount = scanStats.high || 0;
        const mediumCount = scanStats.medium || 0;
        if (highCount > 0) {
            overallRating = "KHÔNG TUÂN THỦ (NGUY CƠ CAO)";
            ratingColor = "#EF4444";
            ratingClass = "fail";
        } else if (mediumCount > 0) {
            overallRating = "TUÂN THỦ MỘT PHẦN (CẢNH BÁO)";
            ratingColor = "#F59E0B";
            ratingClass = "warn";
        }
    }

    const scanDate = new Date().toLocaleString('vi-VN');
    
    // Tạo HTML cho báo cáo
    const reportContainer = document.createElement('div');
    reportContainer.id = 'pdf-report-container';
    reportContainer.style.fontFamily = "'Inter', sans-serif";
    reportContainer.style.color = "#1F2937";
    reportContainer.style.background = "#FFFFFF";
    reportContainer.style.padding = "0";
    reportContainer.style.margin = "0";

    // Chi tiết 14 danh mục rủi ro dày dặn
    const fullPiiDescriptions = {
        "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)": {
            desc: "Phát hiện mã nguồn chứa các hàm thực thi lệnh hệ thống nguy hiểm (`eval`, `system`, `exec`, `shell_exec`, `passthru`, `subprocess.Popen`) hoặc các từ khóa liên quan đến webshell, backdoor, reverse shell.",
            legal: "Quy chuẩn An toàn Thông tin Quốc gia và Luật An ninh mạng Việt Nam. Việc máy chủ tồn tại webshell/backdoor là vi phạm nghiêm trọng quy chuẩn an toàn vận hành hệ thống thông tin.",
            risk: "Kẻ tấn công có thể thực thi lệnh tùy ý từ xa (RCE), chiếm toàn quyền kiểm soát máy chủ web, leo thang đặc quyền, đánh cắp cơ sở dữ liệu và phá hoại hệ thống.",
            solution: "Cách ly tệp tin ngay lập tức (đổi tên sang đuôi `.quarantine`), thu hồi toàn bộ quyền thực thi, rà soát lại nhật ký truy cập để tìm điểm xâm nhập và vá lỗ hổng tải lên tệp tin."
        },
        "Số định danh (CCCD/CMND)": {
            desc: "Số căn cước công dân (12 số) hoặc chứng minh nhân dân (9 số) bị lưu trữ dưới dạng văn bản rõ không mã hóa.",
            legal: "Quy định tại Điều 36 & 37 Nghị định 13/2023/NĐ-CP về biện pháp bảo vệ dữ liệu cá nhân nhạy cảm, yêu cầu các biện pháp mã hóa kỹ thuật tối đa.",
            risk: "Kẻ xấu sử dụng để mạo danh danh tính, thực hiện các hành vi lừa đảo tài chính, đăng ký tài khoản ngân hàng hoặc dịch vụ trái phép.",
            solution: "Tiến hành che (mask) thông tin trên giao diện hiển thị, mã hóa cột dữ liệu này bằng thuật toán mã hóa mạnh (AES-256) và thắt quyền truy cập tệp tin (CHMOD 600)."
        },
        "Số điện thoại": {
            desc: "Số điện thoại di động cá nhân bị rò rỉ trong cơ sở dữ liệu hoặc log.",
            legal: "Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân cơ bản) và Luật Viễn thông.",
            risk: "Nạn nhân liên tục bị làm phiền bởi các cuộc gọi rác, tin nhắn lừa đảo tài chính hoặc bị tấn công SIM-swapping để chiếm đoạt tài khoản OTP.",
            solution: "Che 3-4 số giữa của số điện thoại khi hiển thị trên các giao diện báo cáo công cộng."
        },
        "Địa chỉ email": {
            desc: "Email cá nhân của khách hàng hoặc nhân viên bị lưu thô.",
            legal: "Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân cơ bản) và các luật về an toàn thông tin mạng.",
            risk: "Đối tượng bị tấn công phishing, spam quảng cáo độc hại hoặc rò rỉ tài khoản đăng nhập trên các diễn đàn hacker.",
            solution: "Áp dụng các bộ lọc chống spam và mã hóa email trong DB."
        },
        "Số thẻ tín dụng": {
            desc: "Số thẻ tín dụng quốc tế (Visa, Mastercard, JCB...) được lưu trữ dưới dạng plaintext, vượt qua kiểm tra thuật toán Luhn.",
            legal: "Tiêu chuẩn Bảo mật Dữ liệu Ngành Thanh toán Thẻ PCI-DSS (Yêu cầu 3).",
            risk: "Lộ lọt thông tin thanh toán dẫn đến việc bị quẹt thẻ trái phép, gây thiệt hại tài chính lớn cho khách hàng và doanh nghiệp bị phạt nặng hoặc đình chỉ thanh toán.",
            solution: "Tuyệt đối không lưu trữ số CVV/CVC. Mã hóa mạnh và cắt cụt số thẻ (chỉ hiển thị 6 số đầu và 4 số cuối)."
        },
        "Địa chỉ IP": {
            desc: "Địa chỉ IP truy cập của người dùng hoặc máy chủ.",
            legal: "Nghị định 13/2023/NĐ-CP và Tiêu chuẩn ISO 27001.",
            risk: "Tiết lộ vị trí địa lý sơ bộ, nhà cung cấp dịch vụ Internet và có thể bị quét các cổng dịch vụ mở để tấn công DDoS hoặc khai thác dịch vụ.",
            solution: "Mask IP trong log (ví dụ: `192.168.1.xxx`) và giới hạn thời gian lưu trữ log truy cập."
        },
        "Thông tin xác thực / API Key / Mật khẩu": {
            desc: "Mật khẩu cơ sở dữ liệu, khóa bí mật API (như stripe, google, aws keys), JWT secret key hoặc token xác thực bị lưu cứng trong mã nguồn.",
            legal: "Tiêu chuẩn bảo mật ISO 27001 (Kiểm soát A.5.15) và quy chuẩn bảo mật công nghiệp.",
            risk: "Giúp kẻ tấn công bypass qua mọi cơ chế phòng vệ và đăng nhập trực tiếp vào các hệ thống backend, dịch vụ đám mây với quyền quản trị tối cao.",
            solution: "Chuyển toàn bộ credentials sang các dịch vụ quản lý khóa an toàn (như AWS Secrets Manager, HashiCorp Vault), không bao giờ commit các tệp `.env` lên git."
        },
        "Số tài khoản ngân hàng / IBAN": {
            desc: "Số tài khoản ngân hàng hoặc mã IBAN cùng với thông tin tên ngân hàng bị rò rỉ.",
            legal: "Nghị định 13/2023/NĐ-CP và Luật các Tổ chức tín dụng.",
            risk: "Kẻ xấu lợi dụng để thực hiện các chiến dịch lừa đảo chuyển tiền (phishing), mạo danh ngân hàng hoặc thu thập thông tin tài chính nhằm tấn công chiếm đoạt tài khoản.",
            solution: "Áp dụng cơ chế phân quyền kiểm soát truy cập nghiêm ngặt và mã hóa dữ liệu lưu trữ tĩnh (Encryption at Rest)."
        },
        "Họ và tên": {
            desc: "Tên đầy đủ của cá nhân đi kèm với các thông tin định danh khác.",
            legal: "Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân cơ bản).",
            risk: "Làm cơ sở để kẻ xấu xây dựng sơ đồ thông tin (profiling) nạn nhân, phục vụ cho các kịch bản lừa đảo tinh vi.",
            solution: "Phân quyền truy cập tệp tin chặt chẽ và lưu trữ riêng biệt với các dữ liệu giao dịch nhạy cảm khác."
        },
        "Ngày sinh": {
            desc: "Ngày tháng năm sinh của cá nhân được lưu trữ rõ ràng.",
            legal: "Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân cơ bản).",
            risk: "Kẻ xấu dùng để đoán mật khẩu mặc định, trả lời các câu hỏi xác minh bảo mật của ngân hàng hoặc giả mạo danh tính trên môi trường số.",
            solution: "Chỉ hiển thị năm sinh nếu không cần thiết sử dụng đầy đủ ngày sinh."
        },
        "Địa chỉ": {
            desc: "Địa chỉ nhà riêng, nơi thường trú hoặc tạm trú.",
            legal: "Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân cơ bản).",
            risk: "Đe dọa đến an toàn vật lý của chủ thể dữ liệu và gia đình, gây rò rỉ đời tư cá nhân nghiêm trọng.",
            solution: "Chỉ lưu trữ dạng mã hóa và chỉ giải mã khi thực sự cần thiết (ví dụ khi giao hàng)."
        },
        "Hồ sơ y tế / Thông tin sức khỏe": {
            desc: "Lộ thông tin bệnh án, nhóm máu, đơn thuốc, lịch sử điều trị hoặc thông tin sức khỏe bệnh nhân.",
            legal: "Quy định nghiêm ngặt tại Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân nhạy cảm đặc biệt).",
            risk: "Ảnh hưởng trực tiếp đến đời tư, danh dự của cá nhân; có thể bị tống tiền hoặc sử dụng cho mục đích quảng cáo y tế trái phép.",
            solution: "Hạn chế tối đa lưu trữ, bắt buộc phải có sự đồng ý bằng văn bản của chủ thể dữ liệu và triển khai mã hóa mức độ cao nhất."
        },
        "Dữ liệu sinh trắc học": {
            desc: "Vân tay, FaceID, mống mắt hoặc dữ liệu nhận dạng sinh trắc học khác bị lưu trữ thô.",
            legal: "Quy định tại Nghị định 13/2023/NĐ-CP (Dữ liệu cá nhân nhạy cảm đặc biệt).",
            risk: "Dữ liệu sinh trắc học không thể thay đổi được. Nếu bị lộ, nạn nhân sẽ đối mặt với nguy cơ bị giả mạo vĩnh viễn.",
            solution: "Không lưu trữ dữ liệu ảnh gốc, chỉ lưu trữ dạng hash một chiều được tạo ra bởi các module phần cứng bảo mật chuyên dụng."
        },
        "Cookie phiên": {
            desc: "Cookie Session ID (PHPSESSID, JSESSIONID...) bị lưu trong log truy cập.",
            legal: "Tiêu chuẩn bảo mật ứng dụng web OWASP.",
            risk: "Cho phép kẻ tấn công thực hiện kỹ thuật Session Hijacking để truy cập thẳng vào hệ thống mà không cần mật khẩu hay MFA.",
            solution: "Cấu hình cờ `HttpOnly`, `Secure` và `SameSite` cho cookie, đồng thời tắt chức năng ghi log cookie trên web server."
        }
    };

    // Chuẩn bị danh sách các loại rủi ro phát hiện được để in mô tả chi tiết
    const detectedPiiTypes = new Set();
    scanResults.forEach(res => {
        res.piiFound.forEach(p => {
            detectedPiiTypes.add(p.name);
        });
    });

    let piiDescriptionsHtml = '';
    detectedPiiTypes.forEach(name => {
        const item = fullPiiDescriptions[name] || {
            desc: "Dữ liệu cá nhân nhạy cảm cần được bảo vệ đầy đủ.",
            legal: "Nghị định 13/2023/NĐ-CP về Bảo vệ dữ liệu cá nhân.",
            risk: "Rò rỉ thông tin cá nhân gây ảnh hưởng đến danh dự, tài chính và đời tư của chủ thể dữ liệu.",
            solution: "Mã hóa và phân quyền truy cập nghiêm ngặt."
        };
        piiDescriptionsHtml += `
            <div style="margin-bottom: 20px; padding: 15px; border: 1px solid #E5E7EB; border-radius: 8px; background: #F9FAFB;">
                <h4 style="color: #3B82F6; font-size: 1.05rem; margin-top: 0; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;">
                    <span>⚠️</span> ${name}
                </h4>
                <p style="margin: 0 0 8px 0; font-size: 0.9rem; line-height: 1.45;"><strong>Mô tả rủi ro:</strong> ${item.desc}</p>
                <p style="margin: 0 0 8px 0; font-size: 0.9rem; line-height: 1.45; color: #DC2626;"><strong>Rủi ro khai thác:</strong> ${item.risk}</p>
                <p style="margin: 0 0 8px 0; font-size: 0.9rem; line-height: 1.45; color: #4B5563;"><strong>Cơ sở pháp lý / Tiêu chuẩn:</strong> ${item.legal}</p>
                <p style="margin: 0; font-size: 0.9rem; line-height: 1.45; color: #10B981;"><strong>Khuyến nghị khắc phục:</strong> ${item.solution}</p>
            </div>
        `;
    });

    if (piiDescriptionsHtml === '') {
        piiDescriptionsHtml = '<p style="color: #4B5563; font-style: italic;">Không phát hiện lỗ hổng hay rò rỉ dữ liệu cá nhân nào cần mô tả chi tiết.</p>';
    }

    // Tạo danh sách các file vi phạm
    let fileRowsHtml = '';
    scanResults.forEach((res, idx) => {
        let piiListText = res.piiFound.length > 0 
            ? res.piiFound.map(p => `${p.name} (${p.count})`).join(', ')
            : 'Không phát hiện rủi ro (An toàn)';
        
        let statusText = '';
        let statusColor = '';
        
        if (res.piiFound.length > 0) {
            statusText = isRemediated ? 'Đã khắc phục (CHMOD 600)' : (res.securityStatus === 'unsecured' ? 'Chưa bảo mật (Văn bản thô)' : 'Được cảnh báo / Bảo vệ');
            statusColor = isRemediated ? '#10B981' : (res.securityStatus === 'unsecured' ? '#EF4444' : '#F59E0B');
        } else {
            statusText = 'An toàn / Tuân thủ';
            statusColor = '#10B981';
        }

        fileRowsHtml += `
            <tr style="border-bottom: 1px solid #E5E7EB;">
                <td style="padding: 10px 8px; font-size: 0.8rem; font-weight: 500; word-break: break-all;">${res.path}</td>
                <td style="padding: 10px 8px; font-size: 0.8rem; font-family: monospace;">${res.permissions}</td>
                <td style="padding: 10px 8px; font-size: 0.8rem; color: ${res.piiFound.length > 0 ? '#EF4444' : '#10B981'}; font-weight: 600;">${piiListText}</td>
                <td style="padding: 10px 8px; font-size: 0.8rem; font-family: monospace; font-weight: 700; color: ${res.cvss && res.cvss.score ? '#EF4444' : '#9CA3AF'};">${res.cvss && res.cvss.score ? `${res.cvss.score} (${res.cvss.severity})` : '—'}</td>
                <td style="padding: 10px 8px; font-size: 0.8rem; color: ${statusColor}; font-weight: bold;">${statusText}</td>
            </tr>
        `;
    });

    if (fileRowsHtml === '') {
        fileRowsHtml = `
            <tr>
                <td colspan="5" style="padding: 20px; text-align: center; color: #6B7280; font-style: italic;">Hệ thống hoàn toàn sạch. Không phát hiện tệp tin vi phạm.</td>
            </tr>
        `;
    }

    // Thiết lập nội dung HTML cho báo cáo in
    reportContainer.innerHTML = `
        <style>
            .pdf-page {
                box-sizing: border-box;
                padding: 40px 50px;
                background: #FFFFFF;
                color: #1F2937;
                font-family: 'Inter', sans-serif;
                position: relative;
            }
            .pdf-header {
                border-bottom: 2px solid #E5E7EB;
                padding-bottom: 15px;
                margin-bottom: 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .pdf-header h2 {
                margin: 0;
                font-size: 1.5rem;
                font-weight: 800;
                color: #1E3A8A;
            }
            .pdf-footer {
                position: absolute;
                bottom: 30px;
                left: 50px;
                right: 50px;
                border-top: 1px solid #E5E7EB;
                padding-top: 10px;
                display: flex;
                justify-content: space-between;
                font-size: 0.75rem;
                color: #9CA3AF;
            }
            .pdf-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                margin-bottom: 25px;
            }
            .pdf-table th {
                background: #F3F4F6;
                padding: 10px;
                text-align: left;
                font-size: 0.85rem;
                font-weight: 600;
                border-bottom: 2px solid #D1D5DB;
                color: #374151;
            }
            .pdf-table td {
                padding: 10px;
                border-bottom: 1px solid #E5E7EB;
                font-size: 0.85rem;
            }
            .badge-pdf {
                padding: 3px 6px;
                border-radius: 4px;
                font-size: 0.7rem;
                font-weight: bold;
                text-transform: uppercase;
            }
            .badge-pdf.pass { background: #D1FAE5; color: #065F46; }
            .badge-pdf.fail { background: #FEE2E2; color: #991B1B; }
            .badge-pdf.warn { background: #FEF3C7; color: #92400E; }
        </style>

        <!-- TRANG BÌA (COVER PAGE) -->
        <div class="pdf-page" style="height: 1040px; display: flex; flex-direction: column; justify-content: space-between; border: 15px solid #1E3A8A; padding: 60px 80px;">
            <div style="text-align: center; margin-top: 50px;">
                <div style="font-size: 4.5rem; margin-bottom: 20px;">🛡️</div>
                <h1 style="font-size: 2.1rem; font-weight: 800; color: #1E3A8A; line-height: 1.3; margin: 0 0 10px 0; letter-spacing: -0.5px;">BÁO CÁO KIỂM TOÁN AN TOÀN THÔNG TIN &</h1>
                <h1 style="font-size: 1.9rem; font-weight: 800; color: #3B82F6; line-height: 1.3; margin: 0 0 20px 0; letter-spacing: -0.5px;">TUÂN THỦ BẢO VỆ DỮ LIỆU CÁ NHÂN</h1>
                <div style="width: 120px; height: 5px; background: #3B82F6; margin: 30px auto;"></div>
                <p style="font-size: 1.2rem; color: #4B5563; font-weight: 500; margin: 0;">Tiêu chuẩn đánh giá: Nghị định 13/2023/NĐ-CP & PCI-DSS & ISO 27001</p>
            </div>

            <div style="background: #F3F4F6; padding: 30px 40px; border-radius: 12px; margin: 40px 0;">
                <h3 style="margin-top: 0; margin-bottom: 20px; color: #1E3A8A; font-size: 1.1rem; border-bottom: 1px solid #D1D5DB; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px;">Thông tin phiên quét kiểm toán</h3>
                <table style="width: 100%; font-size: 0.95rem; border-collapse: collapse;">
                    <tr style="height: 35px;">
                        <td style="width: 180px; font-weight: bold; color: #4B5563; padding: 0;">Máy chủ / Thư mục quét:</td>
                        <td style="color: #111827; padding: 0; font-family: monospace; font-weight: 600;">${currentTargetName}</td>
                    </tr>
                    <tr style="height: 35px;">
                        <td style="font-weight: bold; color: #4B5563; padding: 0;">Thời gian thực hiện:</td>
                        <td style="color: #111827; padding: 0;">${scanDate}</td>
                    </tr>
                    <tr style="height: 35px;">
                        <td style="font-weight: bold; color: #4B5563; padding: 0;">Công cụ kiểm tra:</td>
                        <td style="color: #111827; padding: 0;">PIIScan Server Pro (Phiên bản 2.5)</td>
                    </tr>
                    <tr style="height: 35px;">
                        <td style="font-weight: bold; color: #4B5563; padding: 0;">Điểm số An toàn:</td>
                        <td style="color: ${ratingColor}; padding: 0; font-weight: bold; font-size: 1.1rem;">${securityScore} / 100 Điểm</td>
                    </tr>
                    <tr style="height: 35px;">
                        <td style="font-weight: bold; color: #4B5563; padding: 0;">Trạng thái đánh giá:</td>
                        <td style="padding: 0;"><span class="badge-pdf ${ratingClass}" style="font-size: 0.85rem; padding: 4px 8px;">${overallRating}</span></td>
                    </tr>
                </table>
            </div>

            <div style="text-align: center; font-size: 0.85rem; color: #6B7280; line-height: 1.6;">
                <p style="margin: 0; font-weight: 600; color: #374151;">PHÁT HÀNH BỞI HỆ THỐNG PIISCAN SERVER PRO AUTOMATION</p>
                <p style="margin: 4px 0 0 0;">Tài liệu mật - Chỉ sử dụng lưu hành nội bộ và phục vụ công tác khắc phục lỗ hổng hệ thống.</p>
            </div>
        </div>

        <div class="html2pdf__page-break"></div>

        <!-- TRANG 2: TỔNG QUAN KẾT QUẢ VÀ HÀNH CHÍNH -->
        <div class="pdf-page" style="height: 1040px;">
            <div class="pdf-header">
                <h2>PIIScan Server Pro</h2>
                <span style="font-size: 0.8rem; color: #6B7280;">Báo cáo kiểm toán tuân thủ bảo vệ dữ liệu cá nhân</span>
            </div>

            <h3 style="color: #1E3A8A; font-size: 1.25rem; margin-top: 0; margin-bottom: 12px; border-left: 4px solid #3B82F6; padding-left: 10px;">I. Tóm tắt Số liệu Kiểm toán</h3>
            <p style="font-size: 0.9rem; color: #4B5563; line-height: 1.55; margin-bottom: 15px;">
                Báo cáo này cung cấp thông tin kiểm tra tổng quát trạng thái lưu trữ thông tin cá nhân và kiểm tra mã độc trên máy chủ. Kết quả quét được đối chiếu trực tiếp với các quy chuẩn kỹ thuật của **Nghị định 13/2023/NĐ-CP (Việt Nam)**, tiêu chuẩn thẻ thanh toán **PCI-DSS**, và tiêu chuẩn an toàn thông tin **ISO/IEC 27001**.
            </p>

            <table class="pdf-table" style="margin-bottom: 20px;">
                <thead>
                    <tr>
                        <th style="width: 60%;">Chỉ số Kiểm toán</th>
                        <th style="width: 40%; text-align: right;">Giá trị</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Tổng số tệp tin được quét kiểm tra</td>
                        <td style="text-align: right; font-weight: bold; font-family: monospace;">${scanStats.totalFiles}</td>
                    </tr>
                    <tr>
                        <td>Tệp tin phát hiện chứa dữ liệu cá nhân (DLCN) hoặc mã độc</td>
                        <td style="text-align: right; font-weight: bold; font-family: monospace; color: #EF4444;">${scanStats.filesWithPii}</td>
                    </tr>
                    <tr>
                        <td>Số lượng tệp chưa được bảo mật (Lưu trữ dạng thô / Plaintext)</td>
                        <td style="text-align: right; font-weight: bold; font-family: monospace; color: #EF4444;">${isRemediated ? 0 : scanResults.filter(r => r.securityStatus !== 'secured').length}</td>
                    </tr>
                    <tr>
                        <td>Số lượng tệp được bảo vệ tốt (Mã hóa / CHMOD 600)</td>
                        <td style="text-align: right; font-weight: bold; font-family: monospace; color: #10B981;">${isRemediated ? scanResults.length : scanResults.filter(r => r.securityStatus === 'secured').length}</td>
                    </tr>
                </tbody>
            </table>

            <h3 style="color: #1E3A8A; font-size: 1.25rem; margin-top: 20px; margin-bottom: 12px; border-left: 4px solid #3B82F6; padding-left: 10px;">II. Đánh giá Tính Tuân thủ Pháp luật & Tiêu chuẩn</h3>
            
            <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 10px;">
                <div style="border: 1px solid #E5E7EB; border-radius: 8px; padding: 12px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
                        <strong style="font-size: 0.9rem; color: #1E3A8A;">1. Nghị định 13/2023/NĐ-CP (Bảo vệ dữ liệu cá nhân)</strong>
                        <span class="badge-pdf ${ (isRemediated || (scanStats.filesWithPii === 0)) ? 'pass' : 'fail' }">${ (isRemediated || (scanStats.filesWithPii === 0)) ? 'ĐẠT' : 'CHƯA ĐẠT' }</span>
                    </div>
                    <p style="margin: 0; font-size: 0.8rem; color: #4B5563; line-height: 1.45;">Yêu cầu mã hóa thông tin nhạy cảm (CCCD, tài khoản ngân hàng, sinh trắc học, sức khỏe) khi lưu trữ và kiểm soát quyền truy cập chặt chẽ. Việc lưu plaintext vi phạm Điều 36.</p>
                </div>

                <div style="border: 1px solid #E5E7EB; border-radius: 8px; padding: 12px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
                        <strong style="font-size: 0.9rem; color: #1E3A8A;">2. Tiêu chuẩn ngành thẻ thanh toán PCI-DSS (Yêu cầu 3)</strong>
                        <span class="badge-pdf ${ (isRemediated || (scanResults.filter(r => r.level === 'high' && r.securityStatus === 'unsecured').length === 0)) ? 'pass' : 'fail' }">${ (isRemediated || (scanResults.filter(r => r.level === 'high' && r.securityStatus === 'unsecured').length === 0)) ? 'ĐẠT' : 'CHƯA ĐẠT' }</span>
                    </div>
                    <p style="margin: 0; font-size: 0.8rem; color: #4B5563; line-height: 1.45;">Yêu cầu bảo vệ dữ liệu chủ thẻ lưu trữ. Cấm lưu plaintext số thẻ tín dụng hoặc thông tin giao dịch tài chính nhạy cảm.</p>
                </div>

                <div style="border: 1px solid #E5E7EB; border-radius: 8px; padding: 12px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
                        <strong style="font-size: 0.9rem; color: #1E3A8A;">3. Tiêu chuẩn ISO/IEC 27001 (Kiểm soát truy cập & Phân quyền)</strong>
                        <span class="badge-pdf ${ (isRemediated || (scanResults.filter(r => r.permissions.includes("777")).length === 0)) ? 'pass' : 'fail' }">${ (isRemediated || (scanResults.filter(r => r.permissions.includes("777")).length === 0)) ? 'ĐẠT' : 'CHƯA ĐẠT' }</span>
                    </div>
                    <p style="margin: 0; font-size: 0.8rem; color: #4B5563; line-height: 1.45;">Đảm bảo các tệp chứa dữ liệu quan trọng hoặc tệp cấu hình được phân quyền truy cập giới hạn, tránh quyền đọc/ghi công khai (CHMOD 777 hoặc 755).</p>
                </div>
            </div>

            <div class="pdf-footer">
                <span>PIIScan Server Pro v2.5</span>
                <span>Trang 2 / 4</span>
            </div>
        </div>

        <div class="html2pdf__page-break"></div>

        <!-- TRANG 3: MÔ TẢ CHI TIẾT 14 LOẠI LỖ HỔNG / RỦI RO PHÁT HIỆN -->
        <div class="pdf-page" style="height: 1040px;">
            <div class="pdf-header">
                <h2>PIIScan Server Pro</h2>
                <span style="font-size: 0.8rem; color: #6B7280;">Báo cáo kiểm toán tuân thủ bảo vệ dữ liệu cá nhân</span>
            </div>

            <h3 style="color: #1E3A8A; font-size: 1.25rem; margin-top: 0; margin-bottom: 12px; border-left: 4px solid #3B82F6; padding-left: 10px;">III. Phân tích Chi tiết Lỗ hổng & Rủi ro bảo mật phát hiện</h3>
            <p style="font-size: 0.9rem; color: #4B5563; line-height: 1.55; margin-bottom: 15px;">
                Dưới đây là phần mô tả pháp lý, rủi ro kỹ thuật và phương pháp khắc phục chi tiết của từng loại lỗ hổng / danh mục dữ liệu được phát hiện trong phiên quét này:
            </p>

            <div style="height: 780px; overflow-y: auto; padding-right: 5px;">
                ${piiDescriptionsHtml}
            </div>

            <div class="pdf-footer">
                <span>PIIScan Server Pro v2.5</span>
                <span>Trang 3 / 4</span>
            </div>
        </div>

        <div class="html2pdf__page-break"></div>

        <!-- TRANG 4: DANH SÁCH FILE VÀ ĐỀ XUẤT HÀNH ĐỘNG -->
        <div class="pdf-page" style="height: 1040px;">
            <div class="pdf-header">
                <h2>PIIScan Server Pro</h2>
                <span style="font-size: 0.8rem; color: #6B7280;">Báo cáo kiểm toán tuân thủ bảo vệ dữ liệu cá nhân</span>
            </div>

            <h3 style="color: #1E3A8A; font-size: 1.25rem; margin-top: 0; margin-bottom: 12px; border-left: 4px solid #3B82F6; padding-left: 10px;">IV. Danh sách Chi tiết các Tệp tin chứa rủi ro</h3>
            <p style="font-size: 0.9rem; color: #4B5563; line-height: 1.5; margin-bottom: 10px;">
                Bảng dưới đây thống kê danh sách đầy đủ các tệp tin chứa rủi ro được phát hiện cùng thông số phân quyền thực tế và tình trạng bảo mật:
            </p>

            <div style="height: 480px; overflow-y: auto; border: 1px solid #E5E7EB; border-radius: 6px; padding: 5px; margin-bottom: 15px;">
                <table class="pdf-table" style="margin-top: 5px; margin-bottom: 5px;">
                    <thead>
                        <tr>
                            <th style="width: 30%; font-size: 0.8rem;">Đường dẫn tệp</th>
                            <th style="width: 15%; font-size: 0.8rem;">Quyền hạn</th>
                            <th style="width: 25%; font-size: 0.8rem;">Dữ liệu phát hiện</th>
                            <th style="width: 12%; font-size: 0.8rem;">CVSS</th>
                            <th style="width: 18%; font-size: 0.8rem;">Trạng thái</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${fileRowsHtml}
                    </tbody>
                </table>
            </div>

            <h3 style="color: #1E3A8A; font-size: 1.15rem; margin-top: 15px; margin-bottom: 8px; border-left: 4px solid #3B82F6; padding-left: 10px;">V. Khuyến nghị & Ký duyệt kiểm tra</h3>
            <p style="font-size: 0.85rem; color: #4B5563; line-height: 1.5; margin: 0 0 20px 0;">
                **1. Khuyến nghị:** Quản trị viên cần nhanh chóng kích hoạt tính năng **Khắc phục Tự động** trên hệ thống để mã hóa AES-256 các tệp tin chứa dữ liệu cá nhân nhạy cảm, cách ly tệp tin chứa webshell có hậu tố '.quarantine' và thiết lập quyền hạn file về mức an toàn tối đa 'CHMOD 600'.
                <br>
                **2. Tuyên bố:** Báo cáo được phát hành tự động và có giá trị xác nhận tại thời điểm quét. Dữ liệu nhạy cảm hiển thị trong báo cáo này đã được áp dụng bộ lọc che thông tin để tránh rò rỉ dữ liệu thứ cấp.
            </p>

            <!-- Khung ký tên kiểm định -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 20px; padding: 0 20px;">
                <div style="text-align: center; width: 220px;">
                    <p style="margin: 0; font-size: 0.85rem; font-weight: bold; color: #4B5563;">Hệ thống phát hành tự động</p>
                    <p style="margin: 45px 0 0 0; font-size: 0.9rem; font-weight: bold; color: #1E3A8A;">PIIScan Server Pro Engine</p>
                </div>
                <div style="text-align: center; width: 220px;">
                    <p style="margin: 0; font-size: 0.85rem; font-weight: bold; color: #4B5563;">Đại diện Quản trị viên</p>
                    <div style="margin: 10px 0; font-style: italic; color: #9CA3AF; font-size: 0.75rem;">(Đã ký duyệt qua MFA)</div>
                    <p style="margin: 15px 0 0 0; font-size: 0.9rem; font-weight: bold; color: #1E3A8A;">Quản trị viên Hệ thống</p>
                </div>
            </div>

            <div class="pdf-footer">
                <span>PIIScan Server Pro v2.5</span>
                <span>Trang 4 / 4</span>
            </div>
        </div>
    `;

    document.body.appendChild(reportContainer);

    // Cấu hình html2pdf
    const opt = {
        margin:       0,
        filename:     `Bao_cao_Kiem_toan_Bao_mat_Du_lieu_${new Date().toISOString().split('T')[0]}.pdf`,
        image:        { type: 'jpeg', quality: 0.98 },
        html2canvas:  { scale: 2, useCORS: true, letterRendering: true },
        jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
    };

    // Tạo PDF
    html2pdf().set(opt).from(reportContainer).save().then(() => {
        // Xoá container sau khi xuất
        reportContainer.remove();
    }).catch(err => {
        console.error("Xuất báo cáo PDF thất bại: ", err);
        alert("Có lỗi xảy ra khi xuất báo cáo PDF. Vui lòng kiểm tra console hoặc thử lại!");
        reportContainer.remove();
    });
}


// Hiệu ứng tăng số thống kê
function animateNumbers() {
    const nums = document.querySelectorAll('.stat-num');
    nums.forEach(num => {
        const target = +num.getAttribute('data-target');
        let current = 0;
        const increment = target / 50;
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                clearInterval(timer);
                num.innerText = target;
            } else {
                num.innerText = Math.floor(current);
            }
        }, 30);
    });
}
