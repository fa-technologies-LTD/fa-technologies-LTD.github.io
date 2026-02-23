/* Logs Formatter — app.js
   All conversion logic, UI handlers, and event wiring. */

// ── State ──────────────────────────────────────
let lastInputLength = 0;
let customFormat = null;
let lastAutoConvertFormat = null;
let convert2FAToLinks = true;
let lastGeneratedSocialPlatform = null;
let isReverseMode = false;
let processingTimeout = null;
let twoFAPrefix = 'https://fastaccs.com/tools/easylogin/#';

// ── 2FA Prefix Management ──────────────────────
function load2FAPrefix() {
  const saved = localStorage.getItem('logsFormatter2FAPrefix');
  if (saved) twoFAPrefix = saved;
  document.getElementById('prefixInput').value = twoFAPrefix;
  document.getElementById('currentPrefix').textContent = twoFAPrefix;
}

function save2FAPrefix() {
  const input = document.getElementById('prefixInput').value.trim();
  if (!input) { showNotification('Please enter a valid prefix', 'error'); return; }

  twoFAPrefix = input.endsWith('/') || input.endsWith('#') ? input : input + '#';
  localStorage.setItem('logsFormatter2FAPrefix', twoFAPrefix);
  document.getElementById('currentPrefix').textContent = twoFAPrefix;

  const btn = document.getElementById('savePrefix');
  btn.textContent = '✓ Saved';
  setTimeout(() => { btn.textContent = 'Save'; }, 2000);

  showNotification('2FA prefix saved');
  if (document.getElementById('input').value.trim()) autoConvert();
}

function reset2FAPrefix() {
  twoFAPrefix = 'https://fastaccs.com/tools/easylogin/#';
  localStorage.removeItem('logsFormatter2FAPrefix');
  document.getElementById('prefixInput').value = twoFAPrefix;
  document.getElementById('currentPrefix').textContent = twoFAPrefix;
  showNotification('2FA prefix reset');
  if (document.getElementById('input').value.trim()) autoConvert();
}

// ── Pattern Detection ──────────────────────────
const credentialPatterns = [
  /2FA[-_\s]*Link[-_\s]*:[-_\s]*([A-Za-z0-9]+)/gi,
  /2FA[-_\s]*Code[-_\s]*:[-_\s]*([A-Za-z0-9]+)/gi,
  /2FA[-_\s]*:[-_\s]*([A-Za-z0-9]+)/gi,
  /Two[-_\s]*Factor[-_\s]*:[-_\s]*([A-Za-z0-9]+)/gi,
  /Authentication[-_\s]*:[-_\s]*([A-Za-z0-9]+)/gi,
  /Auth[-_\s]*:[-_\s]*([A-Za-z0-9]+)/gi,
  /\b([A-Z0-9]{10,})\b/g,
  /[:;|,]([A-Z0-9]{10,})\s*$/g,
  /[:;|,]([A-Z0-9]{10,})[:;|,]/g
];

function detectSeparator(format) {
  const seps = [':', ',', '|', ';'];
  for (const s of seps) { if (format.includes(s)) return s; }
  return null;
}

function detectInputFormat(inputText) {
  if (!inputText.trim()) return '';
  const firstLine = inputText.split('\n')[0];
  const seps = [':', '|', ';', ','];

  for (const sep of seps) {
    if (firstLine.includes(sep)) {
      const parts = firstLine.split(sep);
      if (parts.length >= 3) {
        return parts.map((_, i) => {
          if (i === 0) return 'username';
          if (i === 1) return 'password';
          if (i === 2 && parts.length === 3) return '2fa';
          if (i === 2 && parts[i].includes('@')) return 'email';
          if (i === 3) return '2fa';
          if (i === 4) return '2fa';
          return `field${i + 1}`;
        }).join(sep);
      }
    }
  }
  return 'username:password:2fa';
}

// ── Field Classification ───────────────────────
function isEmail(f) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.trim()); }

function is2FACode(f) {
  const c = f.trim().replace(/[^A-Za-z0-9]/g, '');
  return c.length >= 10 && /^[A-Z0-9]{10,}$/.test(c);
}

function isHash(f) {
  const c = f.trim();
  return /^[a-fA-F0-9]{32,}$/.test(c) ||
         /^[0-9a-fA-F]{40,}$/.test(c) ||
         (c.length > 30 && /^[a-zA-Z0-9+/=]{30,}$/.test(c));
}

function isPhoneNumber(f) {
  const c = f.replace(/[^\d]/g, '');
  return c.length >= 10 && c.length <= 15 && /^\d+$/.test(c);
}

function smartFieldClassification(parts) {
  const result = [];

  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();

    if (i === 0) {
      if (isEmail(p)) result.push({ type: 'email', value: p, label: 'email' });
      else if (isPhoneNumber(p)) result.push({ type: 'phone', value: p, label: 'username' });
      else result.push({ type: 'username', value: p, label: 'username' });
    } else if (i === 1) {
      result.push({ type: 'password', value: p, label: 'password' });
    } else {
      if (is2FACode(p)) result.push({ type: '2fa', value: p, label: '2FA' });
      else if (isEmail(p)) result.push({ type: 'email', value: p, label: 'email' });
      else if (isHash(p)) result.push({ type: 'hash', value: p, label: null });
      else if (p.length > 20 && /^[a-zA-Z0-9+/=]+$/.test(p)) result.push({ type: 'token', value: p, label: null });
      else if (i === 3) result.push({ type: 'emailPassword', value: p, label: 'email-password' });
      else result.push({ type: 'generic', value: p, label: `field${i + 1}` });
    }
  }
  return result;
}

// ── Custom Format ──────────────────────────────
function formatWithCustomFormat(inputText, format) {
  if (!format || !inputText) return inputText;
  const sep = detectSeparator(format);
  if (!sep) return inputText;

  const lines = inputText.split('\n');
  let out = '';

  lines.forEach(line => {
    if (!line.trim()) return;
    const parts = line.split(sep);
    const formatParts = format.split(sep);
    let formatted = '';

    formatParts.forEach((field, i) => {
      if (parts[i] && field.trim() !== 'omit') {
        if (field.trim().toLowerCase().includes('2fa') && parts[i]) {
          const clean = parts[i].trim().replace(/[^A-Za-z0-9]/g, '');
          if (clean.length >= 10 && /^[A-Z0-9]{10,}$/.test(clean)) {
            formatted += convert2FAToLinks
              ? `2FA_Link: ${twoFAPrefix}${clean}\n`
              : `2FA: ${clean}\n`;
            enable2FAToggle();
          } else {
            formatted += `${field.trim()}: ${parts[i].trim()}\n`;
          }
        } else {
          formatted += `${field.trim()}: ${parts[i].trim()}\n`;
        }
      }
    });

    if (formatted.trim()) out += formatted + '\n';
  });

  return out;
}

function loadSavedFormat() {
  const saved = localStorage.getItem('logsFormatterFormat');
  if (saved) document.getElementById('formatInput').value = saved;
}

function saveFormat() {
  const text = document.getElementById('formatInput').value.trim();
  if (!text) { showNotification('Enter a format template', 'error'); return; }

  localStorage.setItem('logsFormatterFormat', text);
  customFormat = text;
  showNotification('Format saved');
}

function resetFormat() {
  document.getElementById('formatInput').value = '';
  localStorage.removeItem('logsFormatterFormat');
  customFormat = null;
  updateFormatPlaceholder();
  showNotification('Format reset');
}

// ── Core Conversion ────────────────────────────
function convertText(inputText) {
  let conversionCount = 0;
  const patternsFound = new Set();
  const lines = inputText.split('\n');
  const outputLines = [];

  lines.forEach(line => {
    let processedLine = line;
    let lineProcessed = false;

    if (!line.trim()) { outputLines.push(line); return; }

    const separators = [':', '|', ';', ','];
    let detectedSep = null;
    let parts = [];

    for (const sep of separators) {
      if (line.includes(sep)) {
        const test = line.split(sep);
        if (test.length >= 3) { detectedSep = sep; parts = test; break; }
      }
    }

    if (detectedSep && parts.length >= 3) {
      const classification = smartFieldClassification(parts);
      const formattedOutput = [];
      let found2FA = false;
      const autoTemplate = [];

      classification.forEach(field => {
        if (field.label) {
          autoTemplate.push(field.label);
          if (field.type === '2fa') {
            const clean = field.value.trim().replace(/[^A-Za-z0-9]/g, '');
            if (clean.length >= 10 && /^[A-Z0-9]{10,}$/.test(clean)) {
              formattedOutput.push(convert2FAToLinks
                ? `2FA_Link: ${twoFAPrefix}${clean}`
                : `2FA: ${clean}`);
              found2FA = true;
              conversionCount++;
            } else {
              formattedOutput.push(`${field.label}: ${field.value}`);
            }
          } else {
            formattedOutput.push(`${field.label}: ${field.value}`);
          }
        } else {
          autoTemplate.push('omit');
        }
      });

      if (formattedOutput.length > 0) {
        processedLine = formattedOutput.join('\n') + '\n';
        lineProcessed = true;
        patternsFound.add('smart');
        lastAutoConvertFormat = autoTemplate.join(detectedSep);
        if (found2FA) enable2FAToggle();
      }
    }

    if (!lineProcessed) {
      credentialPatterns.slice(0, 6).forEach((pattern, idx) => {
        const matches = [...line.matchAll(pattern)];
        matches.forEach(match => {
          const code = match[1];
          if (code) {
            const clean = code.trim().replace(/[^A-Za-z0-9]/g, '');
            if (clean.length >= 10 && /^[A-Z0-9]{10,}$/.test(clean)) {
              conversionCount++;
              patternsFound.add(idx);
              processedLine = processedLine.replace(code,
                convert2FAToLinks ? `${twoFAPrefix}${clean}` : clean);
              enable2FAToggle();
            }
          }
        });
      });
    }

    outputLines.push(processedLine);
  });

  return { text: outputLines.join('\n'), count: conversionCount, patterns: patternsFound.size };
}

function processLargeDataset(inputText) {
  const lines = inputText.split('\n');
  const chunkSize = 500;
  const processed = [];
  let totalCount = 0;
  let totalPatterns = 0;

  for (let i = 0; i < lines.length; i += chunkSize) {
    const chunk = lines.slice(i, i + chunkSize).join('\n');
    if (chunk.trim()) {
      const r = convertText(chunk);
      if (r.text.trim()) {
        processed.push(r.text.trim());
        totalCount += r.count;
        totalPatterns = Math.max(totalPatterns, r.patterns);
      }
    }
  }

  return { text: processed.join('\n'), count: totalCount, patterns: totalPatterns };
}

// ── Reverse Mode ───────────────────────────────
function reverseClean(inputText, separator = ':') {
  if (!inputText.trim()) return '';

  const lines = inputText.split('\n');
  const outputLines = [];
  let record = {};
  let order = [];

  lines.forEach(line => {
    const t = line.trim();
    if (!t || t.startsWith('---') || t.startsWith('Profile Links')) {
      if (Object.keys(record).length > 0) {
        outputLines.push(buildReverseLine(record, order, separator));
        record = {}; order = [];
      }
      return;
    }

    const m = t.match(/^([^:]+?)\s*:\s*(.+)$/);
    if (m) {
      let key = m[1].trim().toLowerCase();
      let value = m[2].trim();

      if (key === '2fa_link' || key === '2fa link' || key === '2fa-link') {
        const codeMatch = value.match(/[#/]([A-Z0-9]+)$/);
        if (codeMatch) { value = codeMatch[1]; key = '2fa'; }
      }

      key = normalizeKey(key);
      if (!record[key]) { record[key] = value; order.push(key); }
    } else {
      if (Object.keys(record).length > 0) {
        outputLines.push(buildReverseLine(record, order, separator));
        record = {}; order = [];
      }
    }
  });

  if (Object.keys(record).length > 0) {
    outputLines.push(buildReverseLine(record, order, separator));
  }

  return outputLines.filter(l => l).join('\n');
}

function normalizeKey(key) {
  const map = {
    'username': 'username', 'user': 'username', 'login': 'username',
    'password': 'password', 'pass': 'password', 'pwd': 'password',
    'email': 'email', 'mail': 'email', 'e-mail': 'email',
    'email-password': 'email-password', 'emailpassword': 'email-password',
    'email password': 'email-password', 'email pass': 'email-password',
    'mail password': 'email-password', 'm.pass': 'email-password', 'mpass': 'email-password',
    '2fa': '2fa', '2fa_link': '2fa', '2fa link': '2fa',
    'two factor': '2fa', 'twofactor': '2fa',
    'alt mail': 'alt-email', 'alt email': 'alt-email', 'alternate email': 'alt-email'
  };
  return map[key.toLowerCase()] || key;
}

function buildReverseLine(record, order, separator) {
  const stdOrder = ['username', 'password', 'email', 'email-password', '2fa', 'alt-email'];
  const finalOrder = order.length > 0 ? order : stdOrder.filter(k => record[k]);
  return finalOrder.filter(k => record[k]).map(k => record[k]).join(separator);
}

// ── UI Helpers ─────────────────────────────────
function countProcessedLogs(outputText) {
  if (!outputText.trim()) return 0;
  const lines = outputText.split('\n');
  let count = 0;
  let inRecord = false;

  for (const line of lines) {
    const t = line.trim();
    if (!t) {
      if (inRecord) { count++; inRecord = false; }
      continue;
    }
    if (t.startsWith('---')) continue;
    inRecord = true;
  }
  if (inRecord) count++;
  return count;
}

function updateStats(converted, patterns, characters) {
  const el = document.getElementById('statsCounter');
  const output = document.getElementById('output').value;
  const logCount = countProcessedLogs(output);

  if (logCount > 0) {
    el.textContent = `${logCount} log${logCount !== 1 ? 's' : ''} processed`;
  } else if (characters > 0) {
    el.textContent = `${characters.toLocaleString()} chars`;
  } else {
    el.textContent = '';
  }
}

function showNotification(message, type = 'success') {
  const el = document.getElementById('notification');
  el.textContent = message;
  el.style.background = type === 'error' ? '#EF4444' : type === 'info' ? '#3B82F6' : '#4A9B7F';
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3000);
}

function enable2FAToggle() {
  const toggle = document.getElementById('toggleLinks');
  const label = document.getElementById('toggleLabel');
  toggle.disabled = false;
  label.textContent = '2FA Links';
}

function disable2FAToggle() {
  const toggle = document.getElementById('toggleLinks');
  const label = document.getElementById('toggleLabel');
  toggle.disabled = true;
  label.textContent = '2FA Links (none detected)';
}

function toggle2FAConversion() {
  convert2FAToLinks = document.getElementById('toggleLinks').checked;
  if (document.getElementById('input').value.trim()) autoConvert();
}

function updateFormatPlaceholder() {
  const inputText = document.getElementById('input').value;
  const formatInput = document.getElementById('formatInput');

  if (inputText.trim()) {
    const detected = detectInputFormat(inputText);
    const current = formatInput.value.trim();
    const saved = localStorage.getItem('logsFormatterFormat');
    if (!current || current === saved) {
      formatInput.value = detected;
      customFormat = detected;
    }
    formatInput.placeholder = `Detected: ${detected}\nRename fields or use 'omit' to skip`;
  } else {
    formatInput.value = '';
    customFormat = null;
    formatInput.placeholder = "username:password:2fa\nUse 'omit' to skip fields";
  }
}

// ── Main Actions ───────────────────────────────
function manualConvert() {
  const inputText = document.getElementById('input').value;
  const autoToggle = document.getElementById('autoConvert');
  const reverseToggle = document.getElementById('reverseMode');
  const formatText = document.getElementById('formatInput').value.trim();

  if (!inputText.trim()) { showNotification('Enter some text to convert', 'error'); return; }

  if (reverseToggle.checked) {
    const sep = document.getElementById('reverseSeparator').value;
    const reversed = reverseClean(inputText, sep);
    document.getElementById('output').value = reversed;
    const count = reversed.split('\n').filter(l => l.trim()).length;
    updateStats(count, 1, inputText.length);
    showNotification(`Reversed ${count} credential${count !== 1 ? 's' : ''}`);
    return;
  }

  if (!autoToggle.checked && !formatText) {
    showNotification('Enter a custom format or enable auto-convert', 'error');
    return;
  }

  let result;
  if (formatText && !autoToggle.checked) {
    const formatted = formatWithCustomFormat(inputText, formatText);
    const escaped = twoFAPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = {
      text: formatted,
      count: (formatted.match(new RegExp(escaped, 'g')) || []).length,
      patterns: 1
    };
  } else {
    result = convertText(inputText);
  }

  document.getElementById('output').value = result.text;
  updateStats(result.count, result.patterns, inputText.length);

  if (result.count > 0) {
    showNotification(`Converted ${result.count} credential${result.count !== 1 ? 's' : ''}`);
  } else {
    showNotification('Formatted — no 2FA patterns found');
  }
}

function autoConvert() {
  const autoToggle = document.getElementById('autoConvert');
  if (!autoToggle || !autoToggle.checked) return;

  const inputText = document.getElementById('input').value;

  if (document.getElementById('reverseMode').checked) {
    const sep = document.getElementById('reverseSeparator').value;
    const reversed = reverseClean(inputText, sep);
    document.getElementById('output').value = reversed;
    const count = reversed.split('\n').filter(l => l.trim()).length;
    updateStats(count, 1, inputText.length);
    return;
  }

  const result = inputText.length > 100000
    ? processLargeDataset(inputText)
    : convertText(inputText);

  document.getElementById('output').value = result.text;

  if (inputText.length !== lastInputLength) {
    updateStats(result.count, result.patterns, inputText.length);
    lastInputLength = inputText.length;
  }
}

function copyOutput() {
  const output = document.getElementById('output');
  if (!output.value.trim()) { showNotification('Nothing to copy', 'error'); return; }

  navigator.clipboard.writeText(output.value).then(() => {
    showNotification('Copied to clipboard');
  }).catch(() => {
    output.select();
    document.execCommand('copy');
    showNotification('Copied to clipboard');
  });

  lastGeneratedSocialPlatform = null;
  updateSocialButtonStates();
}

function clearAll() {
  document.getElementById('input').value = '';
  document.getElementById('output').value = '';
  document.getElementById('formatInput').value = '';
  lastInputLength = 0;
  customFormat = null;
  lastAutoConvertFormat = null;
  lastGeneratedSocialPlatform = null;
  disable2FAToggle();
  updateSocialButtonStates();
  updateStats(0, 0, 0);
  updateFormatPlaceholder();
  showNotification('Cleared');
}

// ── Download Export ────────────────────────────
function downloadOutput() {
  const output = document.getElementById('output').value;
  if (!output.trim()) { showNotification('Nothing to download', 'error'); return; }

  const blob = new Blob([output], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `logs-formatted-${new Date().toISOString().slice(0, 10)}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showNotification('Downloaded');
}

// ── Social Links ───────────────────────────────
function generateSocialLinks(platform) {
  const outputField = document.getElementById('output');
  const inputField = document.getElementById('input');
  const outputText = outputField.value;
  const inputText = inputField.value;
  const usernames = [];

  // Extract from formatted output
  if (outputText.trim()) {
    outputText.split('\n').forEach(line => {
      const m = line.trim().match(/^username\s*:\s*([^\s\n]+)/i);
      if (m) usernames.push(m[1]);
    });
  }

  // Fallback: extract from raw input
  if (usernames.length === 0 && inputText.trim()) {
    inputText.split('\n').forEach(line => {
      const t = line.trim();
      if (!t || t.startsWith('---')) return;
      for (const sep of [':', '|', ';', ',']) {
        if (t.includes(sep)) {
          const parts = t.split(sep);
          if (parts.length >= 2 && parts[0].trim() && !parts[0].includes('@')) {
            usernames.push(parts[0].trim());
          }
          break;
        }
      }
    });
  }

  if (usernames.length === 0) {
    showNotification('No usernames found', 'error');
    return;
  }

  const urls = {
    x: 'https://x.com/',
    instagram: 'https://instagram.com/',
    facebook: 'https://facebook.com/',
    tiktok: 'https://tiktok.com/@',
    linkedin: 'https://linkedin.com/in/'
  };

  const base = urls[platform];
  if (!base) return;

  const links = usernames.map(u => `${base}${u}`);
  let out = outputText;
  if (!out.endsWith('\n\n')) out += '\n\n';
  out += `--- Profile Links: ${platform.toUpperCase()} ---\n`;
  links.forEach(l => { out += l + '\n'; });

  outputField.value = out;
  lastGeneratedSocialPlatform = platform;
  updateSocialButtonStates();
  showNotification(`${links.length} ${platform} link${links.length !== 1 ? 's' : ''} generated`);
}

function updateSocialButtonStates() {
  const outputText = document.getElementById('output').value;
  const inputText = document.getElementById('input').value;
  const hasUsernames = /username\s*:/i.test(outputText) ||
                       (inputText.trim() && /[:;|,]/.test(inputText));

  const buttons = { btnX: 'x', btnInstagram: 'instagram', btnFacebook: 'facebook', btnTiktok: 'tiktok', btnLinkedin: 'linkedin' };

  Object.entries(buttons).forEach(([id, plat]) => {
    const btn = document.getElementById(id);
    btn.disabled = !hasUsernames;
    btn.classList.toggle('active', hasUsernames && lastGeneratedSocialPlatform === plat);
  });
}

// ── Event Listeners ────────────────────────────

// Drag & drop file import
const dropZone = document.getElementById('dropZone');

['dragenter', 'dragover'].forEach(evt => {
  dropZone.addEventListener(evt, e => {
    e.preventDefault();
    dropZone.classList.add('dragging');
  });
});

['dragleave', 'drop'].forEach(evt => {
  dropZone.addEventListener(evt, () => dropZone.classList.remove('dragging'));
});

dropZone.addEventListener('drop', e => {
  e.preventDefault();
  const file = e.dataTransfer.files[0];
  if (!file) return;

  if (!file.name.endsWith('.txt') && !file.type.startsWith('text/')) {
    showNotification('Only text files supported', 'error');
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById('input').value = reader.result;
    autoConvert();
    updateFormatPlaceholder();
    updateSocialButtonStates();
    showNotification(`Loaded ${file.name}`);
  };
  reader.readAsText(file);
});

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  // Ctrl+Enter or Cmd+Enter = Convert
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    manualConvert();
  }
  // Ctrl+Shift+C or Cmd+Shift+C = Copy output
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'C') {
    e.preventDefault();
    copyOutput();
  }
});

document.getElementById('input').addEventListener('input', () => {
  clearTimeout(processingTimeout);
  processingTimeout = setTimeout(() => {
    autoConvert();
    updateFormatPlaceholder();
    updateSocialButtonStates();
  }, 300);
});

document.getElementById('input').addEventListener('paste', () => {
  setTimeout(() => {
    autoConvert();
    updateFormatPlaceholder();
    updateSocialButtonStates();
  }, 10);
});

document.getElementById('autoConvert').addEventListener('change', function () {
  if (!this.checked) {
    // Auto-open settings and pre-fill format
    document.querySelector('.settings').open = true;
    const input = document.getElementById('input').value;
    const formatInput = document.getElementById('formatInput');
    if (input.trim() && lastAutoConvertFormat) {
      formatInput.value = lastAutoConvertFormat;
      customFormat = lastAutoConvertFormat;
    } else if (input.trim()) {
      const detected = detectInputFormat(input);
      formatInput.value = detected;
      customFormat = detected;
    }
  }
  if (this.checked) autoConvert();
  updateFormatPlaceholder();
});

document.getElementById('reverseMode').addEventListener('change', function () {
  isReverseMode = this.checked;
  const sep = document.getElementById('reverseSeparator');
  const auto = document.getElementById('autoConvert');

  if (this.checked) {
    sep.style.display = 'block';
    auto.checked = true;
    auto.disabled = true;
  } else {
    sep.style.display = 'none';
    auto.disabled = false;
  }

  if (document.getElementById('input').value.trim()) manualConvert();
});

document.getElementById('reverseSeparator').addEventListener('change', () => {
  if (document.getElementById('input').value.trim() && isReverseMode) manualConvert();
});

document.getElementById('toggleLinks').addEventListener('change', toggle2FAConversion);

document.getElementById('formatInput').addEventListener('input', function () {
  customFormat = this.value.trim() || null;
});

// ── Init ───────────────────────────────────────
window.addEventListener('load', () => {
  loadSavedFormat();
  load2FAPrefix();
  disable2FAToggle();
  updateSocialButtonStates();
  updateFormatPlaceholder();
});
