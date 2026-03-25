document.addEventListener('DOMContentLoaded', () => {
  const generateBtn = document.getElementById('generateBtn');
  const rawInput = document.getElementById('rawInput');
  const xmlOutput = document.getElementById('xmlOutput');
  const mappingBody = document.getElementById('mappingBody');
  const copyFullBtn = document.getElementById('copyFullBtn');
  const copyBodyBtn = document.getElementById('copyBodyBtn');
  const deviceTypeInput = document.getElementById('deviceType');
  const parserNameInput = document.getElementById('parserName');
  const eventRecognizerInput = document.getElementById('eventRecognizer');
  const hasSyslogPrefixInput = document.getElementById('hasSyslogPrefix');
  const safeMappingInput = document.getElementById('safeMapping');
  const mapAllKeysInput = document.getElementById('mapAllKeys');
  const errorBox = document.getElementById('errorBox');
  const toast = document.getElementById('toast');

  let lastGeneratedXml = '';
  let lastGeneratedBody = '';

  function showToast(message) {
    toast.textContent = message;
    toast.classList.add('visible');
    setTimeout(() => toast.classList.remove('visible'), 2200);
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }

  function clearError() {
    errorBox.textContent = '';
    errorBox.hidden = true;
  }

  function extractParserBody(fullXml) {
    const match = fullXml.match(/<eventFormatRecognizer[\s\S]*?<\/parsingInstructions>/);
    return match ? match[0] : fullXml;
  }

  function detectPatternName(value, key) {
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return 'gPatIpV4Dot';
    if (/^\d+$/.test(value)) return 'gPatInt';
    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return 'gPatStr';
    if (/^\d{2}:\d{2}:\d{2}$/.test(value)) return 'gPatStr';
    if (key === 'vwlquality') return 'patFormat';
    if (/\s/.test(value)) return 'patSentence';
    return 'gPatStr';
  }

  function escapeRegexLiteral(str) {
    return String(str).replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
  }

  function jsRegexForFortiPattern(patternName) {
    // Approximate FortiSIEM pattern behavior for local "regex match check".
    // This is only used for pre-checking that the generated regex can match the sample.
    switch (patternName) {
      case 'gPatInt':
        return '\\d+';
      case 'gPatIpV4Dot':
        return '(?:\\d{1,3}\\.){3}\\d{1,3}';
      case 'gPatStr':
        return '[^\\s"]+';
      case 'gPatSentence':
      case 'patSentence':
        // Non-greedy sentence capture
        return '.+?';
      case 'patFormat':
        // Typically used inside quotes for FortiGate vwlquality
        return '[^"]+';
      default:
        return '[^\\s]+';
    }
  }

  function testRegexAgainstSample(regexBody, sampleLine) {
    // Convert the FortiSIEM placeholder tokens into JS regex capture groups
    // so we can verify the regex matches the sample.
    const placeholderRe = /<(_[A-Za-z0-9_]+):([A-Za-z0-9_]+)>/g;

    const vars = [];
    let jsSource = regexBody.replace(placeholderRe, (full, varName, patName) => {
      vars.push(varName);
      return `(${jsRegexForFortiPattern(patName)})`;
    });

    // Remove accidental unescaped whitespace issues: FortiSIEM regex uses \s+;
    // leave them as-is for JS regex compilation.
    let re;
    try {
      re = new RegExp(jsSource);
    } catch (e) {
      throw new Error('Regex match test failed to compile as JavaScript RegExp.');
    }

    const m = re.exec(sampleLine);
    if (!m) return { matched: false, captures: {} };

    const captures = {};
    for (let i = 0; i < vars.length; i++) {
      captures[vars[i]] = m[i + 1] || '';
    }
    return { matched: true, captures };
  }

  function preCheckFortiSiemRegexBody(regexBody, usesPatSentence, usesPatFormat) {
    // Validate placeholder syntax and pattern names before we emit XML.
    // This prevents FortiSIEM validation failures from unsupported pattern names
    // and common placeholder formatting mistakes.
    const allowedPatterns = new Set([
      'gPatIpV4Dot',
      'gPatInt',
      'gPatStr',
      'gPatSentence',
      'patSentence',
      'patFormat'
    ]);

    if (regexBody.includes('gPatDate') || regexBody.includes('gPatTime')) {
      throw new Error('Regex pre-check failed: unsupported pattern gPatDate/gPatTime.');
    }

    const placeholderRe = /<(_[A-Za-z0-9_]+):([A-Za-z0-9_]+)>/g;
    let count = 0;
    for (const m of regexBody.matchAll(placeholderRe)) {
      count++;
      const varName = m[1];
      const patternName = m[2];

      // Must use underscore-prefixed variables
      if (!varName.startsWith('_')) {
        throw new Error(`Regex pre-check failed: variable "${varName}" must start with "_"`);
      }

      if (!allowedPatterns.has(patternName)) {
        throw new Error(`Regex pre-check failed: unsupported pattern "${patternName}"`);
      }

      if (patternName === 'patSentence' && !usesPatSentence) {
        throw new Error('Regex pre-check failed: patSentence used but patSentence definition not present.');
      }
      if (patternName === 'patFormat' && !usesPatFormat) {
        throw new Error('Regex pre-check failed: patFormat used but patFormat definition not present.');
      }
    }

    if (count === 0) {
      throw new Error('Regex pre-check failed: no placeholders found (<_var:pattern>).');
    }

    // Avoid strict mismatch when engine expects last token without "\s+"
    if (regexBody.endsWith('\\s+')) {
      throw new Error('Regex pre-check failed: regex ends with "\\s+"; remove trailing "\\s+".');
    }
  }

  function buildParserXml(rawText) {
    const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.length) throw new Error('No log lines detected.');

    const fieldMap = new Map();
    let sawBracketStyle = false;
    const sawPriHeader = lines.some(l => /^<\d+>/.test(l));

    // Use the first non-empty raw line for local regex match pre-check.
    const sampleLine = lines[0];

    lines.forEach(line => {
      let working = line;
      if (hasSyslogPrefixInput.checked) {
        working = working.replace(/^<\d+>\s*/, '');
      }

      const kvRegex = /([A-Za-z0-9._-]+)=("(.*?)"|(\S+))/g;
      let match;
      while ((match = kvRegex.exec(working)) !== null) {
        const key = match[1];
        const quoted = !!match[3];
        const rawVal = quoted ? match[3] : match[4];
        const value = (rawVal || '').trim();

        if (!fieldMap.has(key)) {
          fieldMap.set(key, { key, values: new Set(), quoted });
        }
        const entry = fieldMap.get(key);
        entry.values.add(value);
        entry.quoted = entry.quoted || quoted;
      }

      const bracketRegex = /\[([^\]]+)\]=([^,\]]*)/g;
      let m2;
      while ((m2 = bracketRegex.exec(working)) !== null) {
        const key = m2[1];
        const rawVal = m2[2];
        const value = (rawVal || '').trim();
        sawBracketStyle = true;

        if (!fieldMap.has(key)) {
          fieldMap.set(key, { key, values: new Set(), quoted: false });
        }
        const entry = fieldMap.get(key);
        entry.values.add(value);
      }
    });

    if (!fieldMap.size) {
      throw new Error('Could not detect any key=value pairs in the sample logs.');
    }

    const fields = Array.from(fieldMap.values());
    let regexBody = '';

    if (sawBracketStyle) {
      const regexParts = ['.*'];
      fields.forEach((field, index) => {
        const key = field.key;
        const sampleVal = Array.from(field.values)[0] || '';
        const patternName = detectPatternName(sampleVal, key);
        const varName = key.replace(/[^A-Za-z0-9_]/g, '_');
        const keyRegex = `\\[${escapeRegexLiteral(key)}\\]`;
        let part = `${keyRegex}=<_${varName}:${patternName}>`;
        if (index < fields.length - 1) part += ',';
        regexParts.push(part);
        field.patternName = patternName;
        field.varName = varName;
        field.sample = sampleVal;
      });
      regexBody = regexParts.join('');
    } else {
      const regexParts = [];
      if (hasSyslogPrefixInput.checked || sawPriHeader) {
        // Allow FortiGate logs with or without syslog PRI prefix (<189>...)
        regexParts.push('(?:<\\d+>\\s*)?');
      }
      fields.forEach((field, index) => {
        const key = field.key;
        const sampleVal = Array.from(field.values)[0] || '';
        const patternName = detectPatternName(sampleVal, key);
        const varName = key.replace(/[^A-Za-z0-9_]/g, '_');
        const keyLit = escapeRegexLiteral(key);

        // Between fields: \\s+. For the last field, allow optional whitespace.
        const suffix = index < fields.length - 1 ? '\\s+' : '\\s*';
        let part;
        if (field.quoted) {
          part = `${keyLit}="<_${varName}:${patternName}>"${suffix}`;
        } else {
          part = `${keyLit}=<_${varName}:${patternName}>${suffix}`;
        }
        regexParts.push(part);
        field.patternName = patternName;
        field.varName = varName;
        field.sample = sampleVal;
      });
      regexBody = regexParts.join('');
    }

    const parserName = parserNameInput.value.trim() || 'Custom-Generic-Parser';
    const deviceType = deviceTypeInput.value.trim() || 'Generic-Device';
    const eventRecognizer = eventRecognizerInput.value.trim() || '.*';

    const usesSentence = fields.some(f => f.patternName === 'patSentence');
    const usesFormat = fields.some(f => f.patternName === 'patFormat');
    let patternDefs = '';
    if (usesSentence || usesFormat) {
      const patterns = [];
      if (usesSentence) patterns.push('<pattern name="patSentence"><![CDATA[.+]]></pattern>');
      if (usesFormat) patterns.push('<pattern name="patFormat"><![CDATA[[a-zA-Z0-9) ,:(_-]+]]></pattern>');
      patternDefs = `\n  <patternDefinitions>\n    ${patterns.join('\n    ')}\n  </patternDefinitions>`;
    }

    preCheckFortiSiemRegexBody(regexBody, usesSentence, usesFormat);

    // Local "does it match my sample" check.
    // If it fails, FortiSIEM validation/test will almost certainly fail too.
    const matchRes = testRegexAgainstSample(regexBody, sampleLine);
    if (!matchRes.matched) {
      throw new Error('Regex match check failed against your sample log line.');
    }

    // Update field samples from capture groups (so the mapping table reflects actual matches).
    fields.forEach(f => {
      if (f.varName && matchRes.captures[`_${f.varName}`]) {
        f.sample = matchRes.captures[`_${f.varName}`];
      }
    });

    // Set msg to the raw message by default (always available).
    // If we detect a more meaningful field (like vwlquality / phLogDetail), prefer it.
    const msgPriorityKeys = ['vwlquality', 'phlogdetail', 'addeditem', 'msg', 'phlogdetail'];
    const msgField = fields.find(f => msgPriorityKeys.includes(String(f.key).toLowerCase()));
    const msgSourceVar = msgField ? `$_${msgField.varName}` : '$_rawmsg';

    const sanitizeAttrName = (rawKey) => {
      let s = String(rawKey).replace(/[^A-Za-z0-9_]/g, '_');
      if (/^[0-9]/.test(s)) s = '_' + s;
      return s;
    };

    const setLines = [`    <setEventAttribute attr="msg">${msgSourceVar}</setEventAttribute>`];

    const safeMapping = safeMappingInput ? safeMappingInput.checked : true;
    const mapAllKeys = mapAllKeysInput ? mapAllKeysInput.checked : false;

    if (mapAllKeys) {
      // Map every detected key to an event attribute name derived from the key.
      // You must create these attributes in FortiSIEM first, otherwise validation will fail.
      fields.forEach(f => {
        const attr = sanitizeAttrName(f.key);
        if (!attr || attr === 'msg') return;
        setLines.push(`    <setEventAttribute attr="${attr}">$_${f.varName}</setEventAttribute>`);
      });
    } else if (safeMapping) {
      // Safe mapping mode: FortiSIEM validation is strict about whether attr="..."
      // exists in the event attribute master list.
      // To guarantee validation always passes, we only set msg (always valid).
      // If you want full structured mapping, enable "Map all detected keys"
      // after creating the corresponding attributes in FortiSIEM.
    }

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<parser xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <!-- Parser: ${parserName} | Device Type: ${deviceType} -->
  <eventFormatRecognizer><![CDATA[${eventRecognizer}]]></eventFormatRecognizer>${patternDefs}

  <parsingInstructions>
    <collectFieldsByRegex src="$_rawmsg">
      <regex><![CDATA[${regexBody}]]></regex>
    </collectFieldsByRegex>
${setLines.join('\n')}
  </parsingInstructions>
</parser>`;

    return { xml, body: extractParserBody(xml), fields };
  }

  function renderMappings(fields) {
    mappingBody.innerHTML = '';

    fields.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHtml(f.key)}</code></td>
        <td><span class="pattern-pill">${escapeHtml(f.patternName)}</span></td>
        <td><span class="quoted-badge">${f.quoted ? 'quoted' : 'unquoted'}</span></td>
        <td>${escapeHtml((f.sample || '').slice(0, 40))}${(f.sample || '').length > 40 ? '…' : ''}</td>
      `;
      mappingBody.appendChild(tr);
    });
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  if (generateBtn) {
    generateBtn.addEventListener('click', () => {
      clearError();
      xmlOutput.textContent = '';
      lastGeneratedXml = '';
      lastGeneratedBody = '';

      const rawText = rawInput.value;
      if (!rawText.trim()) {
        showError('Paste at least one raw log line first.');
        return;
      }

      try {
        const { xml, body, fields } = buildParserXml(rawText);
        lastGeneratedXml = xml;
        lastGeneratedBody = body;
        xmlOutput.textContent = xml;
        renderMappings(fields);
        showToast('Parser generated successfully');
      } catch (e) {
        showError(e.message || 'Failed to generate parser.');
      }
    });
  }

  if (copyFullBtn) {
    copyFullBtn.addEventListener('click', () => {
      if (!lastGeneratedXml) return;
      navigator.clipboard.writeText(lastGeneratedXml).then(() => {
        showToast('Full XML copied to clipboard');
      }).catch(() => {});
    });
  }

  if (copyBodyBtn) {
    copyBodyBtn.addEventListener('click', () => {
      const text = lastGeneratedBody || xmlOutput.textContent;
      if (!text) return;
      const body = text.includes('eventFormatRecognizer') ? extractParserBody(text) : text;
      navigator.clipboard.writeText(body).then(() => {
        showToast('Parser body copied (ready for FortiSIEM)');
      }).catch(() => {});
    });
  }
});
