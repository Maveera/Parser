document.addEventListener('DOMContentLoaded', () => {
    // Copy main XML functionality
    const copyBtn = document.getElementById('copyXmlBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const codeBlock = document.querySelector('.xml-section code');
            if (codeBlock) {
                const textTarget = codeBlock.textContent;
                navigator.clipboard.writeText(textTarget).then(() => {
                    const originalText = copyBtn.innerText;
                    copyBtn.innerText = 'Copied! ✓';
                    copyBtn.style.backgroundColor = 'var(--primary)';
                    copyBtn.style.color = '#000';
                    copyBtn.style.boxShadow = 'var(--neon-glow)';
                    setTimeout(() => {
                        copyBtn.innerText = originalText;
                        copyBtn.style.backgroundColor = '';
                        copyBtn.style.color = '';
                        copyBtn.style.boxShadow = '';
                    }, 2000);
                }).catch(err => console.error('Failed to copy text: ', err));
            }
        });
    }

    // Scroll Animations
    const cards = document.querySelectorAll('.card');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = "1";
                entry.target.style.transform = "translateY(0)";
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1, rootMargin: "0px 0px -50px 0px" });

    cards.forEach(card => {
        if (card.getBoundingClientRect().top > window.innerHeight) {
            card.style.opacity = "0";
            card.style.transform = "translateY(20px)";
            card.style.transition = "opacity 0.6s ease-out, transform 0.6s ease-out";
            observer.observe(card);
        }
    });

    // --- Parser Generator Logic ---
    const generateBtn = document.getElementById('generateBtn');
    const rawLogInput = document.getElementById('rawLogInput');
    const loadingContainer = document.getElementById('loadingContainer');
    const outputContainer = document.getElementById('outputContainer');
    const generatedXmlCode = document.getElementById('generatedXmlCode');
    const copyGenXmlBtn = document.getElementById('copyGenXmlBtn');

    if (generateBtn && rawLogInput) {
        generateBtn.addEventListener('click', () => {
            const rawLog = rawLogInput.value.trim();
            if (!rawLog) return;

            outputContainer.style.display = 'none';

            // Generate parser immediately without any artificial delay
            const result = analyzeLogAndGenerateXML(rawLog);
            generatedXmlCode.textContent = result.xml;
            Prism.highlightElement(generatedXmlCode);
            renderMappingTable(result.mappings);

            outputContainer.style.display = 'block';
        });
    }

    if (copyGenXmlBtn) {
        copyGenXmlBtn.addEventListener('click', () => {
            const textTarget = generatedXmlCode.textContent;
            navigator.clipboard.writeText(textTarget).then(() => {
                const originalText = copyGenXmlBtn.innerText;
                copyGenXmlBtn.innerText = 'Copied! ✓';
                copyGenXmlBtn.style.backgroundColor = 'var(--primary)';
                copyGenXmlBtn.style.color = '#000';
                copyGenXmlBtn.style.boxShadow = 'var(--neon-glow)';
                setTimeout(() => {
                    copyGenXmlBtn.innerText = originalText;
                    copyGenXmlBtn.style.backgroundColor = '';
                    copyGenXmlBtn.style.color = '';
                    copyGenXmlBtn.style.boxShadow = '';
                }, 2000);
            });
        });
    }

    const siemFieldMap = {
        'logver': 'Log Version',
        'apprisk': 'Application Risk',
        'srcip': 'Source IP',
        'dstip': 'Destination IP',
        'srcport': 'Source Port',
        'dstport': 'Destination Port',
        'action': 'Action',
        'proto': 'Protocol',
        'duration': 'Duration',
        'timestamp': 'Timestamp',
        'unknownfield': 'Unknown Field'
    };

    function analyzeLogAndGenerateXML(rawLogsText) {
        let kvPairs = [];
        let isJson = false;

        // Process all lines independently to scrape every key
        const lines = rawLogsText.split('\n');
        lines.forEach(line => {
            let logStr = line.trim();
            if (!logStr) return;

            if (logStr.startsWith('{') && logStr.endsWith('}')) {
                try {
                    const jsonObj = JSON.parse(logStr);
                    isJson = true;
                    for (const [key, value] of Object.entries(jsonObj)) {
                        if (typeof value !== 'object') {
                            kvPairs.push({ key, val: String(value) });
                        }
                    }
                } catch (e) { }
            } else {
                const kvRegex = /([a-zA-Z0-9_-]+)=("(.*?)"|([^ ]+))/g;
                let match;
                while ((match = kvRegex.exec(logStr)) !== null) {
                    const key = match[1];
                    let val = match[3] !== undefined ? match[3] : match[4];
                    kvPairs.push({ key, val: val.trim() });
                }
            }
        });

        // Deduplicate keys globally so we build ONE single block output
        // BUT collect multiple unique sample values for user visibility in the mapping table
        const uniqueKvPairs = [];
        const keyValTokens = new Map();

        kvPairs.forEach(pair => {
            if (!keyValTokens.has(pair.key)) {
                keyValTokens.set(pair.key, new Set([pair.val]));
            } else {
                keyValTokens.get(pair.key).add(pair.val);
            }
        });

        for (const [key, valSet] of keyValTokens.entries()) {
            const vals = Array.from(valSet);
            // Display up to 3 distinct examples
            let sampleValStr = vals.length > 3 ? vals.slice(0, 3).join(', ') + ' ...' : vals.join(', ');
            uniqueKvPairs.push({ key: key, val: vals[0], sampleStr: sampleValStr });
        }

        kvPairs = uniqueKvPairs;

        let regexMappingStr = "";
        let attributeAssignmentsStr = "";
        let allMappings = [];

        if (kvPairs.length > 0) {
            kvPairs.forEach(pair => {
                let patType = "gPatStr";
                if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(pair.val)) patType = "gPatIpV4Dot";
                else if (/^\d+$/.test(pair.val)) patType = "gPatInt";

                let siemAttr = pair.key;
                if (siemFieldMap[pair.key.toLowerCase()]) {
                    siemAttr = siemFieldMap[pair.key.toLowerCase()];
                } else {
                    // split camelCase, convert underscores to spaces, and capitalize words
                    siemAttr = pair.key
                        .replace(/([a-z])([A-Z])/g, '$1 $2')
                        .replace(/_/g, ' ')
                        .replace(/\b\w/g, c => c.toUpperCase());
                }

                if (isJson) {
                    regexMappingStr += `"${pair.key}":\\s*"?<_${pair.key}:${patType}>"?\\s*,?\\s*`;
                } else {
                    regexMappingStr += `${pair.key}=<_${pair.key}:${patType}>\\s+`;
                }

                attributeAssignmentsStr += `    <setEventAttribute attr="${siemAttr}">$_${pair.key}</setEventAttribute>\n`;
                allMappings.push({ rawKey: pair.key, siemAttr: siemAttr, pattern: patType, sample: pair.sampleStr });
            });
        } else {
            regexMappingStr = `<_msgBody:gPatMesgBody>`;
        }

        // Clean trailing space or comma patterns
        regexMappingStr = regexMappingStr.trim().replace(/(?:,\\s*|\\s\+)$/, '');
        let eventTypeStr = isJson ? 'Auto-Detected-JSON' : 'Auto-Detected-KV-Log';

        let xmlTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<parser xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <patternDefinitions>
    <pattern name="patFormat"><![CDATA[.*?]]></pattern>
  </patternDefinitions>

  <!-- Auto-detected event format -->
  <eventFormatRecognizer><![CDATA[.*]]></eventFormatRecognizer>

  <parsingInstructions>
    
    <collectFieldsByRegex src="$_rawmsg">
      <regex><![CDATA[${regexMappingStr}]]></regex>
    </collectFieldsByRegex>

    <!-- Standardizing core attributes based on KV analysis -->
${attributeAssignmentsStr.trimEnd()}
    
    <setEventAttribute attr="eventType">${eventTypeStr}</setEventAttribute>
    <setEventAttribute attr="eventSeverity">1</setEventAttribute>

  </parsingInstructions>
</parser>`;

        return { xml: xmlTemplate, mappings: allMappings };
    }

    function renderMappingTable(mappings) {
        const mappingBody = document.getElementById('mappingBody');
        if (!mappingBody) return;

        mappingBody.innerHTML = '';
        if (mappings.length === 0) {
            mappingBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: #ef4444;">No attributes parsed. Unrecognized format.</td></tr>';
            return;
        }

        mappings.forEach((m, index) => {
            const tr = document.createElement('tr');
            tr.style.animation = `fadeIn 0.5s ease-out forwards ${index * 0.05}s`;
            tr.style.opacity = '0';
            tr.innerHTML = `
                <td><code>${m.rawKey}</code></td>
                <td><span class="field-val">${m.siemAttr}</span></td>
                <td><span class="pat-tag">${m.pattern}</span></td>
                <td>${m.sample}</td>
            `;
            mappingBody.appendChild(tr);
        });
    }
});
