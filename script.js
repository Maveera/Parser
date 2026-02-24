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
            loadingContainer.style.display = 'block';

            setTimeout(() => {
                const result = analyzeLogAndGenerateXML(rawLog);
                generatedXmlCode.textContent = result.xml;
                Prism.highlightElement(generatedXmlCode);
                renderMappingTable(result.mappings);
                loadingContainer.style.display = 'none';
                outputContainer.style.display = 'block';
            }, 1500);
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

    function analyzeLogAndGenerateXML(logStr) {
        let kvPairs = [];
        let isJson = false;

        if (logStr.trim().startsWith('{') && logStr.trim().endsWith('}')) {
            try {
                const jsonObj = JSON.parse(logStr);
                isJson = true;
                for (const [key, value] of Object.entries(jsonObj)) {
                    if (typeof value !== 'object') {
                        kvPairs.push({ key, val: String(value) });
                    }
                }
            } catch (e) { }
        }

        if (!isJson) {
            const kvRegex = /([a-zA-Z0-9_-]+)=("(.*?)"|([^ ]+))/g;
            let match;
            while ((match = kvRegex.exec(logStr)) !== null) {
                const key = match[1];
                let val = match[3] !== undefined ? match[3] : match[4];
                kvPairs.push({ key, val: val.trim() });
            }
        }

        let regexMappingStr = "";
        let attributeAssignmentsStr = "";
        let mappings = [];

        if (kvPairs.length > 0) {
            kvPairs.forEach(pair => {
                let patType = "gPatStr";
                if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(pair.val)) patType = "gPatIpV4";
                else if (/^\d+$/.test(pair.val)) patType = "gPatInt";

                const humanFriendlyMap = {
                    "srcip": "Source IP", "source_ip": "Source IP", "src": "Source IP",
                    "dstip": "Destination IP", "dest_ip": "Destination IP", "dst": "Destination IP",
                    "action": "Event Action", "act": "Event Action",
                    "srcport": "Source Port", "source_port": "Source Port", "spt": "Source Port",
                    "dstport": "Destination Port", "dest_port": "Destination Port", "dpt": "Destination Port",
                    "proto": "IP Protocol", "protocol": "IP Protocol",
                    "duration": "Duration (Sec)", "durationmsec": "Duration (MSec)",
                    "devname": "Device Name", "device_name": "Device Name", "dvc": "DeviceName",
                    "vd": "Virtual Domain", "vdom": "Virtual Domain",
                    "logver": "Log Version",
                    "timestamp": "Timestamp", "eventtime": "Event Time",
                    "tz": "Timezone",
                    "devid": "Device ID",
                    "type": "Log Type",
                    "subtype": "Log Subtype",
                    "level": "Log Level", "severity": "Severity",
                    "srcintf": "Source Interface", "srcintfrole": "Source Interface Role",
                    "dstintf": "Destination Interface", "dstintfrole": "Destination Interface Role",
                    "sessionid": "Session ID",
                    "policyid": "Policy ID", "poluuid": "Policy UUID",
                    "polid": "Policy ID",
                    "sentbyte": "Sent Bytes", "sent_byte": "Sent Bytes",
                    "rcvdbyte": "Received Bytes", "rcvd_byte": "Received Bytes",
                    "sentpkt": "Sent Packets", "sent_pkt": "Sent Packets",
                    "rcvdpkt": "Received Packets", "rcvd_pkt": "Received Packets",
                    "app": "Application", "app_name": "Application",
                    "appcat": "Application Category",
                    "apprisk": "Application Risk",
                    "crscore": "CR Score",
                    "craction": "CR Action",
                    "crlevel": "CR Level",
                    "user": "User", "username": "User",
                    "group": "Group",
                    "msg": "Message",
                    "hostname": "Hostname",
                    "mac": "MAC Address", "srcmac": "Source MAC", "dstmac": "Destination MAC",
                    "status": "Status",
                    "url": "URL", "reqtype": "Request Type", "direction": "Direction",
                    "virus": "Virus Name", "viruscat": "Virus Category",
                    "osname": "OS Name", "osversion": "OS Version"
                };

                let mappedName = pair.key;

                if (humanFriendlyMap[pair.key.toLowerCase()]) {
                    mappedName = humanFriendlyMap[pair.key.toLowerCase()];
                } else {
                    // Auto-Capitalize and remove underscores for unknown fields 
                    mappedName = pair.key
                        .replace(/[_-]/g, ' ')
                        .replace(/\w\S*/g, (txt) => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
                }

                if (isJson) {
                    regexMappingStr += `"${pair.key}":\\s*"?<${pair.key}:${patType}>"?\\s*,?\\s*`;
                } else {
                    regexMappingStr += `${pair.key}=<${pair.key}:${patType}> `;
                }

                attributeAssignmentsStr += `    <setEventAttribute name="${mappedName}">$_${pair.key}</setEventAttribute>\n`;
                mappings.push({ rawKey: pair.key, mappedAttr: mappedName, pattern: patType, sample: pair.val });
            });
        } else {
            regexMappingStr = `<_msgBody:gPatMesgBody>`;
        }

        regexMappingStr = regexMappingStr.trim().replace(/,\\s*$/, '');

        const xmlTemplate = `<?xml version="1.0" encoding="UTF-8"?>
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
    
    <setEventAttribute name="eventType">${isJson ? 'Auto-Detected-JSON' : 'Auto-Detected-KV-Log'}</setEventAttribute>
    <setEventAttribute name="eventSeverity">1</setEventAttribute>

  </parsingInstructions>
</parser>`;

        return { xml: xmlTemplate, mappings };
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
                <td><span class="field-val">${m.mappedAttr}</span></td>
                <td><span class="pat-tag">${m.pattern}</span></td>
                <td>${m.sample}</td>
            `;
            mappingBody.appendChild(tr);
        });
    }
});
