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
                }).catch(err => {
                    console.error('Failed to copy text: ', err);
                });
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
    }, {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px"
    });

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

            // Show Loader, Hide Output
            outputContainer.style.display = 'none';
            loadingContainer.style.display = 'block';

            // Simulate parsing engine latency
            setTimeout(() => {
                const generatedXML = analyzeLogAndGenerateXML(rawLog);

                // Escape HTML for rendering in <pre><code>
                generatedXmlCode.textContent = generatedXML;

                // Re-highlight using Prism
                Prism.highlightElement(generatedXmlCode);

                // Show Output, Hide Loader
                loadingContainer.style.display = 'none';
                outputContainer.style.display = 'block';

            }, 1500); // 1.5s simulated loading
        });
    }

    // Copy Generated XML Logic
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
        // Very basic KV heuristic engine for demonstration
        const kvPairs = [];
        const kvRegex = /([a-zA-Z0-9_-]+)=("(.*?)"|([^ ]+))/g;
        let match;

        while ((match = kvRegex.exec(logStr)) !== null) {
            const key = match[1];
            // If the value was in quotes, use match 3, otherwise use match 4
            let val = match[3] !== undefined ? match[3] : match[4];

            // Clean up surrounding brackets or extra spaces if any
            val = val.trim();

            kvPairs.push({ key, val });
        }

        // Generate FortiSIEM Mapping XML Block
        let regexMappingStr = "";
        let attributeAssignmentsStr = "";

        if (kvPairs.length > 0) {
            kvPairs.forEach(pair => {
                // Determine pattern type based on value heuristics
                let patType = "gPatStr";

                if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(pair.val)) patType = "gPatIpV4";
                else if (/^\d+$/.test(pair.val)) patType = "gPatInt";
                else if (pair.val === "root") patType = "gPatStr";

                // Build the regex capture group string
                regexMappingStr += `${pair.key}=<${pair.key}:${patType}> `;

                // Standardizing some core attributes based on KV analysis common in SIEMs
                if (pair.key === "srcip") {
                    attributeAssignmentsStr += `    <setEventAttribute name="srcIpAddr">$_${pair.key}</setEventAttribute>\n`;
                } else if (pair.key === "dstip") {
                    attributeAssignmentsStr += `    <setEventAttribute name="destIpAddr">$_${pair.key}</setEventAttribute>\n`;
                } else if (pair.key === "action") {
                    attributeAssignmentsStr += `    <setEventAttribute name="eventAction">$_${pair.key}</setEventAttribute>\n`;
                } else if (pair.key === "srcport") {
                    attributeAssignmentsStr += `    <setEventAttribute name="srcPort">$_${pair.key}</setEventAttribute>\n`;
                } else if (pair.key === "dstport") {
                    attributeAssignmentsStr += `    <setEventAttribute name="destPort">$_${pair.key}</setEventAttribute>\n`;
                } else if (pair.key === "proto") {
                    attributeAssignmentsStr += `    <setEventAttribute name="ipProto">$_${pair.key}</setEventAttribute>\n`;
                } else if (pair.key === "duration") {
                    attributeAssignmentsStr += `    <setEventAttribute name="durationMSec">$_${pair.key}</setEventAttribute>\n`;
                } else {
                    // For all other fields found dynamically, just passthrough generic mapping
                    attributeAssignmentsStr += `    <setEventAttribute name="${pair.key}">$_${pair.key}</setEventAttribute>\n`;
                }
            });
        } else {
            // Fallback for non KV formats
            regexMappingStr = `<_msgBody:gPatMesgBody>`;
        }

        // Clean trailing space
        regexMappingStr = regexMappingStr.trim();

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
    
    <setEventAttribute name="eventType">Custom-Auto-Generated-Event</setEventAttribute>
    <setEventAttribute name="eventSeverity">1</setEventAttribute>

  </parsingInstructions>
</parser>`;

        return xmlTemplate;
    }
});
