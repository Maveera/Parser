# Unified Security Intelligence Parser Generator

A powerful, client-side web utility designed to simplify one of the most complex aspects of SOC Architecture: **Custom Parsers**.

This portfolio project provides a beautiful, interactive interface where security engineers can simply paste RAW telemetry logs (such as those from FortiGate, Syslog, or custom appliances), and the internal JavaScript heuristic engine will automatically generate a perfectly structured FortiSIEM XML Parser.

## ✨ Features
- **Client-Side Generation**: Entirely driven by JavaScript, requiring no backend servers or data transmission (crucial for dealing with sensitive internal logs).
- **Log Heuristic Engine**: Automatically parses Key-Value (KV) mappings out of raw logs and maps them to standard EventDB attributes.
- **Dynamic Typing**: Automatically detects data types from values (e.g. `192.168.1.1` becomes `gPatIpV4`, while purely numeric ids become `gPatInt`).
- **Standardized Mapping Framework**: Follows Fortinet best practices, mapping generic fields like `srcip` directly into standardized `srcIpAddr` `<setEventAttribute>` syntax.
- **Syntax Highlighting**: Built-in PrismJS provides gorgeous XML rendering.

## 🚀 How to Use It
1. Clone the repository and open `index.html` in your browser.
2. Review the **Core XML Architecture Sample** to understand how advanced `<choose>` routing works inside FortiSIEM constraints.
3. Scroll down to the **Custom Parser Generator** section to build your own.
4. Paste a raw syslog output. Example:
   ```text
   <189>logver=704092829 timestamp=1771954996 devname="FW-01" vd="root" date="2026-02-24" srcip="192.168.0.101" action="accept" 
   ```
5. Click **Generate Parser**.
6. Once complete, copy the output XML logic or download the `.xml` file and upload it directly into your FortiSIEM console via `Admin > Device Support > Parsers`.

## 🛠️ Built With
- **Frontend Core**: Vanilla HTML5, CSS3, JavaScript.
- **Design Paradigm**: Cyberpunk/Glassmorphic aesthetics with neon accenting and CSS animations.
- **Formatting Engine**: Prism.js 

## 📝 FortiSIEM Specifics Implemented
- `<patternDefinitions>`
- `<eventFormatRecognizer>`
- `<choose>` logic routing
- `<setEventAttribute>` casting constraints

---

*Designed by [maveera.tech](https://maveera.tech)*
