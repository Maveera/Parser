# Unified Security Intelligence Parser Generator

A powerful, client-side web utility designed to simplify one of the most complex aspects of SOC Architecture: **Custom Parsers**.

This portfolio project provides a beautiful, interactive interface where security engineers can simply paste RAW telemetry logs (such as those from FortiGate, Syslog, or custom appliances), and the internal JavaScript heuristic engine will automatically generate a perfectly structured FortiSIEM XML Parser.

## ✨ Features
- **Client-Side Generation**: Entirely driven by JavaScript, requiring no backend servers or data transmission (crucial for dealing with sensitive internal logs).
- **Unified Multi-Log Output**: Paste dozens of different log variations simultaneously. The engine will intelligently scrape and deduplicate every single unique key across all examples, building one perfectly comprehensive XML parser schema encompassing all possible telemetry.
- **Direct SIEM Attribute Mapping**: Includes a massive runtime dictionary mapping common telemetry keys directly into valid FortiSIEM fields (e.g., `srcIpAddr`, `hostName`, `msg`) for out-of-the-box perfectly matching SIEM XML schemas.
- **Smart Fallback Formatting**: When unrecognized attributes are parsed, the engine instantly splits camelCase, converts underscores to spaces, and capitalizes words to ensure the FortiSIEM UI displays human-readable attributes rather than broken database keys.
- **Visual Mapping Table**: Outputs a responsive Data Table dynamically confirming exactly how every parsed raw key was formatted and assigned for instant verification. 
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
