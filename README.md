# Network Engineer Toolbox

A frontend-only, serverless web-based toolbox for network engineers, DevOps, cloud architects, and IT professionals. All tools run entirely in the browser using HTML, CSS, and vanilla JavaScript, suitable for deployment on static platforms like GitHub Pages.

## Features

This toolbox provides a collection of essential networking utilities designed for efficiency and ease of use, without requiring any backend services.

### Core Tools

*   **DNS Lookup:** Efficiently perform DNS queries for various record types (A, AAAA, TXT, MX, NS, CNAME) utilizing public DNS-over-HTTPS (DoH) resolvers for accurate and timely results.
*   **IP/Subnet Calculator:** A comprehensive utility for IP address and subnet calculations, assisting with network planning and configuration.
*   **Security Headers Analyzer:** Analyze HTTP security headers of web resources to identify potential vulnerabilities and ensure adherence to best security practices.
*   **IP & ASN Lookup:** Retrieve detailed information about IP addresses and Autonomous System Numbers (ASNs), including geographical location, ISP, and organization details.
*   **HTTPS Latency:** Measure the latency of HTTPS connections to various URLs, providing insights into network performance and responsiveness.
*   **Traceroute Visualizer:** Visualize traceroute output to map network paths and diagnose connectivity issues effectively.

## How to Use

1.  **Clone or Download:** Obtain the repository from its source.
2.  **Open `index.html`:** Navigate to the project directory and open the `index.html` file in your preferred web browser.
3.  **No Installation Required:** This application is designed to run directly in the browser without any prior installation or build processes.

## Technology Stack

*   **Core:** HTML5, CSS3, Vanilla JavaScript (ES6+)
*   **UI:** Bootstrap 5 for a clean, responsive, and professional interface.
*   **APIs:** All tools rely on free and publicly available APIs (e.g., Cloudflare DoH, ip-api.com, ipwho.is).

## Principles

*   **No Backend:** 100% static and client-side operation ensures minimal overhead and maximum portability.
*   **Secure:** No user-specific data is stored or transmitted to any server beyond the necessary calls to public APIs.
*   **Easy to Host:** Deployable on any static web hosting service (e.g., GitHub Pages, Netlify).
*   **Professional Quality:** Developed with clean, modular, and well-documented code standards.

## Author

A.V.

## Disclaimer

The tools provided within this application are for informational and educational purposes only. While efforts are made to ensure accuracy, the developer assumes no liability for errors or omissions, or for any actions taken based on the information provided. Users are encouraged to verify results independently for critical applications.